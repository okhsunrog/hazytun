// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.
//
// This file incorporates work covered by the following copyright and
// permission notice:
//
//   Copyright (c) Mullvad VPN AB. All rights reserved.
//   Copyright (c) 2019 Cloudflare, Inc. All rights reserved.
//
// SPDX-License-Identifier: MPL-2.0

// This module contains some integration tests for gotatun
// Those tests require docker and sudo privileges to run
#[cfg(all(test, not(target_os = "macos"), not(target_os = "windows")))]
mod tests {
    use crate::device::{DefaultDeviceTransports, Device, DeviceBuilder};
    use crate::noise::awg::{AwgConfig, MagicHeader};
    use crate::udp::socket::UdpSocketFactory;
    use crate::x25519::{PublicKey, StaticSecret};
    use base64::Engine as _;
    use base64::prelude::BASE64_STANDARD;
    use hex::encode;
    use rand::{TryRngCore, rngs::OsRng};
    use std::fmt::Write as _;
    use std::io::{BufRead, BufReader, Read, Write};
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
    use std::process::Command;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::thread;
    use tokio::io::{AsyncBufReadExt, AsyncWriteExt};
    use tokio::net::UnixStream;

    static NEXT_IFACE_IDX: AtomicUsize = AtomicUsize::new(100); // utun 100+ should be vacant during testing on CI
    static NEXT_PORT: AtomicUsize = AtomicUsize::new(61111); // Use ports starting with 61111, hoping we don't run into a taken port 🤷
    static NEXT_IP: AtomicUsize = AtomicUsize::new(0xc0000200); // Use 192.0.2.0/24 for those tests, we might use more than 256 addresses though, usize must be >=32 bits on all supported platforms
    static NEXT_IP_V6: AtomicUsize = AtomicUsize::new(0); // Use the 2001:db8:: address space, append this atomic counter for bottom 32 bits

    fn next_ip() -> IpAddr {
        IpAddr::V4(Ipv4Addr::from(
            NEXT_IP.fetch_add(1, Ordering::Relaxed) as u32
        ))
    }

    fn next_ip_v6() -> IpAddr {
        let addr = 0x2001_0db8_0000_0000_0000_0000_0000_0000_u128
            + u128::from(NEXT_IP_V6.fetch_add(1, Ordering::Relaxed) as u32);

        IpAddr::V6(Ipv6Addr::from(addr))
    }

    fn next_port() -> u16 {
        NEXT_PORT.fetch_add(1, Ordering::Relaxed) as u16
    }

    /// Represents an allowed IP and cidr for a peer
    struct AllowedIp {
        ip: IpAddr,
        cidr: u8,
    }

    /// Represents a single peer running in a container
    struct Peer {
        key: StaticSecret,
        endpoint: SocketAddr,
        allowed_ips: Vec<AllowedIp>,
        container_name: Option<String>,
    }

    /// Represents a single WireGuard interface on local machine
    struct WGHandle {
        _device: Device<DefaultDeviceTransports>,
        name: String,
        addr_v4: IpAddr,
        addr_v6: IpAddr,
        started: bool,
        peers: Vec<Arc<Peer>>,
    }

    impl Drop for Peer {
        fn drop(&mut self) {
            if let Some(name) = &self.container_name {
                Command::new("docker")
                    .args([
                        "stop", // Run docker
                        &name[5..],
                    ])
                    .status()
                    .ok();

                std::fs::remove_file(name).ok();
                std::fs::remove_file(format!("{name}.ngx")).ok();
            }
        }
    }

    /// Docker network name for IPv6 endpoint tests
    const DOCKER_IPV6_NETWORK: &str = "gotatun-e2e";
    /// Known gateway for the IPv6 test network (fd00:e2e::/64)
    const DOCKER_IPV6_GATEWAY: &str = "fd00:e2e::1";

    /// Get the Docker bridge gateway IP (set by run-e2e-tests-inner.sh)
    fn docker_bridge_gateway() -> IpAddr {
        std::env::var("DOCKER_BRIDGE_GATEWAY")
            .expect("DOCKER_BRIDGE_GATEWAY not set - are you running via run-e2e-tests.sh?")
            .parse()
            .expect("Invalid DOCKER_BRIDGE_GATEWAY")
    }

    /// Get the IPv4 address of a running Docker container
    fn docker_container_ip(container_name: &str) -> IpAddr {
        let output = Command::new("docker")
            .args([
                "inspect",
                "-f",
                "{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}",
                container_name,
            ])
            .output()
            .expect("Failed to inspect Docker container");
        String::from_utf8(output.stdout)
            .unwrap()
            .trim()
            .parse()
            .unwrap_or_else(|e| panic!("Failed to parse container IP for {container_name}: {e}"))
    }

    /// Get the IPv6 address of a running Docker container
    fn docker_container_ipv6(container_name: &str) -> IpAddr {
        let output = Command::new("docker")
            .args([
                "inspect",
                "-f",
                "{{range .NetworkSettings.Networks}}{{.GlobalIPv6Address}}{{end}}",
                container_name,
            ])
            .output()
            .expect("Failed to inspect Docker container");
        String::from_utf8(output.stdout)
            .unwrap()
            .trim()
            .parse()
            .unwrap_or_else(|e| panic!("Failed to parse container IPv6 for {container_name}: {e}"))
    }

    impl Peer {
        /// Create a new peer with a given endpoint and a list of allowed IPs
        fn new(endpoint: SocketAddr, allowed_ips: Vec<AllowedIp>) -> Peer {
            Peer {
                key: StaticSecret::random_from_rng(rand_core::OsRng),
                endpoint,
                allowed_ips,
                container_name: None,
            }
        }

        /// Creates a new configuration file that can be used by wg-quick
        fn gen_wg_conf(
            &self,
            local_key: &PublicKey,
            local_addr: &IpAddr,
            local_port: u16,
            local_endpoint_host: &IpAddr,
        ) -> String {
            let mut conf = String::from("[Interface]\n");
            // Each allowed ip, becomes a possible address in the config
            for ip in &self.allowed_ips {
                let _ = writeln!(conf, "Address = {}/{}", ip.ip, ip.cidr);
            }

            // The local endpoint port is the remote listen port
            let _ = writeln!(conf, "ListenPort = {}", self.endpoint.port());
            // HACK: this should consume the key so it can't be reused instead of cloning and
            // serializing
            let _ = writeln!(
                conf,
                "PrivateKey = {}",
                BASE64_STANDARD.encode(self.key.to_bytes())
            );

            // We are the peer
            let _ = writeln!(conf, "[Peer]");
            let _ = writeln!(
                conf,
                "PublicKey = {}",
                BASE64_STANDARD.encode(local_key.as_bytes())
            );
            let _ = writeln!(conf, "AllowedIPs = {local_addr}");
            // Use the bridge gateway IP so the peer can reach gotatun via the Docker bridge
            // Format IPv6 endpoints with brackets: [addr]:port
            let endpoint = SocketAddr::new(*local_endpoint_host, local_port);
            let _ = write!(conf, "Endpoint = {endpoint}");

            conf
        }

        /// Create a simple nginx config, that will respond with the peer public key
        fn gen_nginx_conf(&self) -> String {
            format!(
                "server {{\n\
                 listen 80;\n\
                 listen [::]:80;\n\
                 location / {{\n\
                 return 200 '{}';\n\
                 }}\n\
                 }}",
                encode(PublicKey::from(&self.key).as_bytes())
            )
        }

        fn start_in_container(
            &mut self,
            local_key: &PublicKey,
            local_addr: &IpAddr,
            local_port: u16,
        ) {
            let want_ipv6 = self.endpoint.ip().is_ipv6();
            let gateway: IpAddr = if want_ipv6 {
                DOCKER_IPV6_GATEWAY.parse().unwrap()
            } else {
                docker_bridge_gateway()
            };

            let peer_config = self.gen_wg_conf(local_key, local_addr, local_port, &gateway);
            let peer_config_file = temp_path();
            std::fs::write(&peer_config_file, peer_config).unwrap();
            let nginx_config = self.gen_nginx_conf();
            let nginx_config_file = format!("{peer_config_file}.ngx");
            std::fs::write(&nginx_config_file, nginx_config).unwrap();

            let container_name = &peer_config_file[5..];
            let wg_vol = format!("{peer_config_file}:/wireguard/wg.conf");
            let nginx_vol = format!("{nginx_config_file}:/etc/nginx/conf.d/default.conf");

            let mut args = vec![
                "run",
                "-d",
                "--cap-add=NET_ADMIN",
                "--device=/dev/net/tun",
                "--sysctl",
                "net.ipv6.conf.all.disable_ipv6=0",
                "--sysctl",
                "net.ipv6.conf.default.disable_ipv6=0",
            ];

            // Use IPv6-capable network for IPv6 endpoint tests
            if want_ipv6 {
                args.extend_from_slice(&["--network", DOCKER_IPV6_NETWORK]);
            }

            args.extend_from_slice(&[
                "-v",
                &wg_vol,
                "-v",
                &nginx_vol,
                "--rm",
                "--name",
                container_name,
                "vkrasnov/wireguard-test",
            ]);

            Command::new("docker")
                .args(&args)
                .status()
                .expect("Failed to run docker");

            // Get the container's bridge IP and update the endpoint
            let container_ip = if want_ipv6 {
                docker_container_ipv6(container_name)
            } else {
                docker_container_ip(container_name)
            };
            self.endpoint = SocketAddr::new(container_ip, self.endpoint.port());

            self.container_name = Some(peer_config_file);
        }

        fn connect(&self) -> std::net::TcpStream {
            let http_addr = SocketAddr::new(self.allowed_ips[0].ip, 80);
            for _i in 0..10 {
                let res = std::net::TcpStream::connect_timeout(
                    &http_addr,
                    std::time::Duration::from_secs(5),
                );
                if let Err(err) = res {
                    println!("failed to connect: {err:?}");
                    std::thread::sleep(std::time::Duration::from_millis(500));
                    continue;
                }

                return res.unwrap();
            }

            panic!("failed to connect");
        }

        fn get_request(&self) -> String {
            let mut tcp_conn = self.connect();

            write!(
                tcp_conn,
                "GET / HTTP/1.1\nHost: localhost\nAccept: */*\nConnection: close\n\n"
            )
            .unwrap();

            tcp_conn
                .set_read_timeout(Some(std::time::Duration::from_secs(60)))
                .ok();

            let mut reader = BufReader::new(tcp_conn);
            let mut line = String::new();
            let mut response = String::new();
            let mut len = 0usize;

            // Read response code
            if reader.read_line(&mut line).is_ok() && !line.starts_with("HTTP/1.1 200") {
                return response;
            }
            line.clear();

            // Read headers
            while reader.read_line(&mut line).is_ok() {
                if line.trim() == "" {
                    break;
                }

                {
                    let parsed_line: Vec<&str> = line.split(':').collect();
                    if parsed_line.len() < 2 {
                        return response;
                    }

                    let (key, val) = (parsed_line[0], parsed_line[1]);
                    if key.to_lowercase() == "content-length" {
                        len = match val.trim().parse() {
                            Err(_) => return response,
                            Ok(len) => len,
                        };
                    }
                }
                line.clear();
            }

            // Read body
            let mut buf = [0u8; 256];
            while len > 0 {
                let to_read = len.min(buf.len());
                if reader.read_exact(&mut buf[..to_read]).is_err() {
                    return response;
                }
                response.push_str(&String::from_utf8_lossy(&buf[..to_read]));
                len -= to_read;
            }

            response
        }
    }

    impl WGHandle {
        /// Create a new interface for the tunnel with the given address
        async fn init(addr_v4: IpAddr, addr_v6: IpAddr) -> WGHandle {
            Self::init_with_awg(addr_v4, addr_v6, None).await
        }

        /// Create a new interface with optional AmneziaWG obfuscation config
        async fn init_with_awg(
            addr_v4: IpAddr,
            addr_v6: IpAddr,
            awg: Option<AwgConfig>,
        ) -> WGHandle {
            // Generate a new name, utun100+ should work on macOS and Linux
            let tun_name = format!("utun{}", NEXT_IFACE_IDX.fetch_add(1, Ordering::Relaxed));

            let uapi = crate::device::uapi::UapiServer::default_unix_socket(&tun_name, None, None)
                .unwrap();

            let mut builder = DeviceBuilder::new()
                .create_tun(&tun_name)
                .unwrap()
                .with_udp(UdpSocketFactory)
                .with_uapi(uapi);

            if let Some(awg) = awg {
                builder = builder.with_awg(awg);
            }

            let _device = builder.build().await.unwrap();

            WGHandle {
                _device,
                name: tun_name,
                addr_v4,
                addr_v6,
                started: false,
                peers: vec![],
            }
        }

        #[cfg(target_os = "macos")]
        /// Starts the tunnel
        fn start(&mut self) {
            // Assign the ipv4 address to the interface
            Command::new("ifconfig")
                .args(&[
                    &self.name,
                    &self.addr_v4.to_string(),
                    &self.addr_v4.to_string(),
                    "alias",
                ])
                .status()
                .expect("failed to assign ip to tunnel");

            // Assign the ipv6 address to the interface
            Command::new("ifconfig")
                .args(&[
                    &self.name,
                    "inet6",
                    &self.addr_v6.to_string(),
                    "prefixlen",
                    "128",
                    "alias",
                ])
                .status()
                .expect("failed to assign ipv6 to tunnel");

            // Start the tunnel
            Command::new("ifconfig")
                .args(&[&self.name, "up"])
                .status()
                .expect("failed to start the tunnel");

            self.started = true;

            // Add each peer to the routing table
            for p in &self.peers {
                for r in &p.allowed_ips {
                    let inet_flag = match r.ip {
                        IpAddr::V4(_) => "-inet",
                        IpAddr::V6(_) => "-inet6",
                    };

                    Command::new("route")
                        .args(&[
                            "-q",
                            "-n",
                            "add",
                            inet_flag,
                            &format!("{}/{}", r.ip, r.cidr),
                            "-interface",
                            &self.name,
                        ])
                        .status()
                        .expect("failed to add route");
                }
            }
        }

        #[cfg(target_os = "linux")]
        /// Starts the tunnel
        fn start(&mut self) {
            Command::new("ip")
                .args([
                    "address",
                    "add",
                    &self.addr_v4.to_string(),
                    "dev",
                    &self.name,
                ])
                .status()
                .expect("failed to assign ip to tunnel");

            Command::new("ip")
                .args([
                    "address",
                    "add",
                    &self.addr_v6.to_string(),
                    "dev",
                    &self.name,
                ])
                .status()
                .expect("failed to assign ipv6 to tunnel");

            // Start the tunnel
            Command::new("ip")
                .args(["link", "set", "mtu", "1400", "up", "dev", &self.name])
                .status()
                .expect("failed to start the tunnel");

            self.started = true;

            // Add each peer to the routing table
            for p in &self.peers {
                for r in &p.allowed_ips {
                    Command::new("ip")
                        .args([
                            "route",
                            "add",
                            &format!("{}/{}", r.ip, r.cidr),
                            "dev",
                            &self.name,
                        ])
                        .status()
                        .expect("failed to add route");
                }
            }
        }

        /// Issue a get command on the interface
        async fn wg_get(&self) -> String {
            let path = format!("/var/run/wireguard/{}.sock", self.name);

            let mut socket = UnixStream::connect(path)
                .await
                .expect("Must create UNIX socket to send UAPI requests");
            socket.write_all(b"get=1\n\n").await.unwrap();

            let mut ret = String::new();
            let mut reader = tokio::io::BufReader::new(socket);
            // Read until end of file or empty newline
            while reader.read_line(&mut ret).await.unwrap() > 1 {}
            ret
        }

        /// Issue a set command on the interface
        async fn wg_set(&self, setting: &str) -> String {
            let path = format!("/var/run/wireguard/{}.sock", self.name);
            let mut socket = UnixStream::connect(path)
                .await
                .expect("Must create UNIX socket to send UAPI requests");
            socket
                .write_all(format!("set=1\n{setting}\n\n").as_bytes())
                .await
                .unwrap();

            let mut ret = String::new();
            let mut reader = tokio::io::BufReader::new(socket);
            while reader.read_line(&mut ret).await.unwrap() > 1 {}
            ret
        }

        /// Assign a listen_port to the interface
        async fn wg_set_port(&self, port: u16) -> String {
            self.wg_set(&format!("listen_port={port}")).await
        }

        /// Assign a private_key to the interface
        async fn wg_set_key(&self, key: StaticSecret) -> String {
            self.wg_set(&format!("private_key={}", encode(key.to_bytes())))
                .await
        }

        /// Assign a peer to the interface (with public_key, endpoint and a series of nallowed_ip)
        async fn wg_set_peer(
            &self,
            key: &PublicKey,
            ep: &SocketAddr,
            allowed_ips: &[AllowedIp],
        ) -> String {
            let mut req = format!("public_key={}\nendpoint={}", encode(key.as_bytes()), ep);
            for AllowedIp { ip, cidr } in allowed_ips {
                let _ = write!(req, "\nallowed_ip={ip}/{cidr}");
            }

            self.wg_set(&req).await
        }

        /// Add a new known peer
        async fn add_peer(&mut self, peer: Arc<Peer>) {
            self.wg_set_peer(
                &PublicKey::from(&peer.key),
                &peer.endpoint,
                &peer.allowed_ips,
            )
            .await;
            self.peers.push(peer);
        }
    }

    /// Create a new filename in the /tmp dir
    fn temp_path() -> String {
        let mut path = String::from("/tmp/");
        let mut buf = [0u8; 32];
        OsRng.try_fill_bytes(&mut buf).unwrap();
        path.push_str(&encode(buf));
        path
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    #[ignore]
    /// Test if wireguard starts and creates a unix socket that we can read from
    async fn test_wireguard_get() {
        let wg = WGHandle::init("192.0.2.0".parse().unwrap(), "::2".parse().unwrap()).await;
        let response = wg.wg_get().await;
        assert!(
            response.ends_with("errno=0\n\n"),
            "Got response '{response}'"
        );
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    #[ignore]
    /// Test if wireguard starts and creates a unix socket that we can use to set settings
    async fn test_wireguard_set() {
        let port = next_port();
        let own_private_key = StaticSecret::random_from_rng(rand_core::OsRng);

        let wg = WGHandle::init("192.0.2.0".parse().unwrap(), "::2".parse().unwrap()).await;
        assert!(wg.wg_get().await.ends_with("errno=0\n\n"));
        assert_eq!(wg.wg_set_port(port).await, "errno=0\n\n");
        assert_eq!(wg.wg_set_key(own_private_key.clone()).await, "errno=0\n\n");

        let own_private_key = encode(own_private_key.as_bytes());
        // Check that the response matches what we expect
        assert_eq!(
            wg.wg_get().await,
            format!("private_key={own_private_key}\nlisten_port={port}\nerrno=0\n\n",)
        );

        let peer_private_key = StaticSecret::random_from_rng(rand_core::OsRng);
        let peer_pub_key = PublicKey::from(&peer_private_key);
        let endpoint = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(172, 0, 0, 1)), 50001);
        let allowed_ips = [
            AllowedIp {
                ip: IpAddr::V4(Ipv4Addr::new(172, 0, 0, 2)),
                cidr: 32,
            },
            AllowedIp {
                ip: IpAddr::V6(Ipv6Addr::new(0xf120, 0, 0, 2, 2, 2, 0, 0)),
                cidr: 100,
            },
        ];

        assert_eq!(
            wg.wg_set_peer(&peer_pub_key, &endpoint, &allowed_ips).await,
            "errno=0\n\n"
        );

        // Check that the response matches what we expect
        let wg_get = wg.wg_get().await;
        let peer_pub_key = encode(peer_pub_key.as_bytes());
        assert!(wg_get.contains(&format!("public_key={peer_pub_key}")));
        assert!(wg_get.contains(&format!("endpoint={endpoint}")));
        assert!(wg_get.contains(&format!(
            "allowed_ip={}/{}",
            allowed_ips[0].ip, allowed_ips[0].cidr
        )));
        assert!(wg_get.contains(&format!(
            "allowed_ip={}/{}",
            allowed_ips[1].ip, allowed_ips[1].cidr
        )));
        assert!(wg_get.contains("rx_bytes=0"));
        assert!(wg_get.contains("tx_bytes=0"));
        assert!(wg_get.contains(&format!("private_key={own_private_key}")));
        assert!(wg_get.contains(&format!("listen_port={port}")));
        assert!(wg_get.contains("errno=0"));
    }

    /// Test if wireguard can handle simple ipv4 connections
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    #[ignore]
    async fn test_wg_start_ipv4() {
        let port = next_port();
        let private_key = StaticSecret::random_from_rng(rand_core::OsRng);
        let public_key = PublicKey::from(&private_key);
        let addr_v4 = next_ip();
        let addr_v6 = next_ip_v6();

        let mut wg = WGHandle::init(addr_v4, addr_v6).await;

        assert_eq!(wg.wg_set_port(port).await, "errno=0\n\n");
        assert_eq!(wg.wg_set_key(private_key).await, "errno=0\n\n");

        // Create a new peer whose endpoint is on this machine
        let mut peer = Peer::new(
            SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), next_port()),
            vec![AllowedIp {
                ip: next_ip(),
                cidr: 32,
            }],
        );

        peer.start_in_container(&public_key, &addr_v4, port);

        let peer = Arc::new(peer);

        wg.add_peer(Arc::clone(&peer)).await;
        wg.start();

        let response = peer.get_request();

        assert_eq!(response, encode(PublicKey::from(&peer.key).as_bytes()));
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    #[ignore]
    /// Test if wireguard can handle simple ipv6 connections
    async fn test_wg_start_ipv6() {
        let port = next_port();
        let private_key = StaticSecret::random_from_rng(rand_core::OsRng);
        let public_key = PublicKey::from(&private_key);
        let addr_v4 = next_ip();
        let addr_v6 = next_ip_v6();

        let mut wg = WGHandle::init(addr_v4, addr_v6).await;

        assert_eq!(wg.wg_set_port(port).await, "errno=0\n\n");
        assert_eq!(wg.wg_set_key(private_key).await, "errno=0\n\n");

        let mut peer = Peer::new(
            SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), next_port()),
            vec![AllowedIp {
                ip: next_ip_v6(),
                cidr: 128,
            }],
        );

        peer.start_in_container(&public_key, &addr_v6, port);

        let peer = Arc::new(peer);

        wg.add_peer(Arc::clone(&peer)).await;
        wg.start();

        let response = peer.get_request();

        assert_eq!(response, encode(PublicKey::from(&peer.key).as_bytes()));
    }

    /// Test if wireguard can handle connection with an ipv6 endpoint
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    #[ignore]
    #[cfg(target_os = "linux")] // Can't make docker work with ipv6 on macOS ATM
    async fn test_wg_start_ipv6_endpoint() {
        // Skip if the host has IPv6 disabled (detected by run-e2e-tests.sh on the host)
        if std::env::var("E2E_SKIP_IPV6_ENDPOINT").is_ok() {
            eprintln!("Skipping test: host has IPv6 disabled (E2E_SKIP_IPV6_ENDPOINT set)");
            return;
        }

        let port = next_port();
        let private_key = StaticSecret::random_from_rng(rand_core::OsRng);
        let public_key = PublicKey::from(&private_key);
        let addr_v4 = next_ip();
        let addr_v6 = next_ip_v6();

        let mut wg = WGHandle::init(addr_v4, addr_v6).await;

        assert_eq!(wg.wg_set_port(port).await, "errno=0\n\n");
        assert_eq!(wg.wg_set_key(private_key).await, "errno=0\n\n");

        let mut peer = Peer::new(
            SocketAddr::new(
                IpAddr::V6(Ipv6Addr::new(0, 0, 0, 0, 0, 0, 0, 1)),
                next_port(),
            ),
            vec![AllowedIp {
                ip: next_ip_v6(),
                cidr: 128,
            }],
        );

        peer.start_in_container(&public_key, &addr_v6, port);

        let peer = Arc::new(peer);

        wg.add_peer(Arc::clone(&peer)).await;
        wg.start();

        let response = peer.get_request();

        assert_eq!(response, encode(PublicKey::from(&peer.key).as_bytes()));
    }

    /// Test many concurrent connections
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    #[ignore]
    async fn test_wg_concurrent() {
        let port = next_port();
        let private_key = StaticSecret::random_from_rng(rand_core::OsRng);
        let public_key = PublicKey::from(&private_key);
        let addr_v4 = next_ip();
        let addr_v6 = next_ip_v6();

        let mut wg = WGHandle::init(addr_v4, addr_v6).await;

        assert_eq!(wg.wg_set_port(port).await, "errno=0\n\n");
        assert_eq!(wg.wg_set_key(private_key).await, "errno=0\n\n");

        for _ in 0..5 {
            // Create a new peer whose endpoint is on this machine
            let mut peer = Peer::new(
                SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), next_port()),
                vec![AllowedIp {
                    ip: next_ip(),
                    cidr: 32,
                }],
            );

            peer.start_in_container(&public_key, &addr_v4, port);

            let peer = Arc::new(peer);

            wg.add_peer(Arc::clone(&peer)).await;
        }

        wg.start();

        let mut threads = vec![];

        for p in wg.peers {
            let pub_key = PublicKey::from(&p.key);
            threads.push(thread::spawn(move || {
                for _ in 0..100 {
                    let response = p.get_request();
                    assert_eq!(response, encode(pub_key.as_bytes()));
                }
            }));
        }

        for t in threads {
            t.join().unwrap();
        }
    }

    /// Test many concurrent connections
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    #[ignore]
    async fn test_wg_concurrent_v6() {
        let port = next_port();
        let private_key = StaticSecret::random_from_rng(rand_core::OsRng);
        let public_key = PublicKey::from(&private_key);
        let addr_v4 = next_ip();
        let addr_v6 = next_ip_v6();

        let mut wg = WGHandle::init(addr_v4, addr_v6).await;

        assert_eq!(wg.wg_set_port(port).await, "errno=0\n\n");
        assert_eq!(wg.wg_set_key(private_key).await, "errno=0\n\n");

        for _ in 0..5 {
            // Create a new peer whose endpoint is on this machine
            let mut peer = Peer::new(
                SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), next_port()),
                vec![AllowedIp {
                    ip: next_ip_v6(),
                    cidr: 128,
                }],
            );

            peer.start_in_container(&public_key, &addr_v6, port);

            let peer = Arc::new(peer);

            wg.add_peer(Arc::clone(&peer)).await;
        }

        wg.start();

        let mut threads = vec![];

        for p in wg.peers {
            let pub_key = PublicKey::from(&p.key);
            threads.push(thread::spawn(move || {
                for _ in 0..100 {
                    let response = p.get_request();
                    assert_eq!(response, encode(pub_key.as_bytes()));
                }
            }));
        }

        for t in threads {
            t.join().unwrap();
        }
    }

    /// AWG config used by AmneziaWG e2e tests — non-trivial obfuscation settings.
    fn test_awg_config() -> AwgConfig {
        AwgConfig {
            h1: MagicHeader::range(1000, 1100),
            h2: MagicHeader::range(2000, 2100),
            h3: MagicHeader::range(3000, 3100),
            h4: MagicHeader::range(4000, 4100),
            s1: 32,
            s2: 32,
            s3: 0,
            s4: 0,
            jc: 3,
            jmin: 50,
            jmax: 150,
        }
    }

    /// Test AmneziaWG handshake between two gotatun instances over localhost UDP.
    /// Uses non-trivial AWG obfuscation (custom headers, padding, junk packets)
    /// and verifies the handshake completes via persistent_keepalive triggering traffic.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    #[ignore]
    async fn test_awg_handshake() {
        let awg = test_awg_config();

        let port_a = next_port();
        let port_b = next_port();
        let key_a = StaticSecret::random_from_rng(rand_core::OsRng);
        let key_b = StaticSecret::random_from_rng(rand_core::OsRng);
        let pub_a = PublicKey::from(&key_a);
        let pub_b = PublicKey::from(&key_b);

        let addr_a = next_ip();
        let addr_b = next_ip();
        let addr_v6_a = next_ip_v6();
        let addr_v6_b = next_ip_v6();

        // Create two gotatun devices with matching AWG config
        let wg_a = WGHandle::init_with_awg(addr_a, addr_v6_a, Some(awg.clone())).await;
        assert_eq!(wg_a.wg_set_port(port_a).await, "errno=0\n\n");
        assert_eq!(wg_a.wg_set_key(key_a).await, "errno=0\n\n");

        let wg_b = WGHandle::init_with_awg(addr_b, addr_v6_b, Some(awg)).await;
        assert_eq!(wg_b.wg_set_port(port_b).await, "errno=0\n\n");
        assert_eq!(wg_b.wg_set_key(key_b).await, "errno=0\n\n");

        // Add peers via UAPI with persistent_keepalive=1 to trigger handshake
        let endpoint_b = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), port_b);
        assert_eq!(
            wg_a.wg_set(&format!(
                "public_key={}\nendpoint={endpoint_b}\nallowed_ip={addr_b}/32\npersistent_keepalive_interval=1",
                encode(pub_b.as_bytes()),
            ))
            .await,
            "errno=0\n\n"
        );

        let endpoint_a = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), port_a);
        assert_eq!(
            wg_b.wg_set(&format!(
                "public_key={}\nendpoint={endpoint_a}\nallowed_ip={addr_a}/32\npersistent_keepalive_interval=1",
                encode(pub_a.as_bytes()),
            ))
            .await,
            "errno=0\n\n"
        );

        // Wait for persistent_keepalive to trigger AWG handshake over UDP
        tokio::time::sleep(std::time::Duration::from_secs(5)).await;

        // Verify AWG handshake completed: check last_handshake_time is set and
        // at least one side sent data packets (keepalives).
        // The handshake succeeding proves both sides can encode/decode AWG-obfuscated
        // HandshakeInit (h1/s1/junk) and HandshakeResp (h2/s2) messages.
        let get_a = wg_a.wg_get().await;
        assert!(
            get_a.contains("last_handshake_time_sec=")
                && !get_a.contains("last_handshake_time_sec=0\n"),
            "AWG handshake never completed on device A: {get_a}"
        );
        assert!(
            !get_a.contains("tx_bytes=0"),
            "Device A sent no data after AWG handshake: {get_a}"
        );

        let get_b = wg_b.wg_get().await;
        assert!(
            get_b.contains("last_handshake_time_sec=")
                && !get_b.contains("last_handshake_time_sec=0\n"),
            "AWG handshake never completed on device B: {get_b}"
        );
    }
}
