// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.
//
// This file incorporates work covered by the following copyright and
// permission notice:
//
//   Copyright (c) Mullvad VPN AB. All rights reserved.
//
// SPDX-License-Identifier: MPL-2.0

use std::{future::ready, time::Duration};

use futures::{StreamExt, future::pending};
use mock::MockEavesdropper;
use rand::{SeedableRng, rngs::StdRng};
use tokio::{join, select, time::sleep};
use zerocopy::IntoBytes;

use crate::noise::awg::{AwgConfig, MagicHeader, ObfChain};
use crate::noise::index_table::IndexTable;

pub mod mock;

/// Assert that the expected number of packets is sent.
/// We expect there to be [`packet_count`] data packets, one handshake init,
/// one handshake resp, and one keepalive.
#[tokio::test]
#[test_log::test]
async fn number_of_packets() {
    test_device_pair(async |eve| {
        let expected_count = packet_count() + 2 + 1;
        let ipv4_count = eve.ipv4().count().await;
        assert_eq!(ipv4_count, expected_count);
    })
    .await
}

/// Assert that IPv6 is not used.
#[tokio::test]
#[test_log::test]
async fn ipv6_isnt_used() {
    test_device_pair(async |eve| {
        let ipv6_count = eve.ipv6().count().await;
        assert_eq!(dbg!(ipv6_count), 0);
    })
    .await
}

/// Assert that exactly one handshake is performed.
/// This test does not run for long enough to trigger a second handshake.
#[tokio::test]
#[test_log::test]
async fn one_handshake() {
    test_device_pair(async |eve| {
        let handshake_inits = async {
            assert_eq!(eve.wg_handshake_init().count().await, 1);
        };
        let handshake_resps = async {
            assert_eq!(eve.wg_handshake_resp().count().await, 1);
        };
        join! { handshake_inits, handshake_resps };
    })
    .await
}

// TODO: is this according to spec?
/// Assert that exactly one keepalive is sent.
/// The keepalive should be sent after the handshake is completed.
#[tokio::test]
#[test_log::test]
async fn one_keepalive() {
    test_device_pair(async |eve| {
        let keepalive_count = eve
            .wg_data()
            .filter(|wg_data| ready(wg_data.is_keepalive()))
            .count()
            .await;

        assert_eq!(keepalive_count, 1);
    })
    .await
}

/// Assert that all WgData packets lenghts are a multiple of 16.
#[tokio::test]
#[test_log::test]
async fn wg_data_length_is_x16() {
    test_device_pair(async |eve| {
        let wg_data_count = eve
            .wg_data()
            .map(|wg| {
                let payload_len = wg.encrypted_encapsulated_packet().len();
                assert!(
                    payload_len.is_multiple_of(16),
                    "wireguard data length must be a multiple of 16, but was {payload_len}"
                );
            })
            .count()
            .await;

        assert!(dbg!(wg_data_count) >= packet_count());
    })
    .await
}

/// Test that indices work as expected.
#[tokio::test]
#[test_log::test]
async fn test_indices() {
    // Compute the expected first index from each seeded RNG.
    let expected_alice_idx =
        IndexTable::next_id(&mut StdRng::seed_from_u64(mock::ALICE_INDEX_SEED));
    let expected_bob_idx = IndexTable::next_id(&mut StdRng::seed_from_u64(mock::BOB_INDEX_SEED));

    test_device_pair(async |eve| {
        let check_init = eve.wg_handshake_init().for_each(async |p| {
            assert_eq!(p.sender_idx.get(), expected_alice_idx);
        });
        let check_alice_data = eve.wg_data().for_each(async |p| {
            // Every data packet is sent to Bob
            assert_eq!(p.header.receiver_idx, expected_bob_idx);
        });
        let check_resp = eve.wg_handshake_resp().for_each(async |p| {
            assert_eq!(p.sender_idx.get(), expected_bob_idx);
        });
        join!(check_init, check_resp, check_alice_data);
    })
    .await;
}

/// Test that device handles roaming (changes to endpoint) for data packets.
#[tokio::test]
#[test_log::test]
async fn test_endpoint_roaming() {
    let (mut alice, mut bob, eve) = mock::device_pair().await;
    let packet = mock::packet(b"Hello!");

    let mut ping_pong = async |alice_ip| {
        *alice.source_ipv4_override.lock().await = Some(alice_ip);

        alice.app_tx.send(packet.clone()).await;
        assert_eq!(bob.app_rx.recv().await.as_bytes(), packet.as_bytes());

        let peers = bob.device.peers().await;
        assert_eq!(peers.len(), 1);
        let stats = &peers[0];

        // Bob's device's peer should point to Alice's last known endpoint
        assert_eq!(
            stats.peer.endpoint.map(|addr| addr.ip()),
            Some(alice_ip.into()),
        );

        // Bob's sent packets should use the new endpoint
        let ip_stream = eve.ip();
        tokio::pin!(ip_stream);

        let next_packet = async {
            tokio::time::timeout(Duration::from_secs(5), ip_stream.next())
                .await
                .expect("did not see sent packet")
        };

        let (_, sniffed_packet) = join! {
            bob.app_tx.send(packet.clone()),
            next_packet,
        };
        alice.app_rx.recv().await;

        assert_eq!(
            sniffed_packet.and_then(|ip| ip.destination()),
            Some(alice_ip.into())
        );
    };

    // Simulate roaming by changing Alice's source IP
    ping_pong("1.2.3.4".parse().unwrap()).await;
    ping_pong("1.3.3.7".parse().unwrap()).await;
    ping_pong("1.2.3.4".parse().unwrap()).await;
}

/// The number of packets we send through the tunnel
fn packet_count() -> usize {
    mock::packets_of_every_size().len()
}

/// Test that packets flow correctly with AWG obfuscation enabled.
#[tokio::test]
#[test_log::test]
async fn awg_data_flow() {
    let awg = AwgConfig {
        h1: MagicHeader::range(1000, 1100),
        h2: MagicHeader::range(2000, 2100),
        h3: MagicHeader::range(3000, 3100),
        h4: MagicHeader::range(4000, 4100),
        s1: 32,
        s2: 16,
        s3: 8,
        s4: 4,
        jc: 3,
        jmin: 50,
        jmax: 150,
        i_packets: [const { None }; 5],
    };
    assert!(awg.validate().is_ok());

    let (alice, mut bob, _eve) = mock::device_pair_with_awg(awg).await;
    let packet = mock::packet(b"Hello AWG!");

    let drive = async move {
        alice.app_tx.send(packet.clone()).await;
        let received = bob.app_rx.recv().await;
        assert_eq!(received.as_bytes(), packet.as_bytes());

        drop((alice, bob));
    };

    select! {
        _ = drive => {},
        _ = sleep(Duration::from_secs(5)) => panic!("awg_data_flow timeout"),
    }
}

/// Test that AWG obfuscation changes wire-level packet headers.
#[tokio::test]
#[test_log::test]
async fn awg_wire_format_obfuscated() {
    let awg = AwgConfig {
        h1: MagicHeader::range(1000, 1100),
        h2: MagicHeader::range(2000, 2100),
        h3: MagicHeader::range(3000, 3100),
        h4: MagicHeader::range(4000, 4100),
        s1: 32,
        s2: 16,
        s3: 0,
        s4: 8,
        jc: 0,
        jmin: 0,
        jmax: 0,
        i_packets: [const { None }; 5],
    };

    let (alice, mut bob, eve) = mock::device_pair_with_awg(awg.clone()).await;
    let packet = mock::packet(b"Hello obfuscated!");

    let eavesdrop = async {
        // Collect all UDP payloads and verify they don't have standard WG headers
        let mut udp_stream = std::pin::pin!(eve.udp());
        let mut seen_any = false;
        while let Some(udp_pkt) = udp_stream.next().await {
            let payload = udp_pkt.as_bytes();
            if payload.len() >= 4 {
                let header = u32::from_le_bytes(payload[..4].try_into().unwrap());
                // Standard WG uses types 1-4 in the first byte (with 3 zero reserved bytes)
                // AWG headers should be in our custom ranges
                assert!(
                    header > 4,
                    "expected obfuscated header, got standard WG header: {header}"
                );
                seen_any = true;
            }
        }
        assert!(seen_any, "expected to see some packets on the wire");
    };

    let drive = async move {
        alice.app_tx.send(packet.clone()).await;
        let received = bob.app_rx.recv().await;
        assert_eq!(received.as_bytes(), packet.as_bytes());
        drop((alice, bob));
    };

    let combined = async { tokio::join!(drive, eavesdrop) };
    select! {
        _ = combined => {},
        _ = sleep(Duration::from_secs(5)) => panic!("awg_wire_format_obfuscated timeout"),
    }
}

/// Smoke test: I1..I5 custom signature packets do not break the handshake.
///
/// Uses a non-trivial mix of DSL tags across slots (with gaps) plus junk
/// packets and headers/padding. End-to-end data flow must still complete.
#[tokio::test]
#[test_log::test]
async fn awg_i_packets_dataflow() {
    let mut awg = AwgConfig {
        h1: MagicHeader::range(1000, 1100),
        h2: MagicHeader::range(2000, 2100),
        h3: MagicHeader::range(3000, 3100),
        h4: MagicHeader::range(4000, 4100),
        s1: 16,
        s2: 16,
        s3: 8,
        s4: 4,
        jc: 2,
        jmin: 30,
        jmax: 50,
        i_packets: [const { None }; 5],
    };
    awg.i_packets[0] = Some(ObfChain::parse("<b 0x11223344>").unwrap());
    awg.i_packets[1] = Some(ObfChain::parse("<r 20>").unwrap());
    // I3 deliberately empty — verifies that None slots are skipped cleanly.
    awg.i_packets[3] = Some(ObfChain::parse("<rd 12><rc 8>").unwrap());
    awg.i_packets[4] = Some(ObfChain::parse("<t>").unwrap());
    assert!(awg.validate().is_ok());

    let (alice, mut bob, _eve) = mock::device_pair_with_awg(awg).await;
    let packet = mock::packet(b"hello through I-packets");

    let drive = async move {
        alice.app_tx.send(packet.clone()).await;
        let received = bob.app_rx.recv().await;
        assert_eq!(received.as_bytes(), packet.as_bytes());
        drop((alice, bob));
    };

    select! {
        _ = drive => {},
        _ = sleep(Duration::from_secs(5)) => panic!("awg_i_packets_dataflow timeout"),
    }
}

/// Wire-order test: I-packets are sent first, then junk, then the handshake
/// init. None slots are skipped (I3 here). Static `<b …>` bytes are emitted
/// verbatim, random tags produce the correct byte count.
#[tokio::test]
#[test_log::test]
async fn awg_i_packets_wire_order() {
    let mut awg = AwgConfig {
        h1: MagicHeader::range(1000, 1100),
        h2: MagicHeader::range(2000, 2100),
        h3: MagicHeader::range(3000, 3100),
        h4: MagicHeader::range(4000, 4100),
        s1: 0,
        s2: 0,
        s3: 0,
        s4: 0,
        jc: 2,
        // Fixed-size junk so we can identify them by size exactly.
        jmin: 40,
        jmax: 40,
        i_packets: [const { None }; 5],
    };
    // I1 — static bytes (unique, identifiable).
    awg.i_packets[0] = Some(ObfChain::parse("<b 0xCAFEBABE>").unwrap());
    // I2 — 16 random bytes.
    awg.i_packets[1] = Some(ObfChain::parse("<r 16>").unwrap());
    // I3 intentionally None — must be skipped in the stream.
    // I4 — 8 digits.
    awg.i_packets[3] = Some(ObfChain::parse("<rd 8>").unwrap());
    // I5 — static bytes again.
    awg.i_packets[4] = Some(ObfChain::parse("<b 0xDEADBEEF>").unwrap());
    assert!(awg.validate().is_ok());

    let (alice, mut bob, eve) = mock::device_pair_with_awg(awg).await;
    let packet = mock::packet(b"trigger handshake");

    // Collect the first 7 UDP payloads on the wire (UDP header stripped).
    // These must come from alice's handshake burst: 4 I-packets
    // (I1, I2, I4, I5 — I3 skipped), 2 junk, 1 handshake init.
    let eavesdrop = async {
        let udp_stream = eve.udp().map(|u| u.into_payload().as_bytes().to_vec());
        let packets: Vec<Vec<u8>> = udp_stream.take(7).collect().await;

        assert_eq!(
            packets.len(),
            7,
            "expected 7 packets, got {}",
            packets.len()
        );

        // I1: static 4 bytes
        assert_eq!(packets[0], vec![0xCA, 0xFE, 0xBA, 0xBE], "I1 mismatch");
        // I2: 16 random bytes — only length is deterministic
        assert_eq!(packets[1].len(), 16, "I2 size");
        // I4: 8 ASCII digits
        assert_eq!(packets[2].len(), 8, "I4 size");
        for b in &packets[2] {
            assert!(b.is_ascii_digit(), "I4 non-digit byte 0x{b:02x}");
        }
        // I5: static 4 bytes
        assert_eq!(packets[3], vec![0xDE, 0xAD, 0xBE, 0xEF], "I5 mismatch");

        // Junk: two packets of exactly 40 bytes
        assert_eq!(packets[4].len(), 40, "junk 1 size");
        assert_eq!(packets[5].len(), 40, "junk 2 size");

        // Handshake init: size = MessageInitiation struct (148 bytes) with
        // custom header in H1 range [1000..=1100] as LE u32.
        assert_eq!(packets[6].len(), 148, "init size");
        let header = u32::from_le_bytes(packets[6][..4].try_into().unwrap());
        assert!(
            (1000..=1100).contains(&header),
            "init header {header} not in H1 range"
        );
    };

    let drive = async move {
        alice.app_tx.send(packet.clone()).await;
        let _ = bob.app_rx.recv().await;
        drop((alice, bob));
    };

    let combined = async { tokio::join!(drive, eavesdrop) };
    select! {
        _ = combined => {},
        _ = sleep(Duration::from_secs(5)) => panic!("awg_i_packets_wire_order timeout"),
    }
}

/// Helper method to test that packets can be sent from one [`Device`] to another.
/// Use `eavesdrop` to sniff wireguard packets and assert things about the connection.
async fn test_device_pair(eavesdrop: impl AsyncFnOnce(MockEavesdropper) + Send) {
    let (mut alice, mut bob, eve) = mock::device_pair().await;

    // Create a future to eavesdrop on alice and bob.
    let eavesdrop = async {
        select! {
            _ = eavesdrop(eve) => {}
            _ = sleep(Duration::from_secs(1)) => panic!("eavesdrop timeout"),
        }
    };

    // Create a future to drive alice and bob.
    let drive_connection = async move {
        let packets_to_send = mock::packets_of_every_size();
        let packets_to_recv = packets_to_send.clone();

        // Send a bunch of packets from alice to bob.
        let send_packets = async {
            for packet in packets_to_send {
                alice.app_tx.send(packet).await;
            }
            pending().await
        };

        // Receive expected packets to bob from alice.
        let wait_for_packets = async {
            for expected_packet in packets_to_recv {
                let p = bob.app_rx.recv().await;
                assert_eq!(p.as_bytes(), expected_packet.as_bytes());
            }
        };

        select! {
            _ = wait_for_packets => {},
            _ = send_packets => unreachable!(),
            _ = alice.app_rx.recv() => panic!("no data is sent from bob to alice"),
            _ = sleep(Duration::from_secs(1)) => panic!("timeout"),
        }

        // Shut down alice and bob after `wait_for_packets`
        drop((alice, bob));
    };

    // Drive the connection, and eavesdrop it at the same time.
    join! {
        drive_connection,
        eavesdrop
    };
}
