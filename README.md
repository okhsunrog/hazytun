# GotaTun

A userspace [WireGuard<sup>®</sup>](https://www.wireguard.com/) implementation with [AmneziaWG](https://docs.amnezia.org/documentation/amnezia-wg/) obfuscation support.

Fork of [Mullvad's GotaTun](https://github.com/mullvad/gotatun), which is itself a fork of [BoringTun](https://github.com/cloudflare/boringtun).

## AmneziaWG

GotaTun supports AmneziaWG protocol obfuscation to evade deep packet inspection (DPI). When enabled, WireGuard packets are modified so they no longer match known WireGuard traffic signatures. Both sides of a tunnel must use identical AWG settings.

AWG parameters are passed via CLI flags or environment variables:

| Flag | Env var | Description |
|------|---------|-------------|
| `--awg-h1` | `AWG_H1` | Header for HandshakeInit (value or `min-max` range) |
| `--awg-h2` | `AWG_H2` | Header for HandshakeResp |
| `--awg-h3` | `AWG_H3` | Header for CookieReply |
| `--awg-h4` | `AWG_H4` | Header for Data |
| `--awg-s1` | `AWG_S1` | Padding bytes prepended to HandshakeInit |
| `--awg-s2` | `AWG_S2` | Padding bytes prepended to HandshakeResp |
| `--awg-s3` | `AWG_S3` | Padding bytes prepended to CookieReply |
| `--awg-s4` | `AWG_S4` | Padding bytes prepended to Data |
| `--awg-jc` | `AWG_JC` | Number of junk packets before handshake |
| `--awg-jmin` | `AWG_JMIN` | Minimum junk packet size (bytes) |
| `--awg-jmax` | `AWG_JMAX` | Maximum junk packet size (bytes) |

Example:

```sh
gotatun -f utun0 \
  --awg-h1 1000-1100 --awg-h2 2000-2100 --awg-h3 3000-3100 --awg-h4 4000-4100 \
  --awg-s1 32 --awg-s2 32 \
  --awg-jc 3 --awg-jmin 50 --awg-jmax 150
```

With no AWG flags, behavior is identical to standard WireGuard.

## License

All source code in this repository is subject to the terms of the Mozilla Public License, version 2.0 unless stated otherwise. A copy of this license can be found in the file "LICENSE" or at <https://www.mozilla.org/MPL/2.0/>.

Contributions made prior to March 5, 2026 are licensed under the old BSD 3-clause license. A copy of this license can be found in the file "LICENSE-CLOUDFLARE".

### Contribution

Unless you explicitly state otherwise, any contribution intentionally submitted for inclusion in the work by you, as defined in the MPL-2.0 License, shall be licensed as above, without any additional terms or conditions.

## Building

- Library only: `cargo build --lib --no-default-features --release [--target $(TARGET_TRIPLE)]`
- Executable: `cargo build --bin gotatun --release [--target $(TARGET_TRIPLE)]`

### Installation

By default the executable is placed in the `./target/release` folder. You can copy it to a desired location manually, or install it using `cargo install --bin gotatun --path .`.

### Nix

To build the executable, simply run `nix build .#gotatun`. The final binary will be located in `result/bin/gotatun`.

## Running

As per the specification, to start a tunnel use:

`gotatun [-f/--foreground] INTERFACE-NAME`

The tunnel can then be configured using [wg](https://git.zx2c4.com/WireGuard/about/src/tools/man/wg.8), as a regular WireGuard tunnel, or any other tool.

It is also possible to use with [wg-quick](https://git.zx2c4.com/WireGuard/about/src/tools/man/wg-quick.8) by setting the environment variable `WG_QUICK_USERSPACE_IMPLEMENTATION` to `gotatun`. For example:

`sudo WG_QUICK_USERSPACE_IMPLEMENTATION=gotatun WG_SUDO=1 wg-quick up CONFIGURATION`

*Please note that `wg-quick` will ignore `WG_QUICK_USERSPACE_IMPLEMENTATION` on Linux if you have the wireguard kernel module installed.*

## Testing

Unit tests run without special privileges:

```sh
cargo test
```

End-to-end tests run inside an isolated Docker container (requires Docker):

```sh
./run-e2e-tests.sh                        # run all e2e tests
./run-e2e-tests.sh test_wg_start_ipv4     # run a specific test
```

The e2e tests create real TUN interfaces and WireGuard tunnels, verifying both standard WireGuard and AmneziaWG obfuscation.

## Supported platforms

Target triple                 |Binary|Library|
------------------------------|:----:|------|
x86_64-unknown-linux-gnu      |  ✓   | ✓    |
aarch64-unknown-linux-gnu     |  ✓   | ✓    |
aarch64-apple-darwin          |  ✓   | ✓    |
x86_64-pc-windows-msvc        |  ✓   | ✓    |
x86_64-pc-windows-gnullvm     |  ✓   | ✓    |
aarch64-pc-windows-msvc       |  ✓   | ✓    |
aarch64-pc-windows-gnullvm    |  ✓   | ✓    |
x86_64-linux-android          |      | ✓    |
aarch64-linux-android         |      | ✓    |
aarch64-apple-ios             |      | ✓    |

<sub>Other targets may work, but we only test for these</sub>

### Linux

`x86-64`, and `aarch64` architectures are supported. The behaviour should be identical to that of [wireguard-go](https://git.zx2c4.com/wireguard-go/about/), with the following difference:

`gotatun` will drop privileges when started. When privileges are dropped it is not possible to set `fwmark`. If `fwmark` is required, such as when using `wg-quick`, run with `--disable-drop-privileges` or set the environment variable `WG_SUDO=1`.

You will need to give the executable the `CAP_NET_ADMIN` capability using: `sudo setcap cap_net_admin+epi gotatun`. sudo is not needed.

### macOS

The behaviour is similar to that of [wireguard-go](https://git.zx2c4.com/wireguard-go/about/). Specifically the interface name must be `utun[0-9]+` for an explicit interface name or `utun` to have the kernel select the lowest available. If you choose `utun` as the interface name, and the environment variable `WG_TUN_NAME_FILE` is defined, then the actual name of the interface chosen by the kernel is written to the file specified by that variable.

## UAPI extensions

See [UAPI](./UAPI.md) for extensions to the `wg` configuration protocol.

---

## Audits

Independent security audits have been conducted on the project.
See the [audit](./audits/README.md) directory.

---
<sub><sub><sub><sub>WireGuard is a registered trademark of Jason A. Donenfeld. GotaTun is not sponsored or endorsed by Jason A. Donenfeld.</sub></sub></sub></sub>
