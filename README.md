# GotaTun — AmneziaWG fork

Fork of [Mullvad's GotaTun](https://github.com/mullvad/gotatun) (a userspace [WireGuard<sup>®</sup>](https://www.wireguard.com/) implementation, itself a fork of [BoringTun](https://github.com/cloudflare/boringtun)) that adds full [AmneziaWG 2.0](https://docs.amnezia.org/documentation/amnezia-wg/) obfuscation support. Byte-level interoperability with the reference [amneziawg-go](https://github.com/amnezia-vpn/amneziawg-go) implementation is verified by dedicated integration tests.

Upstream GotaTun does **not** implement AmneziaWG; this fork adds it on top. The `amnezia` branch tracks upstream `main` closely and layers AWG-specific changes over it.

## AmneziaWG

AmneziaWG modifies WireGuard packets so they no longer match known WireGuard traffic signatures, defeating deep packet inspection (DPI). Both sides of a tunnel must use identical AWG settings. With no AWG flags, behaviour is identical to standard WireGuard.

The full 2.0 protocol is implemented: custom message headers (H1–H4), message paddings (S1–S4), junk packets (Jc/Jmin/Jmax), and custom signature packets (I1–I5 with the `<b>`/`<r>`/`<rc>`/`<rd>`/`<t>` DSL).

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
| `--awg-i1` | `AWG_I1` | Custom signature packet 1 (DSL — see below) |
| `--awg-i2` | `AWG_I2` | Custom signature packet 2 |
| `--awg-i3` | `AWG_I3` | Custom signature packet 3 |
| `--awg-i4` | `AWG_I4` | Custom signature packet 4 |
| `--awg-i5` | `AWG_I5` | Custom signature packet 5 |

### Custom signature packets (I1–I5)

Up to five custom packets are sent before each handshake initiation — ahead of the junk packets and the actual init. Each spec is a sequence of DSL tags:

| Tag | Produces |
|------|----------|
| `<b 0xHEX>` | Literal bytes (hex-decoded; `0x` prefix optional; even length) |
| `<r N>` | N cryptographically random bytes |
| `<rc N>` | N random ASCII letters `[a-zA-Z]` |
| `<rd N>` | N random ASCII digits `[0-9]` |
| `<t>` | Current Unix timestamp as 4 big-endian bytes |

Tags render in declaration order; any characters outside `<...>` are ignored. Unset slots are skipped on the wire.

Example:

```sh
gotatun -f utun0 \
  --awg-h1 1000-1100 --awg-h2 2000-2100 --awg-h3 3000-3100 --awg-h4 4000-4100 \
  --awg-s1 32 --awg-s2 32 \
  --awg-jc 3 --awg-jmin 50 --awg-jmax 150 \
  --awg-i1 '<b 0xDEADBEEF><r 16>' --awg-i2 '<rd 10>'
```

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
./run-e2e-tests.sh                         # run all e2e tests
./run-e2e-tests.sh test_wg_start_ipv4      # run a specific test
./run-e2e-tests.sh interop_amneziawg_go    # only the amneziawg-go interop suite
```

The e2e tests create real TUN interfaces and WireGuard tunnels, verifying standard WireGuard and AmneziaWG obfuscation. Three additional tests (`interop_amneziawg_go_{baseline,v1,v2}`) spin up our `gotatun` alongside a pinned `amneziawg-go` binary (built into the test image) and verify that a handshake completes between the two across all three obfuscation profiles — this is what guarantees byte-level compatibility with the reference implementation.

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
