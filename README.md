# YubiKey plugin for age clients

`age-plugin-yubikey` is a plugin for [age](https://age-encryption.org/v1) clients
like [`age`](https://age-encryption.org) and [`rage`](https://str4d.xyz/rage),
which enables files to be encrypted to age identities stored on YubiKeys.

## Installation

| Environment | CLI command |
|-------------|-------------|
| Cargo (Rust 1.65+) | `cargo install age-plugin-yubikey` |
| Homebrew (macOS or Linux) | `brew install age-plugin-yubikey` |
| Arch Linux | `pacman -S age-plugin-yubikey` |
| Debian | [Debian package](https://github.com/str4d/age-plugin-yubikey/releases) |
| NixOS | Add to config:<br>`environment.systemPackages = [`<br>`  pkgs.age-plugin-yubikey`<br>`];`<br>Or run `nix-env -i age-plugin-yubikey` |
| Ubuntu 20.04+ | [Debian package](https://github.com/str4d/age-plugin-yubikey/releases) |
| OpenBSD | `pkg_add age-plugin-yubikey` (security/age-plugin-yubikey) |

On Windows, Linux, and macOS, you can use the
[pre-built binaries](https://github.com/str4d/age-plugin-yubikey/releases).

Help from new packagers is very welcome.

### Linux, BSD, etc.

On non-Windows, non-macOS systems, you need to ensure that the `pcscd` service
is installed and running. 

| Environment | CLI command |
|-------------|-------------|
| Debian or Ubuntu | `sudo apt-get install pcscd` |
| Fedora | `sudo dnf install pcsc-lite` |
| OpenBSD | As ```root``` do:<br>`pkg_add pcsc-lite ccid`<br>`rcctl enable pcscd`<br>`rcctl start pcscd` |
| FreeBSD | As ```root``` do:<br>`pkg install pcsc-lite libccid`<br>`service pcscd enable`<br>`service pcscd start` |
| Arch | `sudo pacman -S pcsclite pcsc-tools yubikey-manager`<br>`sudo systemctl enable pcscd`<br>`sudo systemctl start pcscd`| 

When installing via Cargo, you also need to ensure that the development headers
for the `pcsc-lite` library are available, so that the `pcsc-sys` crate can be
compiled.

| Environment | CLI command |
|-------------|-------------|
| Debian or Ubuntu | `sudo apt-get install libpcsclite-dev` |
| Fedora | `sudo dnf install pcsc-lite-devel` |

### Windows Subsystem for Linux (WSL)

WSL does not currently provide native support for USB devices. However, Windows
binaries installed on the host can be run from inside a WSL environment. This
means that you can encrypt or decrypt files inside a WSL environment with a
YubiKey:

1. Install `age-plugin-yubikey` on the Windows host.
2. Install an age client inside the WSL environment.
3. Ensure that `age-plugin-yubikey.exe` is available in the WSL environment's
   `PATH`. For default WSL setups, the Windows host's `PATH` is automatically
   added to the WSL environment's `PATH` (see
   [this Microsoft blog post](https://devblogs.microsoft.com/commandline/share-environment-vars-between-wsl-and-windows/)
   for more details).

## Configuration

`age-plugin-yubikey` identities have two parts:
- The secret key material, which is stored inside a YubiKey.
- An age identity file, which contains information that an age client can use to
  figure out which YubiKey secret key should be used.

There are two ways to configure a YubiKey as an age identity. You can run the
plugin binary directly to use a simple text interface, which will create an age
identity file:

```
$ age-plugin-yubikey
```

Or you can use command-line flags to programmatically generate an identity and
print it to standard output:

```
$ age-plugin-yubikey --generate \
    [--serial SERIAL] \
    [--slot SLOT] \
    [--name NAME] \
    [--pin-policy PIN-POLICY] \
    [--touch-policy TOUCH-POLICY]
```

Once an identity has been created, you can regenerate it later:

```
$ age-plugin-yubikey --identity [--serial SERIAL] --slot SLOT
```

To use the identity with an age client, it needs to be stored in a file. When
using the above programmatic flags, you can do this by redirecting standard
output to a file. On a Unix system like macOS or Ubuntu:

```
$ age-plugin-yubikey --identity --slot SLOT > yubikey-identity.txt
```

## Usage

The age recipients contained in all connected YubiKeys can be printed on
standard output:

```
$ age-plugin-yubikey --list
```

To encrypt files to these YubiKey recipients, ensure that `age-plugin-yubikey`
is accessible in your `PATH`, and then use the recipients with an age client as
normal (e.g. `rage -r age1yubikey1...`).

The output of the `--list` command can also be used directly to encrypt files to
all recipients (e.g. `age -R filename.txt`).

To decrypt files encrypted to a YubiKey identity, pass the identity file to the
age client as normal (e.g. `rage -d -i yubikey-identity.txt`).

## Advanced topics

### Agent support

`age-plugin-yubikey` does not provide or interact with an agent for decryption.
It does however attempt to preserve the PIN cache by not soft-resetting the
YubiKey after a decryption or read-only operation, which enables YubiKey
identities configured with a PIN policy of `once` to not prompt for the PIN on
every decryption. **This does not work for YubiKey 4 series.**

The session that corresponds to the `once` policy can be ended in several ways,
not all of which are necessarily intuitive:

- Unplugging the YubiKey (the obvious way).
- Using a different applet (e.g. FIDO2). This causes the PIV applet to be closed
  which clears its state.
  - This is why the YubiKey 4 series does not support PIN cache preservation:
    their serial can only be obtained by switching to the OTP applet.
- Generating a new age identity via `age-plugin-yubikey --generate` or the CLI
  interface. This is to avoid leaving the YubiKey authenticated with the
  management key.

If the current PIN UX proves to be insufficient, a decryption agent will most
likely be implemented as a separate age plugin that interacts with
[`yubikey-agent`](https://github.com/FiloSottile/yubikey-agent), enabling
YubiKeys to be used simultaneously with age and SSH.

### Manual setup and technical details

`age-plugin-yubikey` only officially supports the following YubiKey variants,
set up either via the text interface or the `--generate` flag:

- YubiKey 4 series
- YubiKey 5 series

NOTE: Nano and USB-C variants of the above are also supported. The pre-YK4
YubiKey NEO series is **NOT** supported. The blue "Security Key by Yubico" will
also not work (as it doesn't support PIV).

In practice, any PIV token with an ECDSA P-256 key and certificate in one of the
20 "retired" slots should work. You can list all age-compatible keys with:

```
$ age-plugin-yubikey --list-all
```

`age-plugin-yubikey` implements several automatic security management features:

- If it detects that the default PIN is being used, it will prompt the user to
  change the PIN. The PUK is then set to the same value as the PIN.
- If it detects that the default management key is being used, it generates a
  random management key and stores it in PIN-protected metadata.
  `age-plugin-yubikey` does not support custom management keys.

## License

Licensed under either of

 * Apache License, Version 2.0, ([LICENSE-APACHE](LICENSE-APACHE) or
   http://www.apache.org/licenses/LICENSE-2.0)
 * MIT license ([LICENSE-MIT](LICENSE-MIT) or http://opensource.org/licenses/MIT)

at your option.

### Contribution

Unless you explicitly state otherwise, any contribution intentionally
submitted for inclusion in the work by you, as defined in the Apache-2.0
license, shall be dual licensed as above, without any additional terms or
conditions.

