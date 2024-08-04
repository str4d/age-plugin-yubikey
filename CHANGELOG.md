# Changelog
All notable changes to this crate will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to Rust's notion of
[Semantic Versioning](https://semver.org/spec/v2.0.0.html). All versions prior
to 0.3.0 are beta releases.

## [Unreleased]

## [0.5.0] - 2024-08-04
### Fixed
- `age-plugin-yubikey` can now be compiled with Rust 1.80 and above.

### Changed
- MSRV is now 1.67.0.

## [0.4.0] - 2023-04-09
### Changed
- MSRV is now 1.65.0.
- The YubiKey PIV PIN and touch caches are now preserved across processes in
  most cases. See [README.md](README.md#agent-support) for exceptions. This has
  several usability effects (not applicable to YubiKey 4 series):
  - If a YubiKey's PIN is cached by an agent like `yubikey-agent`, and then
    `age-plugin-yubikey` is run (either directly or as a plugin), the agent
    won't request a PIN entry on its next use.
  - If a YubiKey's PIN was requested by either a previous invocation of
    `age-plugin-yubikey` or an agent like `yubikey-agent`, subsequent calls to
    `age-plugin-yubikey` won't request a PIN entry to decrypt a file with an
    identity that has a PIN policy of `once`.

### Fixed
- Identities can now be generated with a PIN policy of "always" (in previous
  versions of `age-plugin-yubikey` this would cause an error).

## [0.3.3] - 2023-02-11
### Fixed
- When `age-plugin-yubikey` assists the user in changing their PIN from the
  default PIN, it no longer tells the user that PINs shorter than 6 characters
  are allowed, and instead loops until the user enters a PIN of valid length.
  It also now prevents the user from setting their PIN to the default PIN, to
  avoid creating a cycle.
- More kinds of SmartCard readers are ignored when they have no SmartCard
  inserted.

## [0.3.2] - 2023-01-01
### Changed
- The "sharing violation" logic now also sends SIGHUP to any `yubikey-agent`
  that is running, to have them release any YubiKey locks they are holding.

### Fixed
- The "sharing violation" logic now runs during plugin mode as intended. In the
  previous release it only ran during direct `age-plugin-yubikey` usage.

## [0.3.1] - 2022-12-30
### Changed
- If a "sharing violation" error is encountered while opening a connection to a
  YubiKey, and `scdaemon` is running (which can hold exclusive access to a
  YubiKey indefinitely), `age-plugin-yubikey` now attempts to stop `scdaemon` by
  interrupting it (or killing it on Windows), and then tries again to open the
  connection.
- Several error messages were enhanced with guidance on how to resolve their
  respective issue.

## [0.3.0] - 2022-05-02
First non-beta release!

### Changed
- MSRV is now 1.56.0.
- During decryption, when asked to insert a YubiKey, you can now choose to skip
  it, allowing the client to move on to the next identity instead of returning
  an error.
- Certain kinds of PIN invalidity will now cause the plugin to re-request the
  PIN instead of aborting: if the PIN is too short or too long, or if the user
  touched the YubiKey early and "typed" an OTP.

### Fixed
- The "default" identity (provided by clients that invoke `age-plugin-yubikey`
  using `-j yubikey`) previously caused a panic. It is now correctly treated as
  an invalid identity (because this plugin does not support default identities).

## [0.2.0] - 2021-11-22
### Fixed
- Attempts-before-blocked counter is now returned as part of the invalid PIN
  error string.
- PIN is no longer requested when fetching the recipient for a slot, or when
  decrypting with a slot that has a PIN policy of Never.
- Migrated to `yubikey 0.5` to fix `cargo install age-plugin-yubikey` error
  (caused by the `yubikey-piv` crate being yanked after it was renamed).

## [0.1.0] - 2021-05-02

Initial beta release.
