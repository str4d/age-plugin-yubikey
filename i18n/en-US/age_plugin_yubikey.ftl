# Copyright 2022 Jack Grigg
#
# Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
# http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
# <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
# option. This file may not be copied, modified, or distributed
# except according to those terms.

### Localization for strings in age-plugin-yubikey

-age = age
-yubikey = YubiKey
-yubikeys = YubiKeys
-age-plugin-yubikey = age-plugin-yubikey
-pcscd = pcscd

## CLI commands and flags

-cmd-generate = --generate
-cmd-identity = --identity
-cmd-list     = --list
-cmd-list-all = --list-all

-flag-force  = --force
-flag-serial = --serial
-flag-slot   = --slot

## YubiKey metadata

pin-policy-always = Always (A PIN is required for every decryption, if set)
pin-policy-once   = Once   (A PIN is required once per session, if set)
pin-policy-never  = Never  (A PIN is NOT required to decrypt)

touch-policy-always = Always (A physical touch is required for every decryption)
touch-policy-cached = Cached (A physical touch is required for decryption, and is cached for 15 seconds)
touch-policy-never  = Never  (A physical touch is NOT required to decrypt)

unknown-policy = Unknown

yubikey-metadata =
    #       Serial: {$serial}, Slot: {$slot}
    #         Name: {$name}
    #      Created: {$created}
    #   PIN policy: {$pin_policy}
    # Touch policy: {$touch_policy}
yubikey-identity =
    {$yubikey_metadata}
    #    Recipient: {$recipient}
    {$identity}

## CLI setup via text interface

cli-setup-intro =
    ✨ Let's get your {-yubikey} set up for {-age}! ✨

    This tool can create a new {-age} identity in a free slot of your {-yubikey}.
    It will generate an identity file that you can use with an {-age} client,
    along with the corresponding recipient. You can also do this directly
    with:
    {"    "}{$generate_usage}

    If you are already using a {-yubikey} with {-age}, you can select an existing
    slot to recreate its corresponding identity file and recipient.

    When asked below to select an option, use the up/down arrow keys to
    make your choice, or press [Esc] or [q] to quit.

cli-setup-insert-yk           = ⏳ Please insert the {-yubikey} you want to set up.
cli-setup-yk-name             = {$yubikey_name} (Serial: {$yubikey_serial})
cli-setup-select-yk           = 🔑 Select a {-yubikey}
cli-setup-slot-usable         = Slot {$slot_index} ({$slot_name})
cli-setup-slot-unusable       = Slot {$slot_index} (Unusable)
cli-setup-slot-empty          = Slot {$slot_index} (Empty)
cli-setup-select-slot         = 🕳️  Select a slot for your {-age} identity
cli-setup-name-identity       = 📛 Name this identity
cli-setup-select-pin-policy   = 🔤 Select a PIN policy
cli-setup-select-touch-policy = 👆 Select a touch policy

cli-setup-generate-new = Generate new identity in slot {$slot_index}?
cli-setup-use-existing = Use existing identity in slot {$slot_index}?

cli-setup-identity-file-name   = 📝 File name to write this identity to
cli-setup-identity-file-exists = File exists. Overwrite it?

cli-setup-finished =
    ✅ Done! This {-yubikey} identity is ready to go.

    🔑 { $is_new ->
        [true] Here's your shiny new {-yubikey} recipient:
       *[false] Here's the corresponding {-yubikey} recipient:
    }
    {"  "}{$recipient}

    Here are some example things you can do with it:

    - Encrypt a file to this identity:
    {"  "}{$encrypt_usage}

    - Decrypt a file with this identity:
    {"  "}{$decrypt_usage}

    - Recreate the identity file:
    {"  "}{$identity_usage}

    - Recreate the recipient:
    {"  "}{$recipient_usage}

    💭 Remember: everything breaks, have a backup plan for when this {-yubikey} does.

## Programmatic usage

open-yk-with-serial    = ⏳ Please insert the {-yubikey} with serial {$yubikey_serial}.
open-yk-without-serial = ⏳ Please insert the {-yubikey}.
warn-yk-not-connected  = Ignoring {$yubikey_name}: not connected

print-recipient = Recipient: {$recipient}

printed-kind-identities = identities
printed-kind-recipients = recipients
printed-multiple = Generated {$kind} for {$count} slots. If you intended to select a slot, use {-flag-slot}.

## YubiKey management

mgr-enter-pin = Enter PIN for {-yubikey} with serial {$yubikey_serial} (default is {$default_pin})

mgr-change-default-pin =
    ✨ Your {-yubikey} is using the default PIN. Let's change it!
    ✨ We'll also set the PUK equal to the PIN.

    🔐 The PIN is up to 8 numbers, letters, or symbols. Not just numbers!
    ❌ Your keys will be lost if the PIN and PUK are locked after 3 incorrect tries.

mgr-enter-current-puk = Enter current PUK (default is {$default_puk})
mgr-choose-new-pin    = Choose a new PIN/PUK
mgr-repeat-new-pin    = Repeat the PIN/PUK
mgr-pin-mismatch      = PINs don't match

mgr-changing-mgmt-key =
    ✨ Your {-yubikey} is using the default management key.
    ✨ We'll migrate it to a PIN-protected management key.
mgr-changing-mgmt-key-error =
    An error occurred while setting the new management key.
    ⚠️ SAVE THIS MANAGEMENT KEY - YOU MAY NEED IT TO MANAGE YOUR {-yubikey}! ⚠️
    {"  "}{$management_key}
mgr-changing-mgmt-key-success = Success!

## Plugin usage

plugin-err-invalid-recipient = Invalid recipient
plugin-err-invalid-identity  = Invalid {-yubikey} stub
plugin-err-invalid-stanza    = Invalid {-yubikey} stanza
plugin-err-decryption-failed = Failed to decrypt {-yubikey} stanza

plugin-insert-yk            = Please insert {-yubikey} with serial {$yubikey_serial}
plugin-yk-is-plugged-in     = {-yubikey} is plugged in
plugin-skip-this-yk         = Skip this {-yubikey}
plugin-insert-yk-retry      = Could not open {-yubikey}. Please insert {-yubikey} with serial {$yubikey_serial}
plugin-err-yk-not-found     = Could not find {-yubikey} with serial {$yubikey_serial}
plugin-err-yk-opening       = Could not open {-yubikey} with serial {$yubikey_serial}
plugin-err-yk-timed-out     = Timed out while waiting for {-yubikey} with serial {$yubikey_serial} to be inserted
plugin-err-yk-stub-mismatch = A {-yubikey} stub did not match the {-yubikey}

plugin-err-yk-invalid-pin-policy = Certificate for {-yubikey} identity contains an invalid PIN policy

plugin-enter-pin            = Enter PIN for {-yubikey} with serial {$yubikey_serial}
plugin-err-accidental-touch = Did you touch the {-yubikey} by accident?
plugin-err-pin-too-short    = PIN was too short.
plugin-err-pin-too-long     = PIN was too long.
plugin-err-pin-required     = A PIN is required for {-yubikey} with serial {$yubikey_serial}

## Errors

err-custom-mgmt-key      = Custom unprotected management keys are not supported.
err-invalid-flag-command = Flag '{$flag}' cannot be used with '{$command}'.
err-invalid-flag-tui     = Flag '{$flag}' cannot be used with the interactive interface.
err-invalid-pin-length   = The PIN needs to be 1-8 characters.
err-invalid-pin-policy   = Invalid PIN policy '{$policy}' (expected [{$expected}]).
err-invalid-slot         = Invalid slot '{$slot}' (expected number between 1 and 20).
err-invalid-touch-policy = Invalid touch policy '{$policy}' (expected [{$expected}]).
err-io                   = Failed to set up {-yubikey}: {$err}
err-multiple-commands    = Only one of {-cmd-generate}, {-cmd-identity}, {-cmd-list}, {-cmd-list-all} can be specified.
err-multiple-yubikeys    = Multiple {-yubikeys} are plugged in. Use {-flag-serial} to select a single {-yubikey}.
err-no-empty-slots       = {-yubikey} with serial {$serial} has no empty slots.
err-no-matching-serial   = Could not find {-yubikey} with serial {$serial}.
err-slot-has-no-identity = Slot {$slot} does not contain an {-age} identity or compatible key.
err-slot-is-not-empty    = Slot {$slot} is not empty. Use {-flag-force} to overwrite the slot.
err-timed-out            = Timed out while waiting for a {-yubikey} to be inserted.
err-use-list-for-single  = Use {-cmd-list} to print the recipient for a single slot.

err-yk-no-service-macos = The Crypto Token Kit service is not running.
rec-yk-no-service-macos =
    You may need to restart it. See this Stack Exchange answer for more help:
    {"  "}{$url}

err-yk-no-service-pcscd = {-pcscd} is not running.
rec-yk-no-service-pcscd =
    If you are on Debian or Ubuntu, you can install it with:
    {"  "}{$apt}

err-yk-no-service-win = The Smart Cards for Windows service is not running.
rec-yk-no-service-win =
    See this troubleshooting guide for more help:
    {"  "}{$url}

err-yk-not-found         = Please insert the {-yubikey} you want to set up
err-yk-wrong-pin         = Invalid PIN ({$tries} tries remaining before it is blocked)
err-yk-general           = Error while communicating with {-yubikey}: {$err}
err-yk-general-cause     = Cause: {$inner_err}

err-ux-A = Did this not do what you expected? Could an error be more useful?
err-ux-B = Tell us
# Put (len(A) - len(B) - 46) spaces here.
err-ux-C = {"            "}
