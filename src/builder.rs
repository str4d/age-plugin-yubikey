use dialoguer::Password;
use rand::{rngs::OsRng, RngCore};
use x509::RelativeDistinguishedName;
use yubikey::{
    certificate::Certificate,
    piv::{generate as yubikey_generate, AlgorithmId, RetiredSlotId, SlotId},
    PinPolicy, TouchPolicy, YubiKey,
};

use crate::{
    error::Error,
    fl,
    key::{self, SlotState, Stub},
    native::p256tag,
    util::{Metadata, POLICY_EXTENSION_OID},
    Recipient, BINARY_NAME,
};

pub(crate) const DEFAULT_PIN_POLICY: PinPolicy = PinPolicy::Once;
pub(crate) const DEFAULT_TOUCH_POLICY: TouchPolicy = TouchPolicy::Always;

pub(crate) struct IdentityBuilder {
    slot: Option<RetiredSlotId>,
    force: bool,
    name: Option<String>,
    pin_policy: Option<PinPolicy>,
    touch_policy: Option<TouchPolicy>,
}

impl IdentityBuilder {
    pub(crate) fn new(slot: Option<RetiredSlotId>) -> Self {
        IdentityBuilder {
            slot,
            name: None,
            pin_policy: None,
            touch_policy: None,
            force: false,
        }
    }

    pub(crate) fn with_name(mut self, name: Option<String>) -> Self {
        self.name = name;
        self
    }

    pub(crate) fn with_pin_policy(mut self, pin_policy: Option<PinPolicy>) -> Self {
        self.pin_policy = pin_policy;
        self
    }

    pub(crate) fn with_touch_policy(mut self, touch_policy: Option<TouchPolicy>) -> Self {
        self.touch_policy = touch_policy;
        self
    }

    pub(crate) fn force(mut self, force: bool) -> Self {
        self.force = force;
        self
    }

    pub(crate) fn build(self, yubikey: &mut YubiKey) -> Result<(Stub, Recipient, Metadata), Error> {
        let slot = match self.slot {
            Some(slot) => {
                if !self.force {
                    // Check that the slot is empty. A slot whose contents we can't parse
                    // counts as occupied: we don't know what is stored there, so we must
                    // not destroy it. We report that case the same way `--identity` and
                    // `--list` do, rather than as a bare "not empty", and let genuine
                    // failures to talk to the YubiKey surface as themselves.
                    match key::slot_state(yubikey, slot)? {
                        SlotState::Empty => (),
                        SlotState::Unusable => return Err(Error::SlotIsUnusable(slot)),
                        SlotState::Usable(..) => return Err(Error::SlotIsNotEmpty(slot)),
                    }
                }

                // Now either the slot is empty, or --force is specified.
                slot
            }
            None => {
                // Use the first empty slot. Slots we can't parse are skipped over rather
                // than selected, for the same reason as above.
                key::first_empty_slot(yubikey)
                    .ok_or_else(|| Error::NoEmptySlots(yubikey.serial()))?
            }
        };

        let pin_policy = self.pin_policy.unwrap_or(DEFAULT_PIN_POLICY);
        let touch_policy = self.touch_policy.unwrap_or(DEFAULT_TOUCH_POLICY);

        eprintln!("{}", fl!("builder-gen-key"));

        // No need to ask for users to enter their PIN if the PIN policy requires it,
        // because here we _always_ require them to enter their PIN in order to access the
        // protected management key (which is necessary in order to generate identities).
        key::manage(yubikey)?;

        // Generate a new key in the selected slot.
        let generated = yubikey_generate(
            yubikey,
            SlotId::Retired(slot),
            AlgorithmId::EccP256,
            pin_policy,
            touch_policy,
        )?;

        let recipient = Recipient::P256Tag(
            p256tag::Recipient::from_spki(&generated).expect("YubiKey generates a valid pubkey"),
        );
        let stub = Stub::new(yubikey.serial(), slot, &recipient);

        eprintln!();
        eprintln!("{}", fl!("builder-gen-cert"));

        // Pick a random serial for the new self-signed certificate.
        let mut serial = [0; 20];
        OsRng.fill_bytes(&mut serial);

        let name = self
            .name
            .unwrap_or(format!("age identity {}", hex::encode(stub.tag)));

        if let PinPolicy::Always = pin_policy {
            // We need to enter the PIN again.
            let pin = Password::new()
                .with_prompt(fl!(
                    "plugin-enter-pin",
                    yubikey_serial = yubikey.serial().to_string(),
                ))
                .report(true)
                .interact()?;
            yubikey.verify_pin(pin.as_bytes())?;
        }
        if let TouchPolicy::Never = touch_policy {
            // No need to touch YubiKey
        } else {
            eprintln!("{}", fl!("builder-touch-yk"));
        }

        let cert = Certificate::generate_self_signed(
            yubikey,
            SlotId::Retired(slot),
            serial,
            None,
            &[
                RelativeDistinguishedName::organization(BINARY_NAME),
                RelativeDistinguishedName::organizational_unit(env!("CARGO_PKG_VERSION")),
                RelativeDistinguishedName::common_name(&name),
            ],
            generated,
            &[x509::Extension::regular(
                POLICY_EXTENSION_OID,
                &[pin_policy.into(), touch_policy.into()],
            )],
        )?;

        let metadata = Metadata::extract(yubikey, slot, &cert, false).unwrap();

        Ok((
            Stub::new(yubikey.serial(), slot, &recipient),
            recipient,
            metadata,
        ))
    }
}
