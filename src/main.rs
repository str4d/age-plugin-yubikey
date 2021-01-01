use age_plugin::run_state_machine;
use gumdrop::Options;
use yubikey_piv::{
    certificate::PublicKeyInfo,
    key::{RetiredSlotId, SlotId},
    Key, Readers,
};

mod error;
mod p256;
mod plugin;
mod util;

use error::Error;

const PLUGIN_NAME: &str = "age-plugin-yubikey";
const RECIPIENT_PREFIX: &str = "age1yubikey";

const USABLE_SLOTS: [RetiredSlotId; 20] = [
    RetiredSlotId::R1,
    RetiredSlotId::R2,
    RetiredSlotId::R3,
    RetiredSlotId::R4,
    RetiredSlotId::R5,
    RetiredSlotId::R6,
    RetiredSlotId::R7,
    RetiredSlotId::R8,
    RetiredSlotId::R9,
    RetiredSlotId::R10,
    RetiredSlotId::R11,
    RetiredSlotId::R12,
    RetiredSlotId::R13,
    RetiredSlotId::R14,
    RetiredSlotId::R15,
    RetiredSlotId::R16,
    RetiredSlotId::R17,
    RetiredSlotId::R18,
    RetiredSlotId::R19,
    RetiredSlotId::R20,
];

#[derive(Debug, Options)]
struct PluginOptions {
    #[options(help = "Print this help message and exit.")]
    help: bool,

    #[options(
        help = "Run the given age plugin state machine. Internal use only.",
        meta = "STATE-MACHINE",
        no_short
    )]
    age_plugin: Option<String>,

    #[options(help = "Generate a new YubiKey identity.")]
    generate: bool,

    #[options(help = "Print the identity stored in a YubiKey slot.")]
    identity: bool,

    #[options(help = "List all age identities in connected YubiKeys.")]
    list: bool,

    #[options(help = "List all YubiKey keys that are compatible with age.", no_short)]
    list_all: bool,
}

fn list(all: bool) -> Result<(), Error> {
    let mut readers = Readers::open()?;

    for reader in readers.iter()? {
        let mut yubikey = reader.open()?;

        for key in Key::list(&mut yubikey)? {
            // We only use the retired slots.
            let slot = match key.slot() {
                SlotId::Retired(slot) => slot,
                _ => continue,
            };

            // Only P-256 keys are compatible with us.
            let recipient = match key.certificate().subject_pki() {
                PublicKeyInfo::EcP256(pubkey) => match p256::Recipient::from_pubkey(*pubkey) {
                    Some(recipient) => recipient,
                    None => continue,
                },
                _ => continue,
            };

            let ((name, pin_policy, touch_policy), created) =
                match x509_parser::parse_x509_certificate(key.certificate().as_ref())
                    .ok()
                    .and_then(|(_, cert)| {
                        util::extract_name_and_policies(&mut yubikey, &key, &cert, all)
                            .map(|res| (res, cert.validity().not_before.to_rfc2822()))
                    }) {
                    Some(res) => res,
                    None => continue,
                };

            println!(
                "#       Serial: {}, Slot: {}",
                yubikey.serial(),
                // Use 1-indexing in the UI for niceness
                USABLE_SLOTS.iter().position(|s| s == &slot).unwrap() + 1,
            );
            println!("#         Name: {}", name);
            println!("#      Created: {}", created);
            println!("#   PIN policy: {}", util::pin_policy_to_str(pin_policy));
            println!(
                "# Touch policy: {}",
                util::touch_policy_to_str(touch_policy)
            );
            println!("{}", recipient.to_string());
            println!();
        }
        println!();
    }

    Ok(())
}

fn main() -> Result<(), Error> {
    let opts = PluginOptions::parse_args_default_or_exit();

    if [opts.generate, opts.identity, opts.list, opts.list_all]
        .iter()
        .filter(|&&b| b)
        .count()
        > 1
    {
        return Err(Error::MultipleCommands);
    }

    if let Some(state_machine) = opts.age_plugin {
        run_state_machine(
            &state_machine,
            || plugin::RecipientPlugin::default(),
            || plugin::IdentityPlugin::default(),
        )?;
        Ok(())
    } else if opts.generate {
        todo!()
    } else if opts.identity {
        todo!()
    } else if opts.list {
        list(false)
    } else if opts.list_all {
        list(true)
    } else {
        // TODO: CLI identity generation
        Ok(())
    }
}
