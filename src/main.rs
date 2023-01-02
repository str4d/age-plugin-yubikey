#![forbid(unsafe_code)]

use std::fs::{File, OpenOptions};
use std::io::{self, Write};

use age_plugin::run_state_machine;
use dialoguer::{Confirm, Input, Select};
use gumdrop::Options;
use i18n_embed::{
    fluent::{fluent_language_loader, FluentLanguageLoader},
    DesktopLanguageRequester,
};
use lazy_static::lazy_static;
use rust_embed::RustEmbed;
use yubikey::{piv::RetiredSlotId, reader::Context, PinPolicy, Serial, TouchPolicy};

mod builder;
mod error;
mod format;
mod key;
mod p256;
mod plugin;
mod util;

use error::Error;

const PLUGIN_NAME: &str = "yubikey";
const BINARY_NAME: &str = "age-plugin-yubikey";
const RECIPIENT_PREFIX: &str = "age1yubikey";
const IDENTITY_PREFIX: &str = "age-plugin-yubikey-";
const STANZA_TAG: &str = "piv-p256";

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

#[derive(RustEmbed)]
#[folder = "i18n"]
struct Translations;

const TRANSLATIONS: Translations = Translations {};

lazy_static! {
    static ref LANGUAGE_LOADER: FluentLanguageLoader = fluent_language_loader!();
}

#[macro_export]
macro_rules! fl {
    ($message_id:literal) => {{
        i18n_embed_fl::fl!($crate::LANGUAGE_LOADER, $message_id)
    }};
    ($message_id:literal, $($kwarg:expr),* $(,)*) => {{
        i18n_embed_fl::fl!($crate::LANGUAGE_LOADER, $message_id, $($kwarg,)*)
    }};
}

#[derive(Debug, Options)]
struct PluginOptions {
    #[options(help = "Print this help message and exit.")]
    help: bool,

    #[options(help = "Print version info and exit.", short = "V")]
    version: bool,

    #[options(
        help = "Run the given age plugin state machine. Internal use only.",
        meta = "STATE-MACHINE",
        no_short
    )]
    age_plugin: Option<String>,

    #[options(help = "Force --generate to overwrite a filled slot.")]
    force: bool,

    #[options(help = "Generate a new YubiKey identity.")]
    generate: bool,

    #[options(help = "Print identities stored in connected YubiKeys.")]
    identity: bool,

    #[options(help = "List recipients for age identities in connected YubiKeys.")]
    list: bool,

    #[options(
        help = "List recipients for all YubiKey keys that are compatible with age.",
        no_short
    )]
    list_all: bool,

    #[options(
        help = "Name for the generated identity. Defaults to 'age identity HEX_TAG'.",
        no_short
    )]
    name: Option<String>,

    #[options(help = "One of [always, once, never]. Defaults to 'once'.", no_short)]
    pin_policy: Option<String>,

    #[options(
        help = "Specify which YubiKey to use, if more than one is plugged in.",
        no_short
    )]
    serial: Option<u32>,

    #[options(
        help = "Specify which slot to use. Defaults to first usable slot.",
        no_short
    )]
    slot: Option<u8>,

    #[options(
        help = "One of [always, cached, never]. Defaults to 'always'.",
        no_short
    )]
    touch_policy: Option<String>,
}

struct PluginFlags {
    serial: Option<Serial>,
    slot: Option<RetiredSlotId>,
    name: Option<String>,
    pin_policy: Option<PinPolicy>,
    touch_policy: Option<TouchPolicy>,
    force: bool,
}

impl TryFrom<PluginOptions> for PluginFlags {
    type Error = Error;

    fn try_from(opts: PluginOptions) -> Result<Self, Self::Error> {
        let serial = opts.serial.map(|s| s.into());
        let slot = opts.slot.map(util::ui_to_slot).transpose()?;
        let pin_policy = opts
            .pin_policy
            .map(util::pin_policy_from_string)
            .transpose()?;
        let touch_policy = opts
            .touch_policy
            .map(util::touch_policy_from_string)
            .transpose()?;

        Ok(PluginFlags {
            serial,
            slot,
            name: opts.name,
            pin_policy,
            touch_policy,
            force: opts.force,
        })
    }
}

fn generate(flags: PluginFlags) -> Result<(), Error> {
    let mut yubikey = key::open(flags.serial)?;

    let (stub, recipient, metadata) = builder::IdentityBuilder::new(flags.slot)
        .with_name(flags.name)
        .with_pin_policy(flags.pin_policy)
        .with_touch_policy(flags.touch_policy)
        .force(flags.force)
        .build(&mut yubikey)?;

    util::print_identity(stub, recipient, metadata);

    // We have written to the YubiKey, which means we've authenticated with the management
    // key. Out of an abundance of caution, we let the YubiKey be reset on disconnect,
    // which will clear its PIN and touch caches. This has as small negative UX effect,
    // but identity generation is a relatively infrequent occurrence, and users are more
    // likely to see their cached PINs reset due to switching applets (e.g. from PIV to
    // FIDO2).

    Ok(())
}

fn print_single(
    serial: Option<Serial>,
    slot: RetiredSlotId,
    printer: impl Fn(key::Stub, p256::Recipient, util::Metadata),
) -> Result<(), Error> {
    let mut yubikey = key::open(serial)?;

    let (key, slot, recipient) = key::list_compatible(&mut yubikey)?
        .find(|(_, s, _)| s == &slot)
        .ok_or(Error::SlotHasNoIdentity(slot))?;

    let stub = key::Stub::new(yubikey.serial(), slot, &recipient);
    let metadata = util::Metadata::extract(&mut yubikey, slot, key.certificate(), true).unwrap();

    printer(stub, recipient, metadata);

    key::disconnect_without_reset(yubikey);

    Ok(())
}

fn print_multiple(
    kind: &str,
    serial: Option<Serial>,
    all: bool,
    printer: impl Fn(key::Stub, p256::Recipient, util::Metadata),
) -> Result<(), Error> {
    let mut readers = Context::open()?;

    let mut printed = 0;
    for reader in readers.iter()?.filter(key::filter_connected) {
        let mut yubikey = key::open_connection(&reader)?;
        if let Some(serial) = serial {
            if yubikey.serial() != serial {
                continue;
            }
        }

        for (key, slot, recipient) in key::list_compatible(&mut yubikey)? {
            let stub = key::Stub::new(yubikey.serial(), slot, &recipient);
            let metadata = match util::Metadata::extract(&mut yubikey, slot, key.certificate(), all)
            {
                Some(res) => res,
                None => continue,
            };

            printer(stub, recipient, metadata);
            printed += 1;
            println!();
        }
        println!();

        key::disconnect_without_reset(yubikey);
    }
    if printed > 1 {
        eprintln!("{}", fl!("printed-multiple", kind = kind, count = printed));
    }

    Ok(())
}

fn print_details(
    kind: &str,
    flags: PluginFlags,
    all: bool,
    printer: impl Fn(key::Stub, p256::Recipient, util::Metadata),
) -> Result<(), Error> {
    if let Some(slot) = flags.slot {
        print_single(flags.serial, slot, printer)
    } else {
        print_multiple(kind, flags.serial, all, printer)
    }
}

fn identity(flags: PluginFlags) -> Result<(), Error> {
    if flags.force {
        return Err(Error::InvalidFlagCommand(
            "--force".into(),
            "--identity".into(),
        ));
    }
    print_details(
        &fl!("printed-kind-identities"),
        flags,
        false,
        util::print_identity,
    )
}

fn list(flags: PluginFlags, all: bool) -> Result<(), Error> {
    if all && flags.slot.is_some() {
        return Err(Error::UseListForSingleSlot);
    }
    if flags.force {
        return Err(Error::InvalidFlagCommand(
            "--force".into(),
            format!("--list{}", if all { "-all" } else { "" }),
        ));
    }

    print_details(
        &fl!("printed-kind-recipients"),
        flags,
        all,
        |_, recipient, metadata| {
            println!("{}", metadata);
            println!("{}", recipient);
        },
    )
}

fn main() -> Result<(), Error> {
    env_logger::builder()
        .format_timestamp(None)
        .filter_level(log::LevelFilter::Off)
        .parse_default_env()
        .init();

    let requested_languages = DesktopLanguageRequester::requested_languages();
    i18n_embed::select(&*LANGUAGE_LOADER, &TRANSLATIONS, &requested_languages).unwrap();
    // Unfortunately the common Windows terminals don't support Unicode Directionality
    // Isolation Marks, so we disable them for now.
    LANGUAGE_LOADER.set_use_isolating(false);

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
            plugin::RecipientPlugin::default,
            plugin::IdentityPlugin::default,
        )?;
        Ok(())
    } else if opts.version {
        println!("age-plugin-yubikey {}", env!("CARGO_PKG_VERSION"));
        Ok(())
    } else if opts.generate {
        generate(opts.try_into()?)
    } else if opts.identity {
        identity(opts.try_into()?)
    } else if opts.list {
        list(opts.try_into()?, false)
    } else if opts.list_all {
        list(opts.try_into()?, true)
    } else {
        if opts.force {
            return Err(Error::InvalidFlagTui("--force".into()));
        }
        let flags: PluginFlags = opts.try_into()?;

        eprintln!(
            "{}",
            fl!(
                "cli-setup-intro",
                generate_usage = "age-plugin-yubikey --generate",
            )
        );
        eprintln!();

        if !Context::open()?.iter()?.any(key::is_connected) {
            eprintln!("{}", fl!("cli-setup-insert-yk"));
        };
        let mut readers = key::wait_for_readers()?;

        // Filter out readers we can't connect to.
        let readers_list: Vec<_> = readers.iter()?.filter(key::filter_connected).collect();

        let reader_names = readers_list
            .iter()
            .map(|reader| {
                key::open_connection(reader).map(|yk| {
                    let name = fl!(
                        "cli-setup-yk-name",
                        yubikey_name = reader.name(),
                        yubikey_serial = yk.serial().to_string(),
                    );
                    key::disconnect_without_reset(yk);
                    name
                })
            })
            .collect::<Result<Vec<_>, _>>()?;
        let mut yubikey = match Select::new()
            .with_prompt(fl!("cli-setup-select-yk"))
            .items(&reader_names)
            .default(0)
            .report(true)
            .interact_opt()?
        {
            Some(yk) => readers_list[yk].open()?,
            None => return Ok(()),
        };

        let keys = key::list_slots(&mut yubikey)?.collect::<Vec<_>>();

        // Identify slots that we can't allow the user to select.
        let slot_details: Vec<_> = USABLE_SLOTS
            .iter()
            .map(|&slot| {
                keys.iter()
                    .find(|(_, s, _)| s == &slot)
                    .map(|(key, _, recipient)| {
                        recipient.as_ref().map(|_| {
                            // Cache the details we need to display to the user.
                            let (_, cert) =
                                x509_parser::parse_x509_certificate(key.certificate().as_ref())
                                    .unwrap();
                            let (name, _) = util::extract_name(&cert, true).unwrap();
                            let created = cert
                                .validity()
                                .not_before
                                .to_rfc2822()
                                .unwrap_or_else(|e| format!("Invalid date: {}", e));

                            format!("{}, created: {}", name, created)
                        })
                    })
            })
            .collect();

        let slots: Vec<_> = slot_details
            .iter()
            .enumerate()
            .map(|(i, occupied)| {
                // Use 1-indexing in the UI for niceness
                let i = i + 1;

                match occupied {
                    Some(Some(name)) => fl!(
                        "cli-setup-slot-usable",
                        slot_index = i,
                        slot_name = name.as_str(),
                    ),
                    Some(None) => fl!("cli-setup-slot-unusable", slot_index = i),
                    None => fl!("cli-setup-slot-empty", slot_index = i),
                }
            })
            .collect();

        let ((stub, recipient, metadata), is_new) = {
            let (slot_index, slot) = loop {
                match Select::new()
                    .with_prompt(fl!("cli-setup-select-slot"))
                    .items(&slots)
                    .default(0)
                    .report(true)
                    .interact_opt()?
                {
                    Some(slot) => {
                        if let Some(None) = slot_details[slot] {
                        } else {
                            break (slot + 1, USABLE_SLOTS[slot]);
                        }
                    }
                    None => return Ok(()),
                }
            };

            if let Some((key, _, recipient)) = keys.into_iter().find(|(_, s, _)| s == &slot) {
                let recipient = recipient.expect("We checked this above");

                if Confirm::new()
                    .with_prompt(fl!("cli-setup-use-existing", slot_index = slot_index))
                    .report(true)
                    .interact()?
                {
                    let stub = key::Stub::new(yubikey.serial(), slot, &recipient);
                    let metadata =
                        util::Metadata::extract(&mut yubikey, slot, key.certificate(), true)
                            .unwrap();

                    key::disconnect_without_reset(yubikey);
                    ((stub, recipient, metadata), false)
                } else {
                    key::disconnect_without_reset(yubikey);
                    return Ok(());
                }
            } else {
                let name = Input::<String>::new()
                    .with_prompt(format!(
                        "{} [{}]",
                        fl!("cli-setup-name-identity"),
                        flags.name.as_deref().unwrap_or("age identity TAG_HEX")
                    ))
                    .allow_empty(true)
                    .report(true)
                    .interact_text()?;

                let pin_policy = match Select::new()
                    .with_prompt(fl!("cli-setup-select-pin-policy"))
                    .items(&[
                        fl!("pin-policy-always"),
                        fl!("pin-policy-once"),
                        fl!("pin-policy-never"),
                    ])
                    .default(
                        [PinPolicy::Always, PinPolicy::Once, PinPolicy::Never]
                            .iter()
                            .position(|p| {
                                p == &flags.pin_policy.unwrap_or(builder::DEFAULT_PIN_POLICY)
                            })
                            .unwrap(),
                    )
                    .report(true)
                    .interact_opt()?
                {
                    Some(0) => PinPolicy::Always,
                    Some(1) => PinPolicy::Once,
                    Some(2) => PinPolicy::Never,
                    Some(_) => unreachable!(),
                    None => return Ok(()),
                };

                let touch_policy = match Select::new()
                    .with_prompt(fl!("cli-setup-select-touch-policy"))
                    .items(&[
                        fl!("touch-policy-always"),
                        fl!("touch-policy-cached"),
                        fl!("touch-policy-never"),
                    ])
                    .default(
                        [TouchPolicy::Always, TouchPolicy::Cached, TouchPolicy::Never]
                            .iter()
                            .position(|p| {
                                p == &flags.touch_policy.unwrap_or(builder::DEFAULT_TOUCH_POLICY)
                            })
                            .unwrap(),
                    )
                    .report(true)
                    .interact_opt()?
                {
                    Some(0) => TouchPolicy::Always,
                    Some(1) => TouchPolicy::Cached,
                    Some(2) => TouchPolicy::Never,
                    Some(_) => unreachable!(),
                    None => return Ok(()),
                };

                if Confirm::new()
                    .with_prompt(fl!("cli-setup-generate-new", slot_index = slot_index))
                    .report(true)
                    .interact()?
                {
                    eprintln!();
                    (
                        builder::IdentityBuilder::new(Some(slot))
                            .with_name(match name {
                                s if s.is_empty() => flags.name,
                                s => Some(s),
                            })
                            .with_pin_policy(Some(pin_policy))
                            .with_touch_policy(Some(touch_policy))
                            .build(&mut yubikey)?,
                        true,
                    )
                } else {
                    key::disconnect_without_reset(yubikey);
                    return Ok(());
                }
            }
        };

        eprintln!();
        let file_name = Input::<String>::new()
            .with_prompt(fl!("cli-setup-identity-file-name"))
            .default(format!(
                "age-yubikey-identity-{}.txt",
                hex::encode(stub.tag)
            ))
            .report(true)
            .interact_text()?;

        let mut file = match OpenOptions::new()
            .create_new(true)
            .write(true)
            .open(&file_name)
        {
            Ok(file) => file,
            Err(e) if e.kind() == io::ErrorKind::AlreadyExists => {
                if Confirm::new()
                    .with_prompt(fl!("cli-setup-identity-file-exists"))
                    .report(true)
                    .interact()?
                {
                    File::create(&file_name)?
                } else {
                    return Ok(());
                }
            }
            Err(e) => return Err(e.into()),
        };

        writeln!(
            file,
            "{}",
            fl!(
                "yubikey-identity",
                yubikey_metadata = metadata.to_string(),
                recipient = recipient.to_string(),
                identity = stub.to_string(),
            )
        )?;
        file.sync_data()?;

        // If `rage` binary is installed, use it in examples. Otherwise default to `age`.
        let age_binary = which::which("rage").map(|_| "rage").unwrap_or("age");

        let encrypt_usage = format!(
            "$ cat foo.txt | {} -r {} -o foo.txt.age",
            age_binary, recipient
        );
        let decrypt_usage = format!(
            "$ cat foo.txt.age | {} -d -i {} > foo.txt",
            age_binary, file_name
        );
        let identity_usage = format!(
            "$ age-plugin-yubikey -i --serial {} --slot {} > {}",
            stub.serial,
            util::slot_to_ui(&stub.slot),
            file_name,
        );
        let recipient_usage = format!(
            "$ age-plugin-yubikey -l --serial {} --slot {}",
            stub.serial,
            util::slot_to_ui(&stub.slot),
        );

        eprintln!();
        eprintln!(
            "{}",
            fl!(
                "cli-setup-finished",
                is_new = if is_new { "true" } else { "false" },
                recipient = recipient.to_string(),
                encrypt_usage = encrypt_usage,
                decrypt_usage = decrypt_usage,
                identity_usage = identity_usage,
                recipient_usage = recipient_usage,
            )
        );

        Ok(())
    }
}
