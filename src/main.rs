use age_plugin::run_state_machine;
use gumdrop::Options;
use std::io;

mod format;
mod p256;
mod plugin;

const RECIPIENT_PREFIX: &str = "age1yubikey";
const STANZA_TAG: &str = "piv-p256";

#[derive(Debug, Options)]
struct PluginOptions {
    #[options(help = "print help message")]
    help: bool,

    #[options(help = "run the given age plugin state machine", no_short)]
    age_plugin: Option<String>,
}

fn main() -> io::Result<()> {
    let opts = PluginOptions::parse_args_default_or_exit();

    if let Some(state_machine) = opts.age_plugin {
        // run_state_machine(
        //     &state_machine,
        //     || plugin::RecipientPlugin::default(),
        //     || todo!(),
        // )?;
        Ok(())
    } else {
        // TODO: Key generation
        Ok(())
    }
}
