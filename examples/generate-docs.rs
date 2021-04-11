use flate2::{write::GzEncoder, Compression};
use man::prelude::*;
use std::fs::{create_dir_all, File};
use std::io::prelude::*;

const MANPAGES_DIR: &str = "./target/manpages";

fn generate_manpage(page: String, name: &str) {
    let file = File::create(format!("{}/{}.1.gz", MANPAGES_DIR, name))
        .expect("Should be able to open file in target directory");
    let mut encoder = GzEncoder::new(file, Compression::best());
    encoder
        .write_all(page.as_bytes())
        .expect("Should be able to write to file in target directory");
}

fn main() {
    // Create the target directory if it does not exist.
    let _ = create_dir_all(MANPAGES_DIR);

    let builder = Manual::new("age-plugin-yubikey")
        .about("An age plugin adding support for YubiKeys and other PIV hardware tokens")
        .author(Author::new("Jack Grigg").email("thestr4d@gmail.com"))
        .flag(
            Flag::new()
                .short("-h")
                .long("--help")
                .help("Display help text and exit."),
        )
        .flag(
            Flag::new()
                .short("-V")
                .long("--version")
                .help("Display version info and exit."),
        )
        .flag(
            Flag::new()
                .short("-f")
                .long("--force")
                .help("Force --generate to overwrite a filled slot."),
        )
        .flag(
            Flag::new()
                .short("-g")
                .long("--generate")
                .help("Generate a new YubiKey identity."),
        )
        .flag(
            Flag::new()
                .short("-i")
                .long("--identity")
                .help("Print the identity stored in a YubiKey slot."),
        )
        .flag(
            Flag::new()
                .short("-l")
                .long("--list")
                .help("List all age identities in connected YubiKeys."),
        )
        .flag(
            Flag::new()
                .long("--list-all")
                .help("List all YubiKey keys that are compatible with age."),
        )
        .flag(
            Flag::new()
                .long("--name")
                .help("Name for the generated identity. Defaults to 'age identity HEX_TAG'."),
        )
        .flag(
            Flag::new()
                .long("--pin-policy")
                .help("One of [always, once, never]. Defaults to 'once'."),
        )
        .flag(
            Flag::new()
                .long("--serial")
                .help("Specify which YubiKey to use, if more than one is plugged in."),
        )
        .flag(
            Flag::new()
                .long("--slot")
                .help("Specify which slot to use. Defaults to first usable slot."),
        )
        .flag(
            Flag::new()
                .long("--touch-policy")
                .help("One of [always, cached, never]. Defaults to 'always'."),
        );
    let page = builder.render();

    generate_manpage(page, "age-plugin-yubikey");
}
