use age_core::format::{FileKey, Stanza};
use age_plugin::{
    identity::{self, Callbacks, IdentityPluginV1},
    recipient::{self, RecipientPluginV1},
};
use std::collections::HashMap;
use std::io;

#[derive(Debug, Default)]
pub(crate) struct RecipientPlugin {}

impl RecipientPluginV1 for RecipientPlugin {
    fn add_recipients<'a, I: Iterator<Item = &'a str>>(
        &mut self,
        recipients: I,
    ) -> Result<(), Vec<recipient::Error>> {
        todo!()
    }

    fn wrap_file_key(&mut self, file_key: &FileKey) -> Result<Vec<Stanza>, Vec<recipient::Error>> {
        todo!()
    }
}

#[derive(Debug, Default)]
pub(crate) struct IdentityPlugin {}

impl IdentityPluginV1 for IdentityPlugin {
    fn add_identities<'a, I: Iterator<Item = &'a str>>(
        &mut self,
        identities: I,
    ) -> Result<(), Vec<identity::Error>> {
        todo!()
    }

    fn unwrap_file_keys(
        &mut self,
        files: Vec<Vec<Stanza>>,
        mut callbacks: impl Callbacks,
    ) -> io::Result<HashMap<usize, Result<FileKey, Vec<identity::Error>>>> {
        todo!()
    }
}
