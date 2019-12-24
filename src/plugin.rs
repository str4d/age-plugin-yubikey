use age_core::format::{FileKey, Stanza};
use age_plugin::recipient::{self, RecipientPluginV1};
use bech32::FromBase32;

use crate::{format, p256::PublicKey, RECIPIENT_PREFIX};

#[derive(Debug, Default)]
pub(crate) struct RecipientPlugin {
    recipients: Vec<PublicKey>,
}

impl RecipientPluginV1 for RecipientPlugin {
    fn add_recipients<'a, I: Iterator<Item = &'a str>>(
        &mut self,
        recipients: I,
    ) -> Result<(), Vec<recipient::Error>> {
        let errors: Vec<_> = recipients
            .enumerate()
            .filter_map(|(index, recipient)| {
                if let Some(pk) = bech32::decode(recipient)
                    .ok()
                    .and_then(|(hrp, data)| {
                        if hrp == RECIPIENT_PREFIX {
                            Some(data)
                        } else {
                            None
                        }
                    })
                    .and_then(|data| Vec::from_base32(&data).ok())
                    .and_then(|bytes| PublicKey::from_bytes(&bytes))
                {
                    self.recipients.push(pk);
                    None
                } else {
                    Some(recipient::Error::Recipient {
                        index,
                        message: "Invalid recipient".to_owned(),
                    })
                }
            })
            .collect();
        if errors.is_empty() {
            Ok(())
        } else {
            Err(errors)
        }
    }

    fn wrap_file_key(&mut self, file_key: &FileKey) -> Result<Vec<Stanza>, Vec<recipient::Error>> {
        Ok(self
            .recipients
            .iter()
            .map(|pk| format::RecipientLine::wrap_file_key(file_key, &pk).into())
            .collect())
    }
}
