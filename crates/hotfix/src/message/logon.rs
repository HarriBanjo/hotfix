use crate::message::OutboundMessage;
use hotfix_message::message::Message;
use hotfix_message::session_fields::{
    ENCRYPT_METHOD, HEART_BT_INT, NEXT_EXPECTED_MSG_SEQ_NUM, RESET_SEQ_NUM_FLAG,
};
use hotfix_message::{Field, FieldType, Part, TagU32};
use tracing::warn;

#[derive(Clone, Debug)]
pub struct Logon {
    encrypt_method: EncryptMethod,
    heartbeat_interval: u64,
    reset_seq_num_flag: ResetSeqNumFlag,
    next_expected_msg_seq_num: Option<u64>,
    extra_fields: Vec<(u32, String)>,
}

pub enum ResetSeqNumConfig {
    Reset,
    NoReset(Option<u64>),
}

impl Logon {
    pub const MSG_TYPE: &str = "A";

    pub fn new(heartbeat_interval: u64, reset_config: ResetSeqNumConfig) -> Self {
        let (reset_seq_num_flag, next_expected_msg_seq_num) = match reset_config {
            ResetSeqNumConfig::Reset => (ResetSeqNumFlag::Yes, None),
            ResetSeqNumConfig::NoReset(next) => (ResetSeqNumFlag::No, next),
        };
        Self {
            encrypt_method: EncryptMethod::None,
            heartbeat_interval,
            reset_seq_num_flag,
            next_expected_msg_seq_num,
            extra_fields: Vec::new(),
        }
    }

    /// Append custom fields to the body of this Logon.
    ///
    /// Useful for supplying counterparty-specific authentication fields such
    /// as Username (553) and Password (554), or vendor-specific session
    /// tokens. Fields are written in order after the standard Logon fields.
    /// Tag values that are not valid `TagU32` (i.e. 0) are skipped with a
    /// warning.
    pub fn with_extra_fields(mut self, extra_fields: Vec<(u32, String)>) -> Self {
        self.extra_fields = extra_fields;
        self
    }
}

impl OutboundMessage for Logon {
    fn write(&self, msg: &mut Message) {
        msg.set(ENCRYPT_METHOD, self.encrypt_method);
        msg.set(HEART_BT_INT, self.heartbeat_interval);
        msg.set(RESET_SEQ_NUM_FLAG, self.reset_seq_num_flag);

        if let Some(next) = self.next_expected_msg_seq_num {
            msg.set(NEXT_EXPECTED_MSG_SEQ_NUM, next);
        }

        for (tag, value) in &self.extra_fields {
            match TagU32::new(*tag) {
                Some(tag) => msg
                    .get_field_map_mut()
                    .insert(Field::new(tag, value.as_bytes().to_vec())),
                None => warn!(tag, "skipping invalid Logon extra field tag"),
            }
        }
    }

    fn message_type(&self) -> &str {
        Self::MSG_TYPE
    }
}

#[derive(Debug, Copy, Clone, PartialEq, Eq, Hash, FieldType)]
pub enum EncryptMethod {
    /// Field variant '0'.
    #[hotfix(variant = "0")]
    None,

    /// Field variant '1'.
    #[hotfix(variant = "1")]
    Pkcs,

    /// Field variant '2'.
    #[hotfix(variant = "2")]
    Des,

    /// Field variant '3'.
    #[hotfix(variant = "3")]
    PkcsDes,

    /// Field variant '4'.
    #[hotfix(variant = "4")]
    PgpDes,

    /// Field variant '5'.
    #[hotfix(variant = "5")]
    PgpDesMd5,

    /// Field variant '6'.
    #[hotfix(variant = "6")]
    PemDesMd5,
}

#[derive(Debug, Copy, Clone, PartialEq, Eq, Hash, FieldType)]
pub enum ResetSeqNumFlag {
    /// Field variant 'Y'.
    #[hotfix(variant = "Y")]
    Yes,

    /// Field variant 'N'.
    #[hotfix(variant = "N")]
    No,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::message::generate_message;

    #[test]
    fn extra_fields_are_appended_to_logon_body() {
        let logon = Logon::new(30, ResetSeqNumConfig::Reset).with_extra_fields(vec![
            (553, "alice".to_string()),
            (554, "secret-token".to_string()),
        ]);

        let bytes = generate_message("FIX.4.4", "SENDER", "TARGET", 1, logon).unwrap();
        let wire = String::from_utf8_lossy(&bytes).replace('\x01', "|");

        assert!(wire.contains("|553=alice|"), "missing Username: {wire}");
        assert!(
            wire.contains("|554=secret-token|"),
            "missing Password: {wire}"
        );
        // Standard Logon fields still present:
        assert!(wire.contains("|98=0|"), "missing EncryptMethod: {wire}");
        assert!(wire.contains("|108=30|"), "missing HeartBtInt: {wire}");
        assert!(wire.contains("|141=Y|"), "missing ResetSeqNumFlag: {wire}");
    }

    #[test]
    fn invalid_extra_field_tag_is_skipped_silently() {
        let logon = Logon::new(30, ResetSeqNumConfig::Reset)
            .with_extra_fields(vec![(0, "should-be-skipped".to_string())]);
        let bytes = generate_message("FIX.4.4", "SENDER", "TARGET", 1, logon).unwrap();
        let wire = String::from_utf8_lossy(&bytes);
        assert!(!wire.contains("should-be-skipped"));
    }

    #[test]
    fn no_extra_fields_by_default() {
        let logon = Logon::new(30, ResetSeqNumConfig::Reset);
        let bytes = generate_message("FIX.4.4", "SENDER", "TARGET", 1, logon).unwrap();
        let wire = String::from_utf8_lossy(&bytes);
        assert!(!wire.contains("553="));
        assert!(!wire.contains("554="));
    }
}
