use serde::{Deserialize, Serialize};
use strum_macros::{Display, EnumString};

pub trait ErrorType {
    fn is_biz_error(&self) -> bool;
}

impl ErrorType for anyhow::Error {
    fn is_biz_error(&self) -> bool {
        let err_str = self.to_string();
        serde_json::from_str::<ErrorResponse>(&err_str).is_ok()
    }
}

#[repr(u32)]
#[derive(Debug, Clone, Copy, EnumString, Display, Serialize)]
pub enum Error {
    InternalError = 1000,
    ParamsInvalid = 1001,
    RepeatedNonce = 1002,
    SigExpired = 1003,
    AttestationVerifyFailed = 1004,
    WalletIsLocked = 1005,
    AssertionVerifyFailed = 1006,
    PwdSigVerifyFailed = 1007,
    KMSEncryptFailed = 1008,
    KMSDecryptFailed = 1009,
    PasswordDifferentWithMasterKey = 1010,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ErrorResponse {
    code: u32,
    msg: String,
}

impl Error {
    #[inline]
    pub fn code(self) -> u32 {
        self as u32
    }

    #[inline]
    pub fn message(self) -> String {
        self.to_string()
    }

    pub fn to_response(self) -> ErrorResponse {
        ErrorResponse {
            code: self.code(),
            msg: self.message(),
        }
    }

    pub fn to_json(self) -> String {
        serde_json::to_string(&self.to_response()).unwrap()
    }
}
