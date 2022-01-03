use std::error::Error as StdError;
use std::fmt;
use std::ptr;

use core_foundation::{base::TCFType, string::CFString};
use security_framework_sys::base::{errSecSuccess, SecCopyErrorMessageString};

pub fn check_result(code: i32) -> Result<(), Error> {
    if code == errSecSuccess {
        Ok(())
    } else {
        Err(Error(code))
    }
}

#[derive(Debug)]
pub struct Error(i32);

impl StdError for Error {}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        unsafe {
            let error_message = SecCopyErrorMessageString(self.0, ptr::null_mut());
            if error_message.is_null() {
                write!(f, "Security error [{}]", self.0)
            } else {
                let error_message = CFString::wrap_under_create_rule(error_message).to_string();
                write!(f, "Security error [{}]: {}", self.0, error_message)
            }
        }
    }
}
