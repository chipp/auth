use core_foundation::{base::TCFType, data::CFData, dictionary::CFDictionary, string::CFString};

use rpassword::prompt_password_stdout;

use security_framework_sys::base::errSecSuccess;
use security_framework_sys::keychain_item::{SecItemAdd, SecItemDelete};

use crate::keychain::{find_string_value, kSecAttrAccount, kSecValueData, query, search};

pub fn user_and_password(service: &str) -> (String, String) {
    if let Some(credentials) = find_credentials_in_keychain(service) {
        credentials
    } else {
        request_credentials_from_user(service)
    }
}

fn find_credentials_in_keychain(service: &str) -> Option<(String, String)> {
    unsafe {
        let result = search(service, None);

        let account_key = CFString::wrap_under_get_rule(kSecAttrAccount);
        let value_data_key = CFString::wrap_under_get_rule(kSecValueData);

        let username = find_string_value(&result, &account_key)?;
        let password = find_string_value(&result, &value_data_key)?;

        Some((username, password))
    }
}

fn request_credentials_from_user(service: &str) -> (String, String) {
    let username = request_username(service);
    let password = request_password(service);

    let mut query = query(service, Some(&username));
    query.push((
        unsafe { CFString::wrap_under_get_rule(kSecValueData) },
        CFData::from_buffer(password.as_bytes()).as_CFType(),
    ));

    let params = CFDictionary::from_CFType_pairs(&query);
    let mut ret = std::ptr::null();
    let status = unsafe { SecItemAdd(params.as_concrete_TypeRef(), &mut ret) };

    if status != errSecSuccess {
        panic!("unable to save credentials to keychain");
    }

    (username, password)
}

pub fn reset_user_and_pass(service: &str) {
    let query = query(service, None);
    let params = CFDictionary::from_CFType_pairs(&query);

    if unsafe { SecItemDelete(params.as_concrete_TypeRef()) } != errSecSuccess {
        panic!("unable to remove credentials from keychain");
    }
}

fn request_username(service: &str) -> String {
    use std::io;
    use std::io::prelude::*;
    print!("{} username: ", service);
    io::stdout().flush().unwrap();
    let mut username = String::default();
    io::stdin().read_line(&mut username).unwrap();
    username.trim().to_owned()
}

fn request_password(service: &str) -> String {
    prompt_password_stdout(&format!("{} password: ", service)).unwrap()
}
