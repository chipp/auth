use core_foundation::{base::TCFType, data::CFData, dictionary::CFDictionary, string::CFString};
use rpassword::prompt_password;

use security_framework_sys::keychain_item::{SecItemAdd, SecItemDelete};

use crate::{
    error::check_result,
    keychain::{find_string_value, kSecValueData, query, search},
};

pub fn token(service: &str, token_name: &str) -> String {
    if let Some(token) = find_token_in_keychain(service, token_name) {
        token
    } else {
        request_token_from_user(service, token_name)
    }
}

fn find_token_in_keychain(service: &str, token_name: &str) -> Option<String> {
    unsafe {
        let result = search(service, Some(token_name)).ok()?;

        let value_data_key = CFString::wrap_under_get_rule(kSecValueData);
        let password = find_string_value(&result, &value_data_key)?;

        Some(password)
    }
}

fn request_token_from_user(service: &str, token_name: &str) -> String {
    let password = request_token(service, token_name);

    let mut query = query(service, Some(&token_name));
    query.push((
        unsafe { CFString::wrap_under_get_rule(kSecValueData) },
        CFData::from_buffer(password.as_bytes()).as_CFType(),
    ));

    let params = CFDictionary::from_CFType_pairs(&query);
    let mut ret = std::ptr::null();

    if let Err(error) = check_result(unsafe { SecItemAdd(params.as_concrete_TypeRef(), &mut ret) })
    {
        debug_assert!(true, "unable to save credentials to keychain: {}", error);
    }

    password
}

pub fn reset_token(service: &str, token_name: &str) {
    let query = query(service, Some(token_name));
    let params = CFDictionary::from_CFType_pairs(&query);

    if let Err(error) = check_result(unsafe { SecItemDelete(params.as_concrete_TypeRef()) }) {
        debug_assert!(true, "unable to save credentials to keychain: {}", error);
    }
}

fn request_token(service: &str, token_name: &str) -> String {
    prompt_password(&format!("Enter {} {}: ", service, token_name)).unwrap()
}
