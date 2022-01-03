use core_foundation::{
    base::{CFGetTypeID, CFType, TCFType},
    boolean::CFBoolean,
    data::CFData,
    dictionary::CFDictionary,
    number::CFNumber,
    string::{CFString, CFStringRef},
};

use security_framework_sys::{
    item::{
        kSecClass, kSecClassGenericPassword, kSecMatchLimit, kSecReturnAttributes, kSecReturnData,
    },
    keychain_item::SecItemCopyMatching,
};

use crate::error::{check_result, Error};

// TODO: remove after update to security-framework 2.5.0
extern "C" {
    pub static kSecAttrAccount: CFStringRef;
    pub static kSecAttrService: CFStringRef;
    pub static kSecValueData: CFStringRef;
}

pub fn search(
    service: &str,
    account: Option<&str>,
) -> Result<CFDictionary<CFString, CFType>, Error> {
    unsafe {
        let mut query = query(service, account);

        query.push((
            CFString::wrap_under_get_rule(kSecReturnAttributes),
            CFBoolean::true_value().as_CFType(),
        ));

        query.push((
            CFString::wrap_under_get_rule(kSecReturnData),
            CFBoolean::true_value().as_CFType(),
        ));

        query.push((
            CFString::wrap_under_get_rule(kSecMatchLimit),
            CFNumber::from(1).as_CFType(),
        ));

        let query = CFDictionary::from_CFType_pairs(&query);

        let mut ret = std::ptr::null();
        check_result(SecItemCopyMatching(query.as_concrete_TypeRef(), &mut ret))?;

        Ok(CFDictionary::wrap_under_get_rule(ret as *mut _))
    }
}

pub fn query(service: &str, account: Option<&str>) -> Vec<(CFString, CFType)> {
    let mut query = vec![
        (
            unsafe { CFString::wrap_under_get_rule(kSecClass) },
            unsafe { CFString::wrap_under_get_rule(kSecClassGenericPassword).as_CFType() },
        ),
        (
            unsafe { CFString::wrap_under_get_rule(kSecAttrService) },
            CFString::from(service).as_CFType(),
        ),
    ];

    if let Some(account) = account {
        query.push((
            unsafe { CFString::wrap_under_get_rule(kSecAttrAccount) },
            CFString::from(account).as_CFType(),
        ));
    }

    query
}

pub fn find_string_value(
    dictionary: &CFDictionary<CFString, CFType>,
    key: &CFString,
) -> Option<String> {
    unsafe {
        let value = dictionary.find(key)?;

        match CFGetTypeID(value.as_CFTypeRef()) {
            cfstring if cfstring == CFString::type_id() => Some(format!(
                "{}",
                CFString::wrap_under_get_rule(value.as_CFTypeRef() as *const _)
            )),
            cfdata if cfdata == CFData::type_id() => {
                let buf = CFData::wrap_under_get_rule(value.as_CFTypeRef() as *const _);
                let mut vec = Vec::new();
                vec.extend_from_slice(buf.bytes());
                Some(format!("{}", String::from_utf8_lossy(&vec)))
            }
            _ => None,
        }
    }
}
