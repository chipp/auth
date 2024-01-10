mod config;

use config::*;

use rpassword::prompt_password_stdout;
use security_framework::os::macos::keychain::SecKeychain;
use security_framework::os::macos::passwords::*;

pub fn token(server: &str, token_name: &str) -> String {
    let keychain = SecKeychain::default().unwrap();

    let token = match keychain.find_internet_password(
        server,
        None,
        token_name,
        "",
        None,
        SecProtocolType::Any,
        SecAuthenticationType::Any,
    ) {
        Ok((token, _)) => String::from_utf8(Vec::from(token.as_ref())).unwrap(),
        Err(_) => {
            let token = request_token(server, token_name);

            keychain
                .add_internet_password(
                    server,
                    None,
                    token_name,
                    "",
                    None,
                    SecProtocolType::HTTPS,
                    SecAuthenticationType::Any,
                    &token.as_bytes(),
                )
                .unwrap();

            token
        }
    };

    token
}

pub fn reset_token(server: &str, token_name: &str) {
    let keychain = SecKeychain::default().unwrap();

    if let Ok((_, item)) = keychain.find_internet_password(
        server,
        None,
        token_name,
        "",
        None,
        SecProtocolType::Any,
        SecAuthenticationType::Any,
    ) {
        item.delete()
    }
}

pub fn user_and_password(config_name: &str, server: &str) -> (String, String) {
    let config = load_config(config_name);

    let username = match config.as_ref().and_then(|config| config.get(server)) {
        Some(username) => username.clone(),
        None => {
            let username = request_username(server);

            let mut config = config.unwrap_or_default();
            config.insert(server.to_string(), username.clone());
            save_config(&config, config_name).unwrap();

            username
        }
    };

    let keychain = SecKeychain::default().unwrap();

    let password = match keychain.find_internet_password(
        server,
        None,
        &username,
        "",
        None,
        SecProtocolType::Any,
        SecAuthenticationType::Any,
    ) {
        Ok((password, _)) => String::from_utf8(Vec::from(password.as_ref())).unwrap(),
        Err(_) => {
            let token = request_password(server);

            keychain
                .add_internet_password(
                    server,
                    None,
                    &username,
                    "",
                    None,
                    SecProtocolType::HTTPS,
                    SecAuthenticationType::Any,
                    &token.as_bytes(),
                )
                .unwrap();

            token
        }
    };

    (username, password)
}

pub fn reset_user_and_pass(config_name: &str, server: &str) {
    let config = load_config(config_name);
    let username = match config.as_ref().and_then(|c| c.get(server)) {
        Some(it) => it,
        _ => return,
    };
    let keychain = SecKeychain::default().unwrap();

    if let Ok((_, item)) = keychain.find_internet_password(
        server,
        None,
        &username,
        "",
        None,
        SecProtocolType::Any,
        SecAuthenticationType::Any,
    ) {
        item.delete()
    }
}

fn request_token(server: &str, token_name: &str) -> String {
    prompt_password_stdout(&format!("Enter {} {}: ", server, token_name)).unwrap()
}

fn request_username(server: &str) -> String {
    use std::io;
    use std::io::prelude::*;
    print!("{} username: ", server);
    io::stdout().flush().unwrap();
    let mut username = String::default();
    io::stdin().read_line(&mut username).unwrap();
    username.trim().to_owned()
}

fn request_password(server: &str) -> String {
    prompt_password_stdout(&format!("{} password: ", server)).unwrap()
}
