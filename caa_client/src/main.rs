#![crate_type = "bin"]

use std::collections::HashMap;
use std::error::Error;
use std::io::{Read, Write};
use std::net::TcpStream;
use dryoc::constants::CRYPTO_SECRETBOX_KEYBYTES;
use dryoc::dryocbox::{NewByteArray};
use dryoc::dryocsecretbox::{Key};
use dryoc::pwhash::{Config, PwHash, Salt, VecPwHash};
use dryoc::sign::{PublicKey, SecretKey, SigningKeyPair};
use dryoc::types::StackByteArray;
use log::{error, info};
use read_input::InputBuild;
use read_input::prelude::input;
use sharks::Share;
use simple_logger::SimpleLogger;
use caa_crypto::caa_crypto::{decrypt, decrypt_file, derive_sub_key, encrypt, encrypt_file, generate_company_shares, generate_keypair, recover_company_master_key, recover_encryption_key, sign_message};
use caa_lib::caa_lib::{AuthParams, ClientCompany, Command, EncryptedKPNonce, FileAdd, FileNameList, FileParams, LoginParams, Message, ObfuscatedShare, retrieve_from_buffer, Sequence, ServerCompany, store_in_buffer};
use caa_lib::caa_lib::Sequence::{END, ONE, THREE};

// TODO: Add a revoke user function
// TODO: Clean up the code
// TODO: Factorize the code

fn main() {
    SimpleLogger::new().env().init().unwrap();

    static HOST_ADDRESS: &str = "localhost";
    static HOST_PORT: &str = "3333";

    println!("*******************************************");
    println!("Welcome to the CAA project client App !");
    println!("Connecting to the server ...");
    println!("*******************************************");

    match TcpStream::connect(format!("{}:{}", HOST_ADDRESS, HOST_PORT)) {
        Ok(mut stream) => {
            info!("Successfully connected to server in port {}", HOST_PORT);

            let mut receiver = [0u8; 4096];
            let mut sender = [0u8; 4096];
            let mut company = ClientCompany::new(vec![], 0);

            loop {
                let client_request = ask_user(&mut company);

                match client_request {
                    Ok(request) => {
                        //println!("To Server: {:?}", &req);
                        match store_in_buffer(&request, &mut sender) {
                            Ok(_) => {
                                stream.write(&sender[..]).unwrap();
                            }
                            Err(error) => error!("Error: {}", error)
                        }

                    }
                    Err(_) => {
                        info!("Connection closed");
                        drop(move || stream);
                        return;
                    }
                }

                // Wait for server response
                'inner: while match stream.read(&mut receiver) {
                    Ok(size) => {

                        // Close connection if server sends empty data
                        if size == 0 {
                            info!("Size 0");
                            drop(stream);
                            return;
                        }

                        // Deserialize server response
                        match retrieve_from_buffer::<Message>(&receiver) {
                            Ok(server_response) => {
                                match process_server_message(server_response, &mut company) {
                                    Ok(client_response) => {

                                        match client_response.command {
                                            Command::Bye => break 'inner,
                                            _ => {
                                                // println!("To Server: {:?}", &client_response);
                                                match store_in_buffer(&client_response, &mut sender) {
                                                    Ok(_) => {
                                                        stream.write(&sender[..]).unwrap();
                                                    },
                                                    Err(error) => error!("Error: {}", error)
                                                }

                                            }
                                        }
                                    }
                                    Err(error) => error!("Error: {}", error)
                                }
                            }
                            Err(error) => error!("Error: {}", error)
                        }
                        true
                    }
                    Err(error) => { error!("Failed to receive data: {}", error); false }
                } {}
            }
        }
        Err(e) => error!("Failed to connect: {}", e)
    }
    info!("Terminated.");
}

fn ask_user(company: &mut ClientCompany) -> Result<Message, Box<dyn Error>> {
    println!("\n*******************************************");
    println!("\n0. Exit");
    if company.token.clone().is_none() {
        println!("1. I want to register");
        println!("2. Log me please");
    }
    if !company.token.clone().is_none() {
        println!("3. Show me your list!");
        println!("4. Mais bordel ajoute mon fichier!!\n");
    }
    println!("*******************************************\n");

    match input::<u8>().msg("What do you wish to do ? ").get() {
        1 => register(company),
        2 => {
            company.name = Vec::from(input::<String>().msg("Enter your company name: ").get());
            Ok(Message::new(company.name.clone(), Command::Login, ONE, Some(company.name.clone()), None))
        }
        3 => {
            Ok(Message::new(company.name.clone(), Command::List, ONE, None, company.token.clone()))
        }
        4 => {
            Ok(Message::new(company.name.clone(), Command::AddFile, ONE, None, company.token.clone()))
        }
        _ => {
            Ok(Message::new(company.name.clone(), Command::Bye, ONE, None, company.token.clone()))
        }
    }
}

fn process_server_message(message: Message, company: &mut ClientCompany) -> Result<Message, Box<dyn Error>> {

    match message.command {
        Command::Login => login_server(message, company),
        Command::Register => {
            match message.sequence {
                Sequence::TWO => {
                    Ok(Message::new(company.name.clone(), Command::Login, ONE, Some(company.name.clone()), None))
                }
                _ => Err("Error: Wrong sequence".into())
            }
        }
        Command::Auth => auth_server(message, company),
        Command::List => list_server(message, company),
        Command::File => file_server(message, company),
        Command::AddFile => add_file_server(message, company),
            Command::Bye => Ok(message),
        _ => Err("Not implemented".into())
    }
}

/// Manages auth request to the server
///
/// # Arguments
///
/// * `message` - A message sent by the server
/// * `company` - A mutable reference to the company
///
/// # Returns
///
/// * `Result<Message, Box<dyn Error>>` - A result containing a message to send to the server
///
fn auth_server(message: Message, company: &mut ClientCompany) -> Result<Message, Box<dyn Error>> {
    match message.sequence {
        Sequence::TWO => {

            // Retrieve AuthParams
            let binding = message.body.unwrap();
            let auth_params = retrieve_from_buffer::<AuthParams>(&binding)?;

            company.challenge = Some(auth_params.challenge);

            // Decrypt private key
            let encrypted_secret_key = decrypt(
                &company.master_key.as_ref().unwrap(),
                &auth_params.signing_pair.nonce,
                &auth_params.signing_pair.encrypted_secret_key,
            )?;

            // Convert private key vector to SigningKeyPair
            let mut retrieved_secret_key: StackByteArray<64> = StackByteArray::new();
            retrieved_secret_key.copy_from_slice(&encrypted_secret_key);

            let mut secretk = SecretKey::new();
            secretk.copy_from_slice(&retrieved_secret_key);
            let pair: SigningKeyPair<PublicKey, SecretKey> = SigningKeyPair::from_secret_key(secretk);

            // Sign challenge
            let signed_challenge = sign_message(&pair, &company.challenge.as_ref().unwrap())?;
            let mut sender = [0 as u8; 1024];
            store_in_buffer(&signed_challenge, &mut sender)?;

            Ok(Message::new(
                company.name.clone(),
                Command::Auth,
                THREE,
                Some(company.name.clone()),
                Some(sender.to_vec()),
            ))
        }
        END => {
            // We got the token, we can store it
            company.token = message.token;

            Ok(Message::new(company.name.clone(), Command::Auth, END, Some(company.name.clone()),
                None))
        }
        _ => Ok(Message::new(company.name.clone(), Command::Auth, END, Some(company.name.clone()), None))
    }
}

/// Manages register request to the server
///
/// # Arguments
///
/// * `message` - A message sent by the server
/// * `company` - A mutable reference to the company
///
/// # Returns
///
/// * `Result<Message, Box<dyn Error>>` - A result containing a message to send to the server
///
fn register(company: &mut ClientCompany) -> Result<Message, Box<dyn Error>> {

    print_header("Register");

    // Generate signing key pair
    let company_kp = generate_keypair();

    // Generate shamir_key
    let company_master_key = Key::gen();
    let company_encryption_key = Key::gen();
    let encrypted_company_enc_k = encrypt(&company_master_key, &company_encryption_key.to_vec());

    // Encrypt secret key
    let data = company_kp.secret_key.clone().to_vec();
    let (nonce, secret_box) = encrypt(&company_master_key, &data);


    // Generate encrypted keypair
    let company_enc_kp = EncryptedKPNonce {
        public_key: company_kp.public_key.clone(),
        encrypted_secret_key: secret_box.to_vec(),
        nonce,
    };

    // Ask company name
    company.name = Vec::from(input::<String>().msg("Enter your company name: ").get());

    // Ask threshold
    let _threshold = input::<u8>().msg("Enter your threshold: ").get();

    // Ask number of shares
    let _number_of_shares = input::<usize>().msg("Enter the number of shares: ").get();

    // Generate obfuscated shares
    let shares_bytes = generate_company_shares(_threshold.clone(), _number_of_shares.clone(), &company_master_key.to_vec());

    let mut obfuscated_shares = HashMap::new();

    for i in 0.._number_of_shares {

        // Ask user input
        let username = input::<String>().msg("Enter the username: ").get();
        let password = Vec::from(input::<String>().msg("Enter the password: ").get());

        // Generate a random salt
        let mut salt = Salt::default();
        salt.resize(dryoc::constants::CRYPTO_PWHASH_SALTBYTES, 0);
        dryoc::rng::copy_randombytes(&mut salt);

        // Generate a hash
        let pwhash: VecPwHash = PwHash::hash_with_salt(
            &password,
            salt,
            Config::default().with_hash_length(32),
        ).expect("unable to hash password with salt and custom config");

        let (hash, salt, _config) = pwhash.into_parts();
        let mut hash_key: StackByteArray<CRYPTO_SECRETBOX_KEYBYTES> = StackByteArray::new();
        hash_key.copy_from_slice(&*hash);

        // Encrypt share
        let nonce_box = encrypt(&hash_key, &shares_bytes[i]);

        let obfuscated_share = ObfuscatedShare {
            nonce: nonce_box.0.clone(),
            salt,
            secret_box: nonce_box.1.clone(),
        };

        obfuscated_shares.insert(Vec::from(username), obfuscated_share);
    }

    let mut sender = [0 as u8; 2048];

    let s_company = ServerCompany {
        name: company.name.clone(),
        threshold: _threshold,
        shares: obfuscated_shares,
        file_name_list: HashMap::new(),
        file_list: HashMap::new(),
        encrypted_signing_pair: company_enc_kp,
        encrypted_encryption_key: Option::from(encrypted_company_enc_k),
        token: None,
        challenge: None,
        counter: 0,
    };

    store_in_buffer(&s_company, &mut sender[..])?;

    Ok(Message::new(company.name.clone(), Command::Register, ONE, Some(sender.to_vec()), None))
}

/// Manages login request to the server
///
/// # Arguments
///
/// * `message` - A message sent by the server
/// * `company` - A mutable reference to the company
///
/// # Returns
///
/// * `Result<Message, Box<dyn Error>>` - A result containing a message to send to the server
///
fn login_server(message: Message, company: &mut ClientCompany) -> Result<Message, Box<dyn Error>> {

    print_header("Login");

    // Retrieve LoginParams
    let binding = message.body.unwrap();
    let login_params = retrieve_from_buffer::<LoginParams>(&binding)?;

    // Get threshold
    company.threshold = login_params.threshold;

    let mut retrieved_shares_bytes = Vec::new();

    // Ask for username and password, and decrypt associated share
    for _i in 0..company.threshold {

        // Ask username and password
        let username = Vec::from(input::<String>().msg("What is the username ? ").get());
        let password = Vec::from(input::<String>().msg("What is the password ? ").get());

        let obfuscated_share = login_params.shares.get(&username).unwrap();

        // Hash password
        let pwhash: VecPwHash = PwHash::hash_with_salt(
            &password,
            obfuscated_share.salt.clone(),
            Config::default().with_hash_length(32),
        )?;

        // Convert hash to key
        let (hash, _salt, _config) = pwhash.into_parts();
        let mut hash_key: StackByteArray<CRYPTO_SECRETBOX_KEYBYTES> = StackByteArray::new();
        hash_key.copy_from_slice(&*hash);

        // Decrypt share
        let retrieved_share = decrypt(&hash_key, &obfuscated_share.nonce,
                                      &obfuscated_share.secret_box.to_vec(),
        )?;

        retrieved_shares_bytes.push(retrieved_share);
    }

    // Convert bytes to Share
    let shares = retrieved_shares_bytes.iter().map(|s| Share::try_from(s.as_slice()).unwrap()).collect();

    // Recover master key
    let key = recover_company_master_key(company.threshold, shares);
    let mut master_key: StackByteArray<CRYPTO_SECRETBOX_KEYBYTES> = StackByteArray::new();
    master_key.copy_from_slice(&*key);

    // Save data
    company.master_key = Some(master_key);

    Ok(Message::new(company.name.clone(), Command::Auth, ONE, None, None))
}


/// Manages list request to the server
///
/// # Arguments
///
/// * `message` - A message sent by the server
/// * `company` - A mutable reference to the company
///
/// # Returns
///
/// * `Result<Message, Box<dyn Error>>` - A result containing a message to send to the server
///
fn list_server(message: Message, company: &mut ClientCompany) -> Result<Message, Box<dyn Error>> {

    print_header("Listing files");

    // Get list
    let binding = message.body.unwrap();
    let data : FileNameList =  retrieve_from_buffer::<FileNameList>(&binding)?;

    // Recover encryption key
    let encryption_key =  recover_encryption_key(&company.master_key, &data.encrypted_encryption_key.0, &data.encrypted_encryption_key.1.to_vec())?;

    // Decrypt list
    for file in data.name_list {

        let encrypted_name = file.1;
        let nonce = encrypted_name.0;
        let encrypted = encrypted_name.1;

        let clear_text = decrypt(&encryption_key, &nonce, &encrypted.to_vec())?;

        println!("{} - {:?}", file.0, String::from_utf8(clear_text)?);
    }

    // Ask for user input
    let user_input = input::<u64>().msg("Please provide a file index : ").get();

    let mut buffer = [0 as u8; 16];
    store_in_buffer(&user_input, &mut buffer[..])?;

    Ok(Message::new(company.name.clone(), Command::File, ONE, Some(buffer.to_vec()), company.token.clone()))
}

/// Manages file request to the server
///
/// # Arguments
///
/// * `message` - A message sent by the server
/// * `company` - A mutable reference to the company
///
/// # Returns
///
/// * `Result<Message, Box<dyn Error>>` - A result containing a message to send to the server
///
fn file_server(message: Message, company: &mut ClientCompany) -> Result<Message, Box<dyn Error>> {

    print_header("Show file");

    let binding = message.body.unwrap();
    let file_params : FileParams =  retrieve_from_buffer::<FileParams>(&binding)?;

    // Recover encryption key
    let encryption_key =  recover_encryption_key(&company.master_key, &file_params.encrypted_encryption_key.0, &file_params.encrypted_encryption_key.1.to_vec())?;

    // Recover file encryption key
    let context = Vec::from("_subkey_");
    let file_sub_key = derive_sub_key(&encryption_key, file_params.file.index, &context[..]);

    // Decrypt file
    let (name, content) = decrypt_file(&file_sub_key, &file_params.file.nonce, &file_params.file.name.to_vec(), &file_params.file.content.to_vec());

    // Display file
    println!("name: {}", String::from_utf8(name)?);
    println!("content: {}", String::from_utf8(content)?);

    Ok(Message::new(company.name.clone(), Command::Bye, END, None, None))
}


/// Manages file addition to the server
///
/// # Arguments
///
/// * `message` - A message sent by the server
/// * `company` - A mutable reference to the company
///
/// # Returns
///
/// * `Result<Message, Box<dyn Error>>` - A result containing a message to send to the server
///
fn add_file_server(message: Message, company: &mut ClientCompany) -> Result<Message, Box<dyn Error>> {

    print_header("Add file");

    match message.sequence {
        Sequence::TWO => {
            let binding = message.body.unwrap();
            let data : FileNameList = ciborium::de::from_reader(&binding[..]).unwrap();

            // Recover encryption key
            let encryption_key =  recover_encryption_key(&company.master_key, &data.encrypted_encryption_key.0, &data.encrypted_encryption_key.1.to_vec())?;

            // Get file name and content
            let file_name = Vec::from(input:: < String>().msg("What is the file name ? ").get());
            let file_content = Vec::from(input:: < String>().msg("What is the file content ? ").get());

            // Generate subkey
            let sub_key_id : u64 = data.counter + 1;
            let context = Vec::from("_subkey_");
            let sub_key = derive_sub_key(&encryption_key, sub_key_id, &context[..]);

            // Encrypt file name and content
            let (nonce, name_box, content_box) = encrypt_file( &sub_key, &file_name, &file_content);

            // Encrypt file name for file name list
            let encrypted_filename = encrypt(&encryption_key, &file_name);

            let file_add = FileAdd{
                company_name: company.name.clone(),
                encrypted_filename,
                name: name_box.clone(),
                content: content_box,
                nonce,
            };
            
            let mut sender = [0 as u8; 2048];
            store_in_buffer(&file_add, &mut sender)?;

            Ok(Message::new(company.name.clone(), Command::AddFile, THREE, Some(sender.to_vec()), company.token.clone()))
        }
        END => Ok(Message::new(vec![], Command::Bye, END, None, None)),
        _ => Ok(Message::new(vec![], Command::Bye, END, None, None)),
    }
}

/// Prints the header
///
/// # Arguments
///
/// * `title` - A string containing the title to print
///
fn print_header(title: &str) {
    println!("\n*******************************************");
    println!("{}", title);
    println!("*******************************************\n");
}


/*
fn revoke_user(message: Message, company: &mut ClientCompany) -> Result<Message, Box<dyn Error>> {

    print_header("Revoking user");

    // TODO
    // Which user to revoke ?

    // ONE -> Send username

    // TWO -> Receive encrypted encryption key and encrypted keypair

    // THREE -> Decrypt encryption key, decrypt keypair, generate new master key, generate
    // shares from master key, encrypt encryption key with new master key, encrypt keypair
    // Send encrypted encryption key and encrypted keypair to server, shares to server


    None
}
*/



