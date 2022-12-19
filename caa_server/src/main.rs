use std::collections::HashMap;
use std::fs::File;
use std::error::Error;
use std::io::{Read, Write};
use std::net::{Shutdown, TcpListener, TcpStream};
use dryoc::dryocbox::StackByteArray;
use dryoc::sign::SignedMessage;
use log::{error, info};
use simple_logger::SimpleLogger;
use caa_lib::caa_lib::{AuthParams, Command, CompanyFile, FileAdd, FileNameList, FileParams, generate_token, LoginParams, Message, retrieve_from_buffer, Sequence, ServerCompany, store_in_buffer};
use caa_lib::caa_lib::Sequence::{END, ONE, TWO};
use caa_crypto::caa_crypto::verify_signature;


fn main() {
    let mut companies = restore_db().unwrap();

    SimpleLogger::new().env().init().unwrap();

    println!("*******************************************");
    println!("Welcome to the CAA project server App !");
    println!("Waiting for connections ...");
    println!("*******************************************");

    let listener = TcpListener::bind("127.0.0.1:3333").unwrap();

    info!("Server listening on port 3333");

    for stream in listener.incoming() {
        match stream {
            Ok(stream) => {
                info!("New connection: {}", stream.peer_addr().unwrap());
                match handle_connection(stream, &mut companies) {
                    Ok(_) => {}
                    Err(error) => error!("Error: {}", error)
                }
            }
            Err(error) => error!("Error: {}", error)
        }
    }
    match store_db(&mut companies) {
        Ok(_) => {}
        Err(error) => error!("Error: {}", error)
    }
    drop(listener);
}

fn handle_connection(mut stream: TcpStream, companies: &mut HashMap<Vec<u8>, ServerCompany>) -> Result<(), Box<dyn Error>> {
    let mut receiver = [0u8; 4096];
    let mut sender = [0u8; 4096];

    while match stream.read(&mut receiver) {
        Ok(size) => {

            // Close connection if client sends empty data
            if size == 0 {
                store_db(companies)?;
                info!("Connection closed");
                drop(stream);
                return Ok(());
            }

            let client_request = retrieve_from_buffer::<Message>(&receiver).unwrap();
            //println!("From Client: {:?}", client_request);

            let server_response = process_client_message(client_request, companies);

            match server_response {
                Ok(response) => {
                    store_in_buffer(&response, &mut sender)?;
                    //println!("To Client: {:?}", response);
                    stream.write(&sender[..])?;
                    stream.flush()?;
                }
                Err(error) => {
                    println!("Error: {}", error)
                }
            }
            true
        }
        Err(_) => {
            println!("An error occurred, terminating connection with {}", stream.peer_addr().unwrap());
            store_db(companies)?;
            stream.shutdown(Shutdown::Both)?;
            false
        }
    } {}
    Ok(())
}

fn process_client_message(message: Message, companies: &mut HashMap<Vec<u8>, ServerCompany>) -> Result<Message, Box<dyn Error>> {
    match message.command {
        Command::Login => login(message, companies),
        Command::Register => register(message, companies),
        Command::Auth => auth(message, companies),
        Command::List => list(message, companies),
        Command::File => file(message, companies),
        Command::AddFile => add_file(message, companies),
        _ => Ok(Message::new(vec![], Command::Bye, ONE, None, None))
    }
}

fn add_file(message: Message, companies: &mut HashMap<Vec<u8>, ServerCompany>) -> Result<Message, Box<dyn Error>> {

    let company = companies.get_mut(&message.company_name).unwrap();

    if company.token.clone().unwrap() != message.token.clone().unwrap() {
        Ok(Message::new(vec![], Command::Bye, END, None, None))
    } else {
        match message.sequence {
            ONE => {

                // Create and send data to client
                let file_name_list = FileNameList {
                    counter: company.counter,
                    encrypted_encryption_key: company.encrypted_encryption_key.as_ref().unwrap().clone(),
                    name_list: company.file_name_list.clone(),
                };

                let mut sender = [0 as u8; 2048];
                store_in_buffer(&file_name_list, &mut sender)?;

                Ok(Message::new(vec![], Command::AddFile, TWO, Some(sender.to_vec()), Some(company.token.as_ref().unwrap().clone())))
            }
            Sequence::THREE => {

                let binding = message.body.unwrap();
                let file_add: FileAdd = retrieve_from_buffer(&binding).unwrap();

                // Add file to the system

                company.counter += 1 ;

                company.file_list.insert(company.counter, CompanyFile {
                    index: company.counter,
                    name: file_add.name,
                    content: file_add.content,
                    nonce: file_add.nonce,
                });

                company.file_name_list.insert(company.counter, file_add.encrypted_filename);

                // Save database
                store_db(companies)?;

                Ok(Message::new(vec![], Command::Bye, END, None, None))
            }
            _ => Ok(Message::new(vec![], Command::Bye, END, None, None))
        }
    }


}


fn auth(request: Message, companies: &mut HashMap<Vec<u8>, ServerCompany>) -> Result<Message, Box<dyn Error>> {
    let mut company = companies.get_mut(&*request.company_name).unwrap();

    match request.sequence {
        ONE => {

            // Generate token and params
            let challenge = generate_token();
            let auth_params = AuthParams {
                signing_pair: company.encrypted_signing_pair.clone(),
                challenge: challenge.clone(),
            };

            // Generate challenge
            company.challenge = Some(challenge);

            // Send params
            let mut buffer = [0u8; 2048];
            store_in_buffer(&auth_params, &mut buffer)?;
            store_db(companies)?;

            Ok(Message::new(vec![], Command::Auth, TWO, Some(buffer.to_vec()), None))
        }
        Sequence::THREE => {

            // Get signed message
            let binding = request.token.unwrap();
            let signed_message = retrieve_from_buffer::<SignedMessage<StackByteArray<64>, Vec<u8>>>(&binding).unwrap();

            // Verify signature
            match verify_signature(&signed_message, &company.encrypted_signing_pair) {
                Ok(_) => {
                    let token = generate_token();
                    company.token = Option::from(token.clone());
                    store_db(companies)?;
                    Ok(Message::new(vec![], Command::Auth, END, None, Some(token))) }
                Err(_) => { error!("Signature verification failed");
                    Ok(Message::new(vec![], Command::Bye, END, None, None))
                },
            }
        }
        _ => Ok(Message::new(vec![], Command::Bye, END, None, None))
    }
}

fn register(request: Message, companies: &mut HashMap<Vec<u8>, ServerCompany>) -> Result<Message, Box<dyn Error>> {

    // TODO: Check if company already exists

    let binding = request.body.unwrap();
    let client_company = retrieve_from_buffer::<ServerCompany>(&binding).unwrap();

    // Insert company in the database
    companies.insert(client_company.name.clone(), client_company);
    store_db(companies)?;

    Ok(Message::new(vec![], Command::Register, TWO, Some(vec![]), None)) }

fn login(request: Message, companies: &mut HashMap<Vec<u8>, ServerCompany>) -> Result<Message, Box<dyn Error>> {
    match request.sequence {
        ONE => {
            match companies.get_mut(&request.company_name) {

                Some(c) => {

                    // Send the LoginParams to the client
                    let mut sender = [0 as u8; 1024];
                    store_in_buffer(
                        &LoginParams {
                            threshold: c.threshold,
                            shares: c.shares.clone(),
                        },&mut sender)?;

                    Ok(Message::new(vec![], Command::Login, TWO, Some(sender.to_vec()), None))
                }

                None => Ok(Message::new(vec![], Command::Bye, END, None, None))
            }
        }
        _ => Ok(Message::new(vec![], Command::Bye, END, None, None))
    }
}

fn list(message: Message, companies: &mut HashMap<Vec<u8>, ServerCompany>) -> Result<Message, Box<dyn Error>> {

    // Fetch company data
    let company = companies.get(&*message.company_name).unwrap();

    if company.token.clone().unwrap() != message.token.clone().unwrap() {
        Ok(Message::new(vec![], Command::Bye, END, None, None))
    } else {
        match message.sequence {
            ONE => {
                let clist = company.file_name_list.clone();

                let fnl = FileNameList {
                    counter: company.counter,
                    encrypted_encryption_key: company.encrypted_encryption_key.as_ref().unwrap().clone(),
                    name_list: clist,
                };

                // Send file list
                let mut sender = [0 as u8; 1024];
                store_in_buffer(&fnl, &mut sender)?;

                Ok(Message::new(company.name.clone(), Command::List, TWO, Some(sender.to_vec()), None))
            }
            _ => Ok(Message::new(vec![], Command::Bye, END, None, None))
        }
    }
}


fn file(message: Message, companies: &mut HashMap<Vec<u8>, ServerCompany>) -> Result<Message, Box<dyn Error>> {

    let company = companies.get_mut(&*message.company_name.clone()).unwrap();

    if company.token.clone().unwrap() != message.token.clone().unwrap() {
        Ok(Message::new(vec![], Command::Bye, END, None, None))
    } else {
        match message.sequence {
            ONE => {

                let index = retrieve_from_buffer::<u64>(&message.body.unwrap()).unwrap();


                let file  = company.file_list.get(&index).unwrap();

                let fp = FileParams {
                    encrypted_encryption_key: company.encrypted_encryption_key.as_ref().unwrap().clone(),
                    file : CompanyFile {
                        index: file.index,
                        name: file.name.clone(),
                        content: file.content.clone(),
                        nonce: file.nonce.clone(),
                    },
                };


                let mut sender = [0 as u8; 2048];
                store_in_buffer(&fp, &mut sender)?;

                Ok(Message::new(vec![], Command::File, TWO, Some(sender.to_vec()), None))
            }
            _ => Ok(Message::new(vec![], Command::Bye, END, None, None))
        }
    }
}


fn store_db(companies: &mut HashMap<Vec<u8>, ServerCompany>) -> Result<(), Box<dyn Error>> {

    let mut buffer = [0u8; 8192];
    store_in_buffer(&companies, &mut buffer)?;

    info!("Saving database to disk");
    // Create a file name db.bin, check if file exists, if not create it, else overwrite it with buffer
    let b = std::path::Path::new("db.bin").exists();
    match b {
        true => {
            let mut file = File::create("db.bin").unwrap();
            file.write_all(&buffer).unwrap();
            file.flush().unwrap();
        }
        false => {
            let mut file = File::create("db.bin").unwrap();
            file.write_all(&buffer).unwrap();
            file.flush().unwrap();
        }
    }
    info!("Database saved");
    Ok(())
}

fn restore_db() -> Result<HashMap<Vec<u8>, ServerCompany>, Box<dyn Error>> {

    let b = std::path::Path::new("db.bin").exists();
    match b {
        true => {
            info!("Restoring database from disk");
            let mut file = File::open("db.bin").unwrap();
            let mut buffer = [0u8; 8192];
            file.read(&mut buffer).unwrap();
            retrieve_from_buffer::<HashMap<Vec<u8>, ServerCompany>>(&buffer)
        }
        false => {
            info!("No database found, creating new one");
            Ok(HashMap::new())
        }
    }
}
