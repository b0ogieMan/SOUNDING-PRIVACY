

/*
/******************************************************************************/
/* Client side                                                                */
/******************************************************************************/

fn register_company_client(){

    let company_name = Vec::from(input::<String>().msg("Enter company name: ").get());

    let threshold = input::<u8>().msg("Enter threshold: ").get();

    let number_of_users = input::<u8>().msg("Enter number of users: ").get();

    let mut users:Vec<(_,_)> = Vec::new();

    for i in 0..number_of_users {
        let user_name = Vec::from(input::<String>().msg("\nEnter user name: ").get());
        let user_password = Vec::from(input::<String>().msg("Enter user password: ").get());
        let user_share = Vec::from(input::<String>().msg("Enter user share: ").get());
        users.push((user_name, user_password));
    }

    let company_keypair = generate_company_keypair();

    let shares = generate_company_shares(threshold, &company_keypair);

    let company = Company {name: company_name, users, file_names: Vec::new(), file_list: Vec::new(), shares, public_key: Vec::from(company_keypair.public.to_bytes()) , threshold };

    /*
    let mut sender = [0u8; 8192 + 8192 + 8192 + 8192];
    ciborium::ser::into_writer(&company, &mut sender[..]).unwrap();
    */


    (Message {
        command: Register,
        sequence: Some(ONE),
        body: Some(sender.to_vec()),
        token: None,
    }, company_keypair);
}

fn add_company_file_client() -> Message {

    let file_name = Vec::from(input::<String>().msg("Enter file name: ").get());
    let file_content = Vec::from(input::<String>().msg("Enter file content: ").get());

    // Encrypt file name and content
    let file = CompanyFile::new(file_name, file_content);

    let mut sender = [0 as u8; 512];
    ciborium::ser::into_writer(&file, &mut sender[..]).unwrap();

    Message {
        command: AddFile,
        sequence: Some(ONE),
        body: Some(sender.to_vec()),
        token: None,
    }
}

fn update_company_filelist_client() -> Message {
    Message {
        command: Revoke,
        sequence: Some(ONE),
        body: None,
        token: None,
    }
}

fn revoke_user_company_client() -> Message {

    let user_name = Vec::from(input::<String>().msg("Enter user name to revoke: ").get());

    Message {
        command: Revoke,
        sequence: Some(ONE),
        body: None,
        token: None,
    }
}


/******************************************************************************/
/* Server side                                                                */
/******************************************************************************/
fn register_company_server(vault: &mut Vault, company: Company) -> Message {

    vault.companies.insert(company.name.clone(), company);

    Message {
        command: Register,
        sequence: Some(END),
        body: None,
        token: None,
    }
}

fn add_company_file_server(company: &mut Company, company_file: CompanyFile) -> Message {

    company.file_list.push((company_file.uuid, company_file));

    Message {
        command: AddFile,
        sequence: Some(TWO),
        body: None,
        token: None,
    }
}

fn update_company_filelist_server(company: &mut Company, company_file: CompanyFile) -> Message {

    company.file_list.push((company_file.uuid, company_file));

    Message {
        command: AddFile,
        sequence: Some(END),
        body: None,
        token: None,
    }
}

fn revoke_user_company_server(company: &mut Company, user_name: Vec<u8>) -> Message {

    company.users.retain(|(k, _)| *k != user_name);
    // If nb of users < threshold, regenerate shares
    if company.users.len() < company.threshold as usize {
        Message {
            command: Revoke,
            sequence: Some(THREE),
            body: None,
            token: None,
        }
    } else {
        Message {
            command: Revoke,
            sequence: Some(END),
            body: None,
            token: None,
        }
    }
}

*/


use std::io::Read;
use std::ops::Deref;
use dryoc::constants::{CRYPTO_BOX_PUBLICKEYBYTES, CRYPTO_BOX_SECRETKEYBYTES, CRYPTO_KDF_KEYBYTES, CRYPTO_SIGN_BYTES, CRYPTO_SIGN_PUBLICKEYBYTES, CRYPTO_SIGN_SECRETKEYBYTES};
use dryoc::dryocbox::{Bytes, KeyPair, NewByteArray, Nonce, PublicKey, StackByteArray};
use dryoc::dryocsecretbox::{DryocSecretBox, Mac};
use dryoc::kdf::{Context, Kdf, Key};
use dryoc::pwhash::{Config, PwHash, Salt, VecPwHash};
use dryoc::sign::{SecretKey, SignedMessage, SigningKeyPair};
use rand::Rng;
use read_input::InputBuild;
use read_input::prelude::input;
use uuid::Uuid;
use sharks;
use sharks::{Share, Sharks};
use serde::{Serialize, Deserialize};


pub fn encrypt(secret_key: &StackByteArray<32>, data: &Vec<u8>) -> (StackByteArray<24>, DryocSecretBox<Mac, Vec<u8>>){
    let nonce = Nonce::gen();
    let secret_box = DryocSecretBox::encrypt_to_vecbox(data, &nonce, secret_key);
    (nonce, secret_box)
}


pub fn decrypt(secret_key: &StackByteArray<32>, nonce: &StackByteArray<24>, secret_box: Vec<u8>) -> Vec<u8> {
    let dryocsecretbox: DryocSecretBox<Mac, Vec<u8>> = DryocSecretBox::from_bytes(&secret_box[..]).expect("unable to load box");
    dryocsecretbox.decrypt(nonce, secret_key).expect("unable to decrypt")
}

fn main() {


}

    /*
    // Generation Shamir Key
    let shamir_secret_key = Key::gen();

    let sharks = Sharks(2);
    let dealer = sharks.dealer(&shamir_secret_key);
    let shares: Vec<Share> = dealer.take(3).collect();

    let mut shares_bytes = Vec::new();
    for share in shares {
        shares_bytes.push(Vec::from(&share));
    };

    let recovered_shares : Vec<Share> = shares_bytes.iter().map(|s| Share::try_from(s.as_slice()).unwrap()).collect();

    let shamir_recovered_key = sharks.recover(&recovered_shares).unwrap();



// Generate a random salt
    let mut salt = Salt::default();
    salt.resize(dryoc::constants::CRYPTO_PWHASH_SALTBYTES, 0);
    dryoc::rng::copy_randombytes(&mut salt);

// A strong passphrase
    let password = input::<String>().msg("What is the username ?").get();

    let pwhash: VecPwHash = PwHash::hash_with_salt(
        &Vec::from(password.clone()),
        salt,
        Config::interactive().with_opslimit(1).with_memlimit(8192),
    )
        .expect("unable to hash password with salt and custom config");

    pwhash.verify(&Vec::from(password)).expect("verification failed");
    pwhash
        .verify(b"invalid password").unwrap();


    // Generate a random secret key and nonce
    let secret_key = Key::gen();
    let nonce = Nonce::gen();
    let message = b"Why hello there, fren";

// Encrypt `message`, into a Vec-based box
    let dryocsecretbox = DryocSecretBox::encrypt_to_vecbox(message, &nonce, &secret_key);

// Convert into a libsodium-compatible box
    let sodium_box = dryocsecretbox.to_vec();

// Read the same box we just made into a new DryocBox
    let dryocsecretbox = DryocSecretBox::from_bytes(&sodium_box).expect("unable to load box");

// Decrypt the box we previously encrypted,
    let decrypted = dryocsecretbox
        .decrypt_to_vec(&nonce, &secret_key)
        .expect("unable to decrypt");

    assert_eq!(message, decrypted.as_slice());

    /* let signing_keypair = generate_keypair();

    // Encrypt signing_keypair
    let message = signing_keypair.secret_key.clone().to_vec();
    // let sawdw = StackByteArray::from(message);
    let nonce = Nonce::gen();
    let encrypted_secret_k = DryocSecretBox::encrypt_to_vecbox(&message, &nonce, &shamir_secret_key).to_vec();

    let s = EncryptedKPNonce {
        public_key: signing_keypair.public_key.clone(),
        encrypted_secret_key: encrypted_secret_k,
        nonce,
    };

    // Send Encrypted SigningKeyPair to Server
    let mut sender = [0u8;1024];
    ciborium::ser::into_writer(&s, &mut sender[..]).unwrap();

    let challenge = generate_token();

    // Sign challenge on Client
    let signed_message_client = sign_message(&signing_keypair, &challenge);
    // Retrieve Encrypted SigningKeyPair on Server
    let enc_kp: EncryptedKPNonce = ciborium::de::from_reader(&sender[..]).unwrap();

    ciborium::ser::into_writer(&signed_message_client, &mut sender[..]).unwrap();

    // Retrieve SignedMessage on Server
    let signed_message_server : SignedMessage<StackByteArray<64>, Vec<u8>> = ciborium::de::from_reader(&sender[..]).unwrap();

    // Verify the message signature
    let i = verify_signature(&signed_message_server, &enc_kp);

    // Derive MasterKey from ShamirKey on Client
    let master_key = derive_sub_key(&shamir_secret_key, 0, Context::new());

    let nonce2 = Nonce::gen();
    let enc_key = Key::gen().to_vec();

    let dryocsecretbox_vec = encrypt(&master_key, &nonce2, &enc_key);

    // Decrypt the box we previously encrypted
    let decrypted = decrypt(&master_key, &nonce2, dryocsecretbox_vec);

    assert_eq!(enc_key.as_slice(), decrypted.as_slice());





    println!("{}", CRYPTO_BOX_PUBLICKEYBYTES);
    println!("{}", CRYPTO_BOX_SECRETKEYBYTES);

    println!("{}", CRYPTO_SIGN_PUBLICKEYBYTES);
    println!("{}", CRYPTO_SIGN_SECRETKEYBYTES);

    println!("{}", CRYPTO_KDF_KEYBYTES); */
















}
