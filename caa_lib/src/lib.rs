#![crate_type = "lib"]

pub mod caa_lib {
    use std::collections::HashMap;
    use rand::Rng;
    use serde::{Serialize, Deserialize};
    use dryoc::dryocbox::{PublicKey, StackByteArray};
    use dryoc::dryocsecretbox::{DryocSecretBox, Mac};
    use dryoc::pwhash::Salt;


    // TODO: add params in Enum
    #[derive(Debug, Serialize, Deserialize, PartialEq)]
    pub enum Command {
        Welcome,
        Login,
        Register,
        Auth,
        List,
        File,
        AddFile,
        RemoveFile,
        Revoke,
        Error,
        Bye,
    }

    #[derive(Debug, Serialize, Deserialize, PartialEq)]
    pub enum Sequence {
        ONE,
        TWO,
        THREE,
        FOUR,
        FIVE,
        SIX,
        END
    }

    #[derive(Debug, Serialize, Deserialize)]
    pub struct Message {
        pub company_name: Vec<u8>,
        pub command: Command,
        pub sequence: Sequence,
        pub body: Option<Vec<u8>>,
        pub token: Option<Vec<u8>>
    }

    impl Message {
        pub fn new(company_name: Vec<u8>, command: Command, sequence: Sequence, body: Option<Vec<u8>>, token: Option<Vec<u8>>) -> Message {
            Message {
                company_name,
                command,
                sequence,
                body,
                token
            }
        }
    }

    #[derive(Debug, Serialize, Deserialize, Clone)]
    pub struct User {
        pub username: String,
        pub password_hash: String,
    }

    #[derive(Debug, Serialize, Deserialize)]
    pub struct CompanyFile {
        pub index: u64,
        pub name: DryocSecretBox<Mac, Vec<u8>>,
        pub content: DryocSecretBox<Mac, Vec<u8>>,
        pub nonce: StackByteArray<24>,
    }

    impl CompanyFile {
        pub fn new(index: u64, name: Vec<u8>, content: Vec<u8>, nonce: StackByteArray<24>) -> Self {
            CompanyFile {
                index: index,
                name: DryocSecretBox::from_bytes(&name).unwrap(),
                content: DryocSecretBox::from_bytes(&content).unwrap(),
                nonce,
            }
        }
    }

    impl Clone for CompanyFile {
        fn clone(&self) -> Self {
            CompanyFile {
                index: self.index,
                name: self.name.clone(),
                content: self.content.clone(),
                nonce: self.nonce.clone(),
            }
        }
    }


    #[derive(Debug, Serialize, Deserialize)]
    pub struct ObfuscatedShare {
        pub nonce: StackByteArray<24>,
        pub salt: Salt,
        pub secret_box: DryocSecretBox<Mac, Vec<u8>>
    }

    impl Clone for ObfuscatedShare {
        fn clone(&self) -> Self {
            ObfuscatedShare {
                nonce: self.nonce.clone(),
                salt: self.salt.clone(),
                secret_box: self.secret_box.clone()
            }
        }
    }

    #[derive(Debug, Serialize, Deserialize)]
    pub struct EncryptedKPNonce {
        pub public_key: PublicKey,
        pub encrypted_secret_key: Vec<u8>,
        pub nonce : StackByteArray<24>,
    }

    impl Clone for EncryptedKPNonce {
        fn clone(&self) -> Self {
            EncryptedKPNonce {
                public_key: self.public_key.clone(),
                encrypted_secret_key: self.encrypted_secret_key.clone(),
                nonce: self.nonce.clone()
            }
        }
    }


    #[derive(Debug, Serialize, Deserialize)]
    pub struct ServerCompany {
        pub name: Vec<u8>,
        pub threshold: u8,
        pub shares: HashMap<Vec<u8>, ObfuscatedShare>,
        pub file_name_list: HashMap<u64, (StackByteArray<24>, DryocSecretBox<Mac, Vec<u8>>)>,
        pub file_list: HashMap<u64, CompanyFile>,
        pub encrypted_signing_pair: EncryptedKPNonce,
        pub encrypted_encryption_key: Option<(StackByteArray<24>, DryocSecretBox<Mac, Vec<u8>>)>,
        pub token: Option<Vec<u8>>,
        pub challenge: Option<Vec<u8>>,
        pub counter: u64,
    }

    #[derive(Debug, Serialize, Deserialize)]
    pub struct ClientCompany {
        pub name: Vec<u8>,
        pub signing_pair: Option<EncryptedKPNonce>,
        pub master_key: Option<StackByteArray<32>>,
        pub threshold: u8,
        pub token: Option<Vec<u8>>,
        pub challenge: Option<Vec<u8>>,
    }

    impl ClientCompany {
        pub fn new(name: Vec<u8>, threshold: u8) -> ClientCompany {
            ClientCompany {
                name,
                signing_pair: None,
                master_key: None,
                threshold,
                token: None,
                challenge: None,
            }
        }
    }

    #[derive(Debug, Serialize, Deserialize)]
    pub struct LoginParams {
        pub threshold: u8,
        pub shares: HashMap<Vec<u8>, ObfuscatedShare>,

    }
    #[derive(Debug, Serialize, Deserialize)]
    pub struct AuthParams {
        pub signing_pair: EncryptedKPNonce,
        pub challenge: Vec<u8>,
    }

    #[derive(Debug, Serialize, Deserialize)]
    pub struct FileParams {
        pub encrypted_encryption_key : (StackByteArray<24>, DryocSecretBox<Mac, Vec<u8>>),
        pub file : CompanyFile,
    }

    #[derive(Debug, Serialize, Deserialize)]
    pub struct FileNameList {
        pub counter: u64,
        pub encrypted_encryption_key : (StackByteArray<24>, DryocSecretBox<Mac, Vec<u8>>),
        pub name_list: HashMap<u64, (StackByteArray<24>, DryocSecretBox<Mac, Vec<u8>>)>,
    }

    #[derive(Debug, Serialize, Deserialize)]
    pub struct FileAdd {
        pub company_name: Vec<u8>,
        pub encrypted_filename: (StackByteArray<24>, DryocSecretBox<Mac, Vec<u8>>),
        pub name: DryocSecretBox<Mac, Vec<u8>>,
        pub content: DryocSecretBox<Mac, Vec<u8>>,
        pub nonce: StackByteArray<24>,
    }

    pub type FileList = Vec<CompanyFile>;

    #[derive(Debug, Serialize, Deserialize)]
    pub struct Vault {
        pub companies: HashMap<Vec<u8>, ServerCompany>,
    }

    impl Vault {
        pub fn new() -> Vault {
            Vault {
                companies: HashMap::new(),
            }
        }

        pub fn add_company(&mut self, company: ServerCompany) {
            self.companies.insert(company.name.clone(), company);
        }
    }


    pub fn generate_token() -> Vec<u8> {
        rand::thread_rng().gen::<[u8; 32]>().to_vec()
    }

    pub fn retrieve_from_buffer<'a,T: Deserialize<'a>>(buffer: &[u8]) -> Result<T, Box<dyn std::error::Error>>{
        let value = ciborium::de::from_reader(&buffer[..])?;
        Ok(value)
    }

    pub fn store_in_buffer<T: Serialize>(data: &T, buffer: &mut [u8]) -> Result<(), Box<dyn std::error::Error>>{
        ciborium::ser::into_writer(&data, buffer)?;
        Ok(())
    }

    pub fn create_message(company_name: Vec<u8>, command: Command,
                          sequence: Sequence, body: Option<Vec<u8>>, token: Option<Vec<u8>>) -> Message {
        Message {
            company_name,
            command,
            sequence,
            body,
            token,
        }
    }

}
