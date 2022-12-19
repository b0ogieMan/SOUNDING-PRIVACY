#![crate_type = "lib"]

pub mod caa_crypto {
    use sharks::{Share, Sharks};
    use dryoc::dryocbox::{Nonce, StackByteArray};
    use dryoc::dryocsecretbox::{DryocSecretBox, Mac};
    use dryoc::Error;
    use dryoc::kdf::{Kdf};
    use dryoc::sign::{SignedMessage, SigningKeyPair};

    use sharks;
    use caa_lib::caa_lib::EncryptedKPNonce;

    /// Returns a person with the name given them
    ///
    /// # Arguments
    ///
    /// * `name` - A string slice that holds the name of the person
    ///
    /// # Examples
    ///
    /// ```
    /// // You can have rust code between fences inside the comments
    /// // If you pass --test to `rustdoc`, it will even test it for you!
    /// use doc::Person;
    /// let person = Person::new("name");
    /// ```
    pub fn generate_company_shares(threshold: u8, nb_of_shares: usize, secret: &Vec<u8>) -> Vec<Vec<u8>> {
        let mut shares_bytes: Vec<Vec<u8>> = Vec::new();

        let shares : Vec<Share>= Sharks(threshold).dealer(&secret).take(nb_of_shares).collect();

        for share in shares {
            shares_bytes.push(Vec::from(&share));
        };

        shares_bytes
    }

    pub fn recover_company_master_key(threshold: u8, shares: Vec<Share>) -> Vec<u8> {
        Sharks(threshold).recover(shares.as_slice()).unwrap()
    }

    pub fn generate_keypair() -> SigningKeyPair<StackByteArray<32>, StackByteArray<64>> {
        SigningKeyPair::gen_with_defaults()
    }

    pub fn sign_message(keypair : &SigningKeyPair<StackByteArray<32>, StackByteArray<64>>, message: &Vec<u8>) -> Result<SignedMessage<StackByteArray<64>, Vec<u8>>, Error> {
        keypair.sign_with_defaults(message.as_slice())
    }

    pub fn verify_signature(message: &SignedMessage<StackByteArray<64>, Vec<u8>>, keypair: &EncryptedKPNonce) -> Result<(), Error> {
        message.verify(&keypair.public_key)
    }

    pub fn derive_sub_key(secret_key: &StackByteArray<32>, subkey_id: u64, context: &[u8]) -> StackByteArray<32> {
        let key = Kdf::from_parts(secret_key.clone(), context);
        key.derive_subkey::<StackByteArray<32>>(subkey_id).unwrap()
    }

    pub fn encrypt(secret_key: &StackByteArray<32>, data: &Vec<u8>) -> (StackByteArray<24>, DryocSecretBox<Mac, Vec<u8>>){
        let nonce = Nonce::new();
        let secret_box = DryocSecretBox::encrypt_to_vecbox(data, &nonce, secret_key);
        (nonce, secret_box)
    }

    pub fn encrypt_file(secret_key: &StackByteArray<32>, file_name: &Vec<u8>, file_content: &Vec<u8>) -> (StackByteArray<24>, DryocSecretBox<Mac, Vec<u8>>, DryocSecretBox<Mac, Vec<u8>>) {
        let nonce = Nonce::new();
        let name_box = DryocSecretBox::encrypt_to_vecbox(file_name, &nonce, secret_key);
        let content_box = DryocSecretBox::encrypt_to_vecbox(file_content, &nonce, secret_key);

        (nonce, name_box, content_box)
    }

    pub fn decrypt(secret_key: &StackByteArray<32>, nonce: &StackByteArray<24>, secret_box: &Vec<u8>) -> Result<Vec<u8>, Error> {

        let c : DryocSecretBox<Mac, Vec<u8>> = DryocSecretBox::from_bytes(&secret_box[..])?;
        c.decrypt(nonce, secret_key)

    }

    pub fn decrypt_file(secret_key: &StackByteArray<32>, nonce: &StackByteArray<24>, name_box: &Vec<u8>, content_box: &Vec<u8>) -> (Vec<u8>, Vec<u8>) {

        let mut dryocsecretbox: DryocSecretBox<Mac, Vec<u8>> = DryocSecretBox::from_bytes(&name_box[..]).expect("unable to load box");
        let name = dryocsecretbox.decrypt(nonce, secret_key).expect("unable to decrypt");
        dryocsecretbox = DryocSecretBox::from_bytes(&content_box[..]).expect("unable to load box");
        let content = dryocsecretbox.decrypt(nonce, secret_key).expect("unable to decrypt");
        (name, content)
    }

    pub fn recover_encryption_key(secret_key: &Option<StackByteArray<32>>, nonce: &StackByteArray<24>, secret_box: &Vec<u8>) -> Result<StackByteArray<32>, Box<dyn std::error::Error>> {
        let encryption_key = decrypt(&secret_key.as_ref().unwrap(), &nonce, &*secret_box)?;
        let mut enc_key: StackByteArray<32> = StackByteArray::new();

        enc_key.copy_from_slice( &encryption_key);
        Ok(enc_key)
    }

}