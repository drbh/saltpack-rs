use std::convert::TryInto;
// use rand::Rng;
use sodiumoxide::crypto::box_;
use sodiumoxide::crypto::secretbox;

#[derive(Debug)]
pub struct HeaderPacket {}

impl HeaderPacket {
    pub fn new() -> HeaderPacket {
        let header_packet = HeaderPacket {};
        header_packet
    }

    pub fn generate_payload_key() -> Vec<u8> {
        // println!("\n1. Generate a random 32-byte payload key.");
        let payload_key: Vec<u8> = [
            111, 123, 234, 59, 4, 64, 124, 173, 191, 8, 140, 112, 82, 6, 248, 79, 52, 135, 15, 106,
            129, 218, 53, 8, 1, 115, 16, 105, 192, 105, 129, 189,
        ]
        .to_vec();
        // println!("payload_key: {:?}", payload_key);
        payload_key
    }

    pub fn generate_ephemeral_keys() -> (
        sodiumoxide::crypto::box_::curve25519xsalsa20poly1305::PublicKey,
        sodiumoxide::crypto::box_::curve25519xsalsa20poly1305::SecretKey,
    ) {
        // println!("\n\n2. Generate a random ephemeral keypair, using crypto_box_keypair.");
        // ephemeral_keypair_seed_slice
        let ephemeral_keypair_seed_slice = [
            154, 118, 13, 59, 4, 64, 124, 173, 191, 8, 140, 112, 82, 6, 248, 79, 52, 135, 15, 106,
            129, 218, 53, 8, 1, 115, 16, 105, 192, 105, 129, 189,
        ];
        // println!("ephemeral_keypair_seed_slice: {:#?}", ephemeral_keypair_seed_slice);
        let seed = sodiumoxide::crypto::box_::curve25519xsalsa20poly1305::Seed::from_slice(
            &ephemeral_keypair_seed_slice,
        )
        .expect("Failed to make seed");
        let (ephemeral_public_key, ephemeral_private_key) =
            sodiumoxide::crypto::box_::curve25519xsalsa20poly1305::keypair_from_seed(&seed);

        // println!("ephemeral_public_key: {:#?}", ephemeral_public_key);
        // println!("ephemeral_private_key: {:#?}", ephemeral_private_key);
        // println!("Keypair: {:#?}", keypair);

        return (ephemeral_public_key, ephemeral_private_key);
    }

    pub fn sender_secretbox(payload_key: &Vec<u8>) -> Vec<u8> {
        // println!("\n\n3. Encrypt the sender's long-term public key using crypto_secretbox with the payload key and the nonce saltpack_sender_key_sbox, to create the sender secretbox.");
        let key =
            sodiumoxide::crypto::secretbox::xsalsa20poly1305::Key::from_slice(payload_key).unwrap();
        let nonce = sodiumoxide::crypto::secretbox::xsalsa20poly1305::Nonce::from_slice(
            b"saltpack_sender_key_sbox",
        )
        .unwrap();
        // let nonce = secretbox::gen_nonce();

        let plaintext = b"sender's long-term public key";
        let sender_secretbox = secretbox::seal(plaintext, &nonce, &key);

        // println!("{:?}", sender_secretbox);
        return sender_secretbox;
    }

    pub fn generate_recipient_keypair() -> (
        sodiumoxide::crypto::box_::curve25519xsalsa20poly1305::PublicKey,
        sodiumoxide::crypto::box_::curve25519xsalsa20poly1305::SecretKey,
    ) {
        let recp_keypair_seed_slice = [
            100, 100, 13, 59, 100, 64, 100, 100, 100, 8, 100, 100, 82, 100, 248, 100, 100, 100, 15,
            106, 129, 218, 100, 8, 1, 115, 16, 105, 192, 105, 100, 189,
        ];
        // println!("recp_keypair_seed_slice: {:#?}", recp_keypair_seed_slice);
        let seed = sodiumoxide::crypto::box_::curve25519xsalsa20poly1305::Seed::from_slice(
            &recp_keypair_seed_slice,
        )
        .expect("Failed to make seed");
        let (recp_public_key, recp_private_key) =
            sodiumoxide::crypto::box_::curve25519xsalsa20poly1305::keypair_from_seed(&seed);

        // println!("recp_public_key: {:#?}", recp_public_key);
        // println!("recp_private_key: {:#?}", recp_private_key);
        return (recp_public_key, recp_private_key);
    }

    pub fn encrypt_payload_key_for_recipient(
        payload_key: Vec<u8>,
        recp_public_key: sodiumoxide::crypto::box_::curve25519xsalsa20poly1305::PublicKey,
        ephemeral_private_key: sodiumoxide::crypto::box_::curve25519xsalsa20poly1305::SecretKey,
    ) -> Vec<u8> {
        let nonce = sodiumoxide::crypto::box_::curve25519xsalsa20poly1305::Nonce::from_slice(
            b"saltpack_recipsbXXXXXXXX",
        )
        .unwrap();
        let recipient_ciphertext = box_::seal(
            &payload_key,
            &nonce,
            &recp_public_key,
            &ephemeral_private_key,
        );

        return recipient_ciphertext;
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn it_works() {
        assert_eq!(2 + 2, 4);
    }
}
