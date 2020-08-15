use saltpack_rs::*;
use sodiumoxide::crypto::box_;
use sodiumoxide::crypto::secretbox;
use std::convert::TryInto;

fn transform_u32_to_array_of_u8(x: u32) -> [u8; 4] {
    let b1: u8 = ((x >> 24) & 0xff) as u8;
    let b2: u8 = ((x >> 16) & 0xff) as u8;
    let b3: u8 = ((x >> 8) & 0xff) as u8;
    let b4: u8 = (x & 0xff) as u8;
    return [b1, b2, b3, b4];
}

fn main() {
    let header_packet = HeaderPacket::new();

    // 1. Generate a random 32-byte payload key.
    let payload_key = saltpack_rs::HeaderPacket::generate_payload_key();

    // 2. Generate a random ephemeral keypair, using crypto_box_keypair.
    let (ephemeral_public_key, ephemeral_private_key) =
        saltpack_rs::HeaderPacket::generate_ephemeral_keys();

    // 3. Encrypt the sender's long-term public key using crypto_secretbox with the
    // payload key and the nonce saltpack_sender_key_sbox, to create the sender secretbox.
    let sender_secretbox = saltpack_rs::HeaderPacket::sender_secretbox(&payload_key);

    // 4. For each recipient, encrypt the payload key using crypto_box with the recipient's public key,
    // the ephemeral private key, and the nonce saltpack_recipsbXXXXXXXX. XXXXXXXX is 8-byte big-endian
    // unsigned recipient index, where the first recipient is index zero. Pair these with the recipients'
    // public keys, or null for anonymous recipients, and collect the pairs into the recipients list.
    let (recp_public_key, recp_private_key) =
        saltpack_rs::HeaderPacket::generate_recipient_keypair();

    let recipient_ciphertext = saltpack_rs::HeaderPacket::encrypt_payload_key_for_recipient(
        payload_key,
        recp_public_key,
        ephemeral_private_key,
    );

    let recipients_list: Vec<Vec<u8>> = vec![recipient_ciphertext];
    println!("{:?}", recipients_list);

    // 5. Collect the format name, version, and mode into a list, followed by the ephemeral public key,
    // the sender secretbox, and the nested recipients list.
    let x = &[
        &"saltpack",
        &"[2, 0]",
        &"0",
        &"ca dd 21 d0 47 1f 09 90 92 79 84 57 78 7a af bd 35 d6 1f 1c fe dc 2f d8 d7 d9 86 eb fe cd 53 35",
        &"sender secretbox",
        &"recipients list",
    ];

    println!("{:#?}", x);

    // 6. Serialize the list from #5 into a MessagePack array object.
    let mut msg = Vec::new();
    for pat in recipients_list {
        for valu in pat {
            // println!("{:?}", valu);
            let mut buf = Vec::new();
            rmp::encode::write_sint(&mut buf, valu.try_into().unwrap()).unwrap();
            // println!("{:?}", buf);
            msg.extend(buf.clone());
        }
    }
    // rmp::encode::write_u8(&mut bufs[0], recipients_list).unwrap();
    println!("\n\n");
    println!("{:?}", msg);

    // 7. Take the crypto_hash (SHA512) of the bytes from #6. This is the header hash.

    // 8. Serialize the bytes from #6 again into a MessagePack bin object.
    // These twice-encoded bytes are the header packet.

    // After generating the header, the sender computes each recipient's MAC key,
    // which will be used below to authenticate the payload:

    // 9. Concatenate the first 16 bytes of the header hash from step 7 above, with the recipient
    // index from step 4 above. This is the basis of each recipient's MAC nonce.
}
