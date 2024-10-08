use crate::bls::verify;
use crate::data::puzzle_data;
use crate::hash::hash_to_curve;
use crate::sage_output::sage_output;
use ark_bls12_381::{G1Affine, G1Projective};
use ark_ec::group::Group;
use ark_ec::AffineCurve;
use ark_ff::Zero;
use ark_serialize::CanonicalSerialize;
use std::fs::File;
use std::io::Write;
use std::time::{SystemTime, UNIX_EPOCH};

pub fn bytes_to_bits(bytes: &[u8]) -> Vec<bool> {
    let mut bits = Vec::with_capacity(bytes.len() * 8);
    for byte in bytes {
        for i in 0..8 {
            let bit = (*byte >> i) & 1;
            bits.push(bit == 1)
        }
    }
    bits
}

fn bytes_to_bits_string(bytes: &[u8]) -> String {
    let bits = bytes_to_bits(bytes);
    let mut s = String::with_capacity(bits.len());
    for bit in bits {
        if bit {
            s.push('1');
        } else {
            s.push('0');
        }
    }
    s
}

pub fn write_msgs_to_file(msgs: Vec<Vec<u8>>) {
    let mut file = File::create(format!(
        "bits_vecs-{}.txt",
        (SystemTime::now().duration_since(UNIX_EPOCH))
            .unwrap()
            .as_millis()
    ))
    .unwrap();
    for msg in msgs {
        let blake = hash_to_curve(&msg).0;
        let string = bytes_to_bits_string(&blake);
        file.write_all(string.as_ref()).unwrap();
        file.write_all(b"\n").unwrap();
    }
}

pub fn generate_input_for_sage(ms: Vec<Vec<u8>>) {
    write_msgs_to_file(ms);
}

pub fn run_solution(msg: &[u8]) -> String {
    let (pk, ms, sigs) = puzzle_data();

    // Given the message, calculate its blake2b hash and convert it to bit string of 256 length
    generate_input_for_sage(ms);

    {
        let hashed_msg = hash_to_curve(msg).0;
        println!("out hashed msg: {}", bytes_to_bits_string(&hashed_msg));
    }

    // multpliy each selector[i] by s_i, the signature of ith message
    let mut sum = G1Projective::zero();
    let selectors = sage_output();
    for (i, num) in selectors.iter().enumerate() {
        let additive = sigs[i].into_projective().mul(num);
        sum += additive;
    }
    let sig_as_group_element = G1Affine::from(sum);
    verify(pk, msg, sig_as_group_element);

    let mut sig = Vec::new();
    sig_as_group_element.serialize(&mut sig).unwrap();
    let sig_hex = hex::encode(sig);
    println!("sig: {}", sig_hex);
    sig_hex
}
