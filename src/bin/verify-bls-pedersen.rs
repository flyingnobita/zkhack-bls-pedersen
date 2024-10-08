use ark_bls12_381::G1Affine;
use ark_serialize::CanonicalDeserialize;
use bls_pedersen::solution1::run_solution;
use std::io::Cursor;

use bls_pedersen::bls::verify;
use bls_pedersen::data::puzzle_data;
use bls_pedersen::PUZZLE_DESCRIPTION;
use prompt::{puzzle, welcome};

fn main() {
    welcome();
    puzzle(PUZZLE_DESCRIPTION);
    let (pk, _ms, _sigs) = puzzle_data();
    // for (m, sig) in ms.iter().zip(sigs.iter()) {
    //     verify(pk, m, *sig);
    // }

    /* Your solution here! */
    // let sig = ...;
    // let m = your username

    // Given a signature, produce a username that verifies.
    let m = b"tom marvolo riddle";

    let sig_hex = run_solution(m);
    let sig = G1Affine::deserialize(&mut Cursor::new(hex::decode(sig_hex).unwrap())).unwrap();

    verify(pk, m, sig);
}
