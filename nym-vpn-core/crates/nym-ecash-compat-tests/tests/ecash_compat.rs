//! Byte-level compatibility of the pinned nym-compact-ecash across
//! architectures. A router's client builds the spend proof; a 64-bit gateway
//! verifies it. Both hash `VerificationKeyAuth::to_bytes()` into the proof's
//! challenge, so those bytes must be the same on every architecture.
//!
//! The fixture was generated on x86_64 (`generate_spend_fixture`, ignored by
//! default). On a 32-bit target without the ecash patch the round trips fail
//! and the x86_64 payment no longer verifies.

use std::collections::HashMap;

use nym_compact_ecash::{
    Base58, PartialWallet, PayInfo, SecretKeyAuth, VerificationKeyAuth,
    aggregate_verification_keys, aggregate_wallets, generate_keypair_user, issue, issue_verify,
    scheme::{Payment, Wallet},
    setup::Parameters,
    tests::helpers::{generate_coin_indices_signatures, generate_expiration_date_signatures},
    ttp_keygen, withdrawal_request,
};

const FIXTURE: &str = include_str!("fixtures/spend-x86_64.txt");
const FIXTURE_PATH: &str = "tests/fixtures/spend-x86_64.txt";

// Dates at 00:00:00 UTC, as the scheme expects.
const SPEND_DATE: u32 = 1_701_907_200; // 2023-12-07
const EXPIRATION_DATE: u32 = 1_702_166_400; // 2023-12-10
const TOTAL_COINS: u64 = 32;
const PAY_INFO: PayInfo = PayInfo {
    pay_info_bytes: [6u8; 72],
};

fn fixture() -> HashMap<&'static str, &'static str> {
    FIXTURE
        .lines()
        .filter(|line| !line.starts_with('#') && !line.trim().is_empty())
        .filter_map(|line| line.split_once('='))
        .collect()
}

fn fixture_value(key: &str) -> &'static str {
    fixture()
        .get(key)
        .copied()
        .unwrap_or_else(|| panic!("{FIXTURE_PATH} has no '{key}='"))
}

#[test]
fn authority_keys_round_trip() {
    for keypair in ttp_keygen(2, 3).expect("ttp keygen") {
        let sk: &SecretKeyAuth = keypair.secret_key();
        let sk_bytes = sk.to_bytes();
        // x, then the number of ys as a u64: 8 bytes on every architecture.
        let ys_len = u64::from_le_bytes(sk_bytes[32..40].try_into().unwrap());
        assert_eq!(ys_len as usize, sk.size(), "secret key length field");
        assert_eq!(
            &SecretKeyAuth::from_bytes(&sk_bytes).expect("secret key from its own bytes"),
            sk
        );

        let vk = keypair.verification_key();
        let vk_bytes = vk.to_bytes();
        assert_eq!(
            VerificationKeyAuth::from_bytes(&vk_bytes)
                .expect("verification key from its own bytes"),
            vk
        );
    }
}

#[test]
fn fixture_verification_key_bytes_are_stable() {
    let encoded = fixture_value("verification_key");
    let vk = VerificationKeyAuth::try_from_bs58(encoded).expect("fixture verification key");
    // The bytes this architecture feeds into the challenge hash are the ones
    // x86_64 wrote.
    assert_eq!(vk.to_bs58(), encoded);
}

#[test]
fn fixture_payment_from_x86_64_verifies() {
    let vk = VerificationKeyAuth::try_from_bs58(fixture_value("verification_key"))
        .expect("fixture verification key");
    let payment = Payment::try_from_bs58(fixture_value("payment")).expect("fixture payment");
    let spend_date: u32 = fixture_value("spend_date").parse().expect("spend_date");
    assert_eq!(spend_date, SPEND_DATE);
    payment
        .spend_verify(&vk, &PAY_INFO, spend_date)
        .expect("the x86_64 payment verifies here");
}

/// Regenerates the fixture. Run on x86_64 only:
/// `cargo test -p nym-ecash-compat-tests -- --ignored generate_spend_fixture`
#[test]
#[ignore = "writes tests/fixtures/spend-x86_64.txt"]
fn generate_spend_fixture() {
    if !cfg!(target_arch = "x86_64") {
        panic!("the fixture is the x86_64 reference; generate it there");
    }
    let params = Parameters::new(TOTAL_COINS);
    let user = generate_keypair_user();
    let authorities = ttp_keygen(2, 3).expect("ttp keygen");
    let indices: [u64; 3] = [1, 2, 3];
    let secret_keys: Vec<&SecretKeyAuth> = authorities.iter().map(|kp| kp.secret_key()).collect();
    let verification_keys: Vec<VerificationKeyAuth> =
        authorities.iter().map(|kp| kp.verification_key()).collect();
    let vk = aggregate_verification_keys(&verification_keys, Some(&indices)).expect("aggregate vk");

    let date_signatures = generate_expiration_date_signatures(
        EXPIRATION_DATE,
        &secret_keys,
        &verification_keys,
        &vk,
        &indices,
    )
    .expect("expiration date signatures");
    let coin_signatures =
        generate_coin_indices_signatures(&params, &secret_keys, &verification_keys, &vk, &indices)
            .expect("coin index signatures");

    let t_type = 1;
    let (request, request_info) =
        withdrawal_request(user.secret_key(), EXPIRATION_DATE, t_type).expect("withdrawal");
    let shares: Vec<PartialWallet> = authorities
        .iter()
        .zip(verification_keys.iter())
        .zip(indices)
        .map(|((kp, auth_vk), index)| {
            let blinded = issue(
                kp.secret_key(),
                user.public_key(),
                &request,
                EXPIRATION_DATE,
                t_type,
            )
            .expect("issue");
            issue_verify(auth_vk, user.secret_key(), &blinded, &request_info, index)
                .expect("issue verify")
        })
        .collect();
    let mut wallet: Wallet =
        aggregate_wallets(&vk, user.secret_key(), &shares, &request_info).expect("wallet");

    let payment = wallet
        .spend(
            &params,
            &vk,
            user.secret_key(),
            &PAY_INFO,
            1,
            &date_signatures,
            &coin_signatures,
            SPEND_DATE,
        )
        .expect("spend");
    payment
        .spend_verify(&vk, &PAY_INFO, SPEND_DATE)
        .expect("the fresh payment verifies");

    let contents = format!(
        "# Generated on x86_64 by generate_spend_fixture in tests/ecash_compat.rs.\n\
         # A payment of one ticket and the aggregated verification key it was\n\
         # made against, both base58; pay_info is 72 bytes of 6.\n\
         spend_date={SPEND_DATE}\n\
         verification_key={}\n\
         payment={}\n",
        vk.to_bs58(),
        payment.to_bs58(),
    );
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join(FIXTURE_PATH);
    std::fs::write(&path, contents).expect("write fixture");
}
