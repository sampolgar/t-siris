use ark_bls12_381::{Bls12_381, Fr, G1Projective};
use ark_ec::CurveGroup;
use ark_ff::Field;
use ark_ff::UniformRand;
use criterion::{criterion_group, criterion_main, BenchmarkId, Criterion};
use std::ops::Mul;
use std::time::Duration;
use t_siris::keygen::keygen;
use t_siris::protocol::{UserProtocol, VerifierProtocol};
use t_siris::shamir::{generate_shares, reconstruct_secret};
use t_siris::signer::Signer;

/// Benchmark function for threshold PS protocol
fn benchmark_t_siris(c: &mut Criterion) {
    // Test configurations to match tACT paper's parameters
    let configs = [
        // N=4, t=N/2+1=3, with varying attribute sizes
        (4, 3, 4),
        (4, 3, 8),
        (4, 3, 16),
        (4, 3, 32),
        (4, 3, 64),
        (4, 3, 128),
        // N=16, t=N/2+1=9, with varying attribute sizes
        (16, 9, 4),
        (16, 9, 8),
        (16, 9, 16),
        (16, 9, 32),
        (16, 9, 64),
        (16, 9, 128),
        // N=64, t=N/2+1=33, with varying attribute sizes
        (64, 33, 4),
        (64, 33, 8),
        (64, 33, 16),
        (64, 33, 32),
        (64, 33, 64),
        (64, 33, 128),
    ];

    // ObtainMaster benchmarks
    {
        let mut group = c.benchmark_group("t_siris");
        group.sample_size(100);
        group.measurement_time(Duration::from_secs(25));

        for &(n_participants, threshold, l_attributes) in &configs {
            let id_suffix = format!("N{}_t{}_n{}", n_participants, threshold, l_attributes);

            // Setup for this specific configuration
            let mut setup_rng = ark_std::test_rng();
            let (ck, _, _) =
                keygen::<Bls12_381>(threshold, n_participants, l_attributes, &mut setup_rng);

            let s1_shared_secret = Fr::rand(&mut setup_rng);
            let shares =
                generate_shares(&s1_shared_secret, threshold, n_participants, &mut setup_rng);

            // Only benchmark the request_credential function
            group.bench_function(BenchmarkId::new("obtain_master", id_suffix), |b| {
                b.iter(|| {
                    // Fresh RNG for each iteration
                    let mut bench_rng = ark_std::test_rng();

                    // model the benchmark for creating the shared secret, this is currently not implemented inside the commitment but here for bench
                    let _ = reconstruct_secret(&shares[0..threshold], threshold);

                    // Create attributes specific to this benchmark iteration
                    let attributes: Vec<Fr> = (0..l_attributes)
                        .map(|_| Fr::rand(&mut bench_rng))
                        .collect();

                    // Benchmark the complete request_credential operation
                    UserProtocol::request_credential(ck.clone(), Some(&attributes), &mut bench_rng)
                        .expect("Failed to create credential request")
                })
            });
        }

        group.finish();
    }

    // IssueMaster benchmarks (includes share generation and aggregation)
    {
        let mut group = c.benchmark_group("t_siris");
        group.sample_size(100);
        group.measurement_time(Duration::from_secs(25));

        for &(n_participants, threshold, l_attributes) in &configs {
            let id_suffix = format!("N{}_t{}_n{}", n_participants, threshold, l_attributes);

            // Complete setup outside the benchmark
            let mut setup_rng = ark_std::test_rng();

            // Setup keys
            let (ck, _, ts_keys) =
                keygen::<Bls12_381>(threshold, n_participants, l_attributes, &mut setup_rng);

            // Create signers
            let signers: Vec<_> = ts_keys
                .sk_shares
                .iter()
                .zip(ts_keys.vk_shares.iter())
                .map(|(sk_share, vk_share)| Signer::new(&ck, sk_share, vk_share))
                .collect();

            // Create credential request
            let attributes: Vec<Fr> = (0..l_attributes)
                .map(|_| Fr::rand(&mut setup_rng))
                .collect();
            let (credential, credential_request) =
                UserProtocol::request_credential(ck.clone(), Some(&attributes), &mut setup_rng)
                    .expect("Failed to create credential request");

            // Benchmark the complete issuance process (share generation + verification + aggregation)
            group.bench_function(BenchmarkId::new("issue_master", id_suffix), |b| {
                b.iter(|| {
                    let mut bench_rng = ark_std::test_rng();

                    // 1. Generate signature shares from threshold signers
                    let signature_shares = signers
                        .iter()
                        .take(threshold)
                        .map(|signer| {
                            let sig = signer
                                .sign_share(
                                    &credential_request.commitments,
                                    &credential_request.proofs,
                                    &credential_request.h,
                                    &mut bench_rng,
                                )
                                .expect("Failed to generate signature share");
                            (sig.party_index, sig)
                        })
                        .collect::<Vec<_>>();

                    // 2. Verify signature shares
                    let verified_shares = UserProtocol::verify_signature_shares(
                        &ck,
                        &ts_keys.vk_shares,
                        &credential_request,
                        &signature_shares,
                        threshold,
                    )
                    .expect("Failed to verify signature shares");

                    // 3. Aggregate shares
                    let blindings = credential.get_blinding_factors();
                    UserProtocol::aggregate_shares(
                        &ck,
                        &verified_shares,
                        &blindings,
                        threshold,
                        &credential_request.h,
                    )
                })
            });
        }

        group.finish();
    }

    // IssueMaster issue_master_no_zkp benchmarks (includes share generation and aggregation)
    {
        let mut group = c.benchmark_group("t_siris");
        group.sample_size(100);
        group.measurement_time(Duration::from_secs(15));

        for &(n_participants, threshold, l_attributes) in &configs {
            let id_suffix = format!("N{}_t{}_n{}", n_participants, threshold, l_attributes);

            // Complete setup outside the benchmark
            let mut setup_rng = ark_std::test_rng();

            // Setup keys
            let (ck, _, ts_keys) =
                keygen::<Bls12_381>(threshold, n_participants, l_attributes, &mut setup_rng);

            // Create signers
            let signers: Vec<_> = ts_keys
                .sk_shares
                .iter()
                .zip(ts_keys.vk_shares.iter())
                .map(|(sk_share, vk_share)| Signer::new(&ck, sk_share, vk_share))
                .collect();

            // Create credential request
            let attributes: Vec<Fr> = (0..l_attributes)
                .map(|_| Fr::rand(&mut setup_rng))
                .collect();
            let (credential, credential_request) =
                UserProtocol::request_credential(ck.clone(), Some(&attributes), &mut setup_rng)
                    .expect("Failed to create credential request");

            // Benchmark the complete issuance process (share generation + verification + aggregation)
            group.bench_function(BenchmarkId::new("issue_master_no_zkp", id_suffix), |b| {
                b.iter(|| {
                    let mut bench_rng = ark_std::test_rng();

                    // 1. Generate signature shares from threshold signers
                    let verified_shares = signers
                        .iter()
                        .take(threshold)
                        .map(|signer| {
                            let sig = signer
                                .sign_share_no_zkp_verify(
                                    &credential_request.commitments,
                                    &credential_request.proofs,
                                    &credential_request.h,
                                    &mut bench_rng,
                                )
                                .expect("Failed to generate signature share");
                            (sig.party_index, sig)
                        })
                        .collect::<Vec<_>>();

                    // // 2. Verify signature shares
                    // let verified_shares = UserProtocol::verify_signature_shares(
                    //     &ck,
                    //     &ts_keys.vk_shares,
                    //     &credential_request,
                    //     &signature_shares,
                    //     threshold,
                    // )
                    // .expect("Failed to verify signature shares");

                    // 3. Aggregate shares
                    let blindings = credential.get_blinding_factors();
                    UserProtocol::aggregate_shares(
                        &ck,
                        &verified_shares,
                        &blindings,
                        threshold,
                        &credential_request.h,
                    )
                })
            });
        }

        group.finish();
    }

    // ObtainContext benchmarks (master showing + nullifier + context credential request)
    {
        let mut group = c.benchmark_group("t_siris");
        group.sample_size(100);
        group.measurement_time(Duration::from_secs(25));

        for &(n_participants, threshold, l_attributes) in &configs {
            let id_suffix = format!("N{}_t{}_n{}", n_participants, threshold, l_attributes);

            // Setup
            let mut setup_rng = ark_std::test_rng();
            let (ck, _, ts_keys) =
                keygen::<Bls12_381>(threshold, n_participants, l_attributes, &mut setup_rng);

            // Create and issue a complete master credential
            let attributes: Vec<Fr> = (0..l_attributes)
                .map(|_| Fr::rand(&mut setup_rng))
                .collect();
            let (mut master_credential, master_request) =
                UserProtocol::request_credential(ck.clone(), Some(&attributes), &mut setup_rng)
                    .expect("Failed to create credential request");

            // Create signers
            let signers: Vec<_> = ts_keys
                .sk_shares
                .iter()
                .zip(ts_keys.vk_shares.iter())
                .map(|(sk_share, vk_share)| Signer::new(&ck, sk_share, vk_share))
                .collect();

            // Generate signature shares
            let signature_shares = UserProtocol::collect_signature_shares(
                &signers,
                &master_request,
                threshold,
                &mut setup_rng,
            )
            .expect("Failed to collect signature shares");

            // Process shares
            let verified_shares = UserProtocol::verify_signature_shares(
                &ck,
                &ts_keys.vk_shares,
                &master_request,
                &signature_shares,
                threshold,
            )
            .expect("Failed to verify signature shares");

            // Aggregate shares
            let blindings = master_credential.get_blinding_factors();
            let threshold_signature = UserProtocol::aggregate_shares(
                &ck,
                &verified_shares,
                &blindings,
                threshold,
                &master_request.h,
            )
            .expect("Failed to aggregate signature shares");

            // Attach signature to create complete master credential
            master_credential.attach_signature(threshold_signature);

            // Benchmark ObtainContext
            group.bench_function(BenchmarkId::new("obtain_context", id_suffix), |b| {
                b.iter(|| {
                    let mut bench_rng = ark_std::test_rng();

                    // 1. Show master credential (rerandomization + proof)
                    let (master_sig, _, _, _) =
                        UserProtocol::show(&master_credential, &mut bench_rng)
                            .expect("Failed to show master credential");

                    // 2. Generate nullifier (synthetic benchmark)
                    let sk = Fr::rand(&mut bench_rng);
                    let ctx = Fr::rand(&mut bench_rng);
                    let combined = sk + ctx;
                    let inv = combined.inverse().unwrap();
                    let g = G1Projective::rand(&mut bench_rng);
                    let nullifier = g.mul(inv).into_affine();

                    // 3. Create context credential request
                    let context_attrs: Vec<Fr> = (0..l_attributes)
                        .map(|_| Fr::rand(&mut bench_rng))
                        .collect();

                    let context_request = UserProtocol::request_credential(
                        ck.clone(),
                        Some(&context_attrs),
                        &mut bench_rng,
                    )
                    .expect("Failed to create context credential request");

                    (master_sig, nullifier, context_request)
                })
            });
        }

        group.finish();
    }

    // IssueContext benchmarks (master verification + nullifier verification + issuance)
    {
        let mut group = c.benchmark_group("t_siris");
        group.sample_size(100);
        group.measurement_time(Duration::from_secs(25));

        for &(n_participants, threshold, l_attributes) in &configs {
            let id_suffix = format!("N{}_t{}_n{}", n_participants, threshold, l_attributes);

            // Setup
            let mut setup_rng = ark_std::test_rng();
            let (ck, vk, ts_keys) =
                keygen::<Bls12_381>(threshold, n_participants, l_attributes, &mut setup_rng);

            // Create signers
            let signers: Vec<_> = ts_keys
                .sk_shares
                .iter()
                .zip(ts_keys.vk_shares.iter())
                .map(|(sk_share, vk_share)| Signer::new(&ck, sk_share, vk_share))
                .collect();

            // Create master credential
            let master_attrs: Vec<Fr> = (0..l_attributes)
                .map(|_| Fr::rand(&mut setup_rng))
                .collect();
            let (mut master_credential, master_request) =
                UserProtocol::request_credential(ck.clone(), Some(&master_attrs), &mut setup_rng)
                    .expect("Failed to create master credential request");

            // Issue master credential
            let signature_shares = UserProtocol::collect_signature_shares(
                &signers,
                &master_request,
                threshold,
                &mut setup_rng,
            )
            .expect("Failed to collect master signature shares");

            let verified_shares = UserProtocol::verify_signature_shares(
                &ck,
                &ts_keys.vk_shares,
                &master_request,
                &signature_shares,
                threshold,
            )
            .expect("Failed to verify master signature shares");

            let master_signature = UserProtocol::aggregate_shares(
                &ck,
                &verified_shares,
                &master_credential.get_blinding_factors(),
                threshold,
                &master_request.h,
            )
            .expect("Failed to aggregate master signature shares");

            master_credential.attach_signature(master_signature);

            // Show master credential
            let (master_sig, master_cm, master_cm_tilde, master_proof) =
                UserProtocol::show(&master_credential, &mut setup_rng)
                    .expect("Failed to show master credential");

            // Create context credential request
            let context_attrs: Vec<Fr> = (0..l_attributes)
                .map(|_| Fr::rand(&mut setup_rng))
                .collect();
            let (context_credential, context_request) =
                UserProtocol::request_credential(ck.clone(), Some(&context_attrs), &mut setup_rng)
                    .expect("Failed to create context credential request");

            // Generate synthetic nullifier
            let sk = Fr::rand(&mut setup_rng);
            let ctx = Fr::rand(&mut setup_rng);
            let combined = sk + ctx;
            let inv = combined.inverse().unwrap();
            let g = G1Projective::rand(&mut setup_rng);
            let nullifier = g.mul(inv).into_affine();

            // Benchmark IssueContext
            group.bench_function(BenchmarkId::new("issue_context", id_suffix), |b| {
                b.iter(|| {
                    let mut bench_rng = ark_std::test_rng();

                    // 1. Verify master credential
                    let master_valid = VerifierProtocol::verify(
                        &ck,
                        &vk,
                        &master_cm,
                        &master_cm_tilde,
                        &master_sig,
                        &master_proof,
                    )
                    .expect("Failed to verify master credential");
                    assert!(master_valid, "Master credential verification failed");

                    // 2. Verify nullifier (synthetic benchmark)
                    let check1 = g.mul(combined).mul(inv).into_affine() == g.into_affine();
                    let check2 = nullifier.mul(combined).into_affine() == g.into_affine();
                    assert!(check1 && check2, "Nullifier verification failed");

                    // 3. Issue signature shares
                    let sig_shares = signers
                        .iter()
                        .take(threshold)
                        .map(|signer| {
                            let sig = signer
                                .sign_share(
                                    &context_request.commitments,
                                    &context_request.proofs,
                                    &context_request.h,
                                    &mut bench_rng,
                                )
                                .expect("Failed to generate signature share");
                            (sig.party_index, sig)
                        })
                        .collect::<Vec<_>>();

                    // 4. Verify signature shares
                    let verified_shares = UserProtocol::verify_signature_shares(
                        &ck,
                        &ts_keys.vk_shares,
                        &context_request,
                        &sig_shares,
                        threshold,
                    )
                    .expect("Failed to verify signature shares");

                    // 5. Aggregate shares
                    let blindings = context_credential.get_blinding_factors();
                    UserProtocol::aggregate_shares(
                        &ck,
                        &verified_shares,
                        &blindings,
                        threshold,
                        &context_request.h,
                    )
                })
            });
        }

        group.finish();
    }

    // IssueContext benchmarks (master verification + nullifier verification + issuance)
    {
        let mut group = c.benchmark_group("t_siris");
        group.sample_size(100);
        group.measurement_time(Duration::from_secs(25));

        for &(n_participants, threshold, l_attributes) in &configs {
            let id_suffix = format!("N{}_t{}_n{}", n_participants, threshold, l_attributes);

            // Setup
            let mut setup_rng = ark_std::test_rng();
            let (ck, vk, ts_keys) =
                keygen::<Bls12_381>(threshold, n_participants, l_attributes, &mut setup_rng);

            // Create signers
            let signers: Vec<_> = ts_keys
                .sk_shares
                .iter()
                .zip(ts_keys.vk_shares.iter())
                .map(|(sk_share, vk_share)| Signer::new(&ck, sk_share, vk_share))
                .collect();

            // Create master credential
            let master_attrs: Vec<Fr> = (0..l_attributes)
                .map(|_| Fr::rand(&mut setup_rng))
                .collect();
            let (mut master_credential, master_request) =
                UserProtocol::request_credential(ck.clone(), Some(&master_attrs), &mut setup_rng)
                    .expect("Failed to create master credential request");

            // Issue master credential
            let verified_shares = UserProtocol::collect_signature_shares(
                &signers,
                &master_request,
                threshold,
                &mut setup_rng,
            )
            .expect("Failed to collect master signature shares");

            let master_signature = UserProtocol::aggregate_shares(
                &ck,
                &verified_shares,
                &master_credential.get_blinding_factors(),
                threshold,
                &master_request.h,
            )
            .expect("Failed to aggregate master signature shares");

            master_credential.attach_signature(master_signature);

            // Show master credential
            let (master_sig, master_cm, master_cm_tilde, master_proof) =
                UserProtocol::show(&master_credential, &mut setup_rng)
                    .expect("Failed to show master credential");

            // Create context credential request
            let context_attrs: Vec<Fr> = (0..l_attributes)
                .map(|_| Fr::rand(&mut setup_rng))
                .collect();
            let (context_credential, context_request) =
                UserProtocol::request_credential(ck.clone(), Some(&context_attrs), &mut setup_rng)
                    .expect("Failed to create context credential request");

            // Generate synthetic nullifier
            let sk = Fr::rand(&mut setup_rng);
            let ctx = Fr::rand(&mut setup_rng);
            let combined = sk + ctx;
            let inv = combined.inverse().unwrap();
            let g = G1Projective::rand(&mut setup_rng);
            let nullifier = g.mul(inv).into_affine();

            // Benchmark IssueContext
            group.bench_function(BenchmarkId::new("issue_context_no_zkp", id_suffix), |b| {
                b.iter(|| {
                    let mut bench_rng = ark_std::test_rng();

                    // 1. Verify master credential
                    let master_valid = VerifierProtocol::verify(
                        &ck,
                        &vk,
                        &master_cm,
                        &master_cm_tilde,
                        &master_sig,
                        &master_proof,
                    )
                    .expect("Failed to verify master credential");
                    assert!(master_valid, "Master credential verification failed");

                    // 2. Verify nullifier (synthetic benchmark)
                    let check1 = g.mul(combined).mul(inv).into_affine() == g.into_affine();
                    let check2 = nullifier.mul(combined).into_affine() == g.into_affine();
                    assert!(check1 && check2, "Nullifier verification failed");

                    // 3. Issue signature shares
                    let verified_shares = signers
                        .iter()
                        .take(threshold)
                        .map(|signer| {
                            let sig = signer
                                .sign_share_no_zkp_verify(
                                    &context_request.commitments,
                                    &context_request.proofs,
                                    &context_request.h,
                                    &mut bench_rng,
                                )
                                .expect("Failed to generate signature share");
                            (sig.party_index, sig)
                        })
                        .collect::<Vec<_>>();

                    // // 4. Verify signature shares
                    // let verified_shares = UserProtocol::verify_signature_shares(
                    //     &ck,
                    //     &ts_keys.vk_shares,
                    //     &context_request,
                    //     &sig_shares,
                    //     threshold,
                    // )
                    // .expect("Failed to verify signature shares");

                    // 5. Aggregate shares
                    let blindings = context_credential.get_blinding_factors();
                    UserProtocol::aggregate_shares(
                        &ck,
                        &verified_shares,
                        &blindings,
                        threshold,
                        &context_request.h,
                    )
                })
            });
        }

        group.finish();
    }

    // Show benchmark
    {
        let mut group = c.benchmark_group("t_siris");
        group.sample_size(100);
        group.measurement_time(Duration::from_secs(25));

        for &(n_participants, threshold, l_attributes) in &configs {
            let id_suffix = format!("N{}_t{}_n{}", n_participants, threshold, l_attributes);

            // Setup - create one complete credential
            let mut setup_rng = ark_std::test_rng();
            let (ck, _, ts_keys) =
                keygen::<Bls12_381>(threshold, n_participants, l_attributes, &mut setup_rng);

            // Create and issue a credential
            let attributes: Vec<Fr> = (0..l_attributes)
                .map(|_| Fr::rand(&mut setup_rng))
                .collect();

            let (mut credential, credential_request) =
                UserProtocol::request_credential(ck.clone(), Some(&attributes), &mut setup_rng)
                    .expect("Failed to create credential request");

            // Create signers
            let signers: Vec<_> = ts_keys
                .sk_shares
                .iter()
                .zip(ts_keys.vk_shares.iter())
                .map(|(sk_share, vk_share)| Signer::new(&ck, sk_share, vk_share))
                .collect();

            // Get signature shares
            let signature_shares = UserProtocol::collect_signature_shares(
                &signers,
                &credential_request,
                threshold,
                &mut setup_rng,
            )
            .expect("Failed to collect signature shares");

            // Verify and aggregate shares
            let verified_shares = UserProtocol::verify_signature_shares(
                &ck,
                &ts_keys.vk_shares,
                &credential_request,
                &signature_shares,
                threshold,
            )
            .expect("Failed to verify signature shares");

            let threshold_signature = UserProtocol::aggregate_shares(
                &ck,
                &verified_shares,
                &credential.get_blinding_factors(),
                threshold,
                &credential_request.h,
            )
            .expect("Failed to aggregate signature shares");

            // Attach signature to credential
            credential.attach_signature(threshold_signature);

            // Benchmark the Show operation
            group.bench_function(BenchmarkId::new("show", id_suffix), |b| {
                b.iter(|| {
                    let mut bench_rng = ark_std::test_rng();
                    UserProtocol::show(&credential, &mut bench_rng)
                })
            });
        }

        group.finish();
    }

    // Verify benchmark
    {
        let mut group = c.benchmark_group("t_siris");
        group.sample_size(100);
        group.measurement_time(Duration::from_secs(25));

        for &(n_participants, threshold, l_attributes) in &configs {
            let id_suffix = format!("N{}_t{}_n{}", n_participants, threshold, l_attributes);

            // Setup - create one complete credential
            let mut setup_rng = ark_std::test_rng();
            let (ck, vk, ts_keys) =
                keygen::<Bls12_381>(threshold, n_participants, l_attributes, &mut setup_rng);

            // Create and issue a credential
            let attributes: Vec<Fr> = (0..l_attributes)
                .map(|_| Fr::rand(&mut setup_rng))
                .collect();

            let (mut credential, credential_request) =
                UserProtocol::request_credential(ck.clone(), Some(&attributes), &mut setup_rng)
                    .expect("Failed to create credential request");

            // Create signers and issue credential
            let signers: Vec<_> = ts_keys
                .sk_shares
                .iter()
                .zip(ts_keys.vk_shares.iter())
                .map(|(sk_share, vk_share)| Signer::new(&ck, sk_share, vk_share))
                .collect();

            // Get signature shares
            let signature_shares = UserProtocol::collect_signature_shares(
                &signers,
                &credential_request,
                threshold,
                &mut setup_rng,
            )
            .expect("Failed to collect signature shares");

            // Verify and aggregate shares
            let verified_shares = UserProtocol::verify_signature_shares(
                &ck,
                &ts_keys.vk_shares,
                &credential_request,
                &signature_shares,
                threshold,
            )
            .expect("Failed to verify signature shares");

            let threshold_signature = UserProtocol::aggregate_shares(
                &ck,
                &verified_shares,
                &credential.get_blinding_factors(),
                threshold,
                &credential_request.h,
            )
            .expect("Failed to aggregate signature shares");

            // Attach signature to credential
            credential.attach_signature(threshold_signature);

            // Create a presentation to verify
            let (test_sig, test_cm, test_cm_tilde, test_proof) =
                UserProtocol::show(&credential, &mut setup_rng)
                    .expect("Failed to generate presentation");

            // Benchmark just the verification
            group.bench_function(BenchmarkId::new("verify", id_suffix), |b| {
                b.iter(|| {
                    VerifierProtocol::verify(
                        &ck,
                        &vk,
                        &test_cm,
                        &test_cm_tilde,
                        &test_sig,
                        &test_proof,
                    )
                    .expect("Failed to verify credential")
                })
            });
        }

        group.finish();
    }
}

criterion_group!(
    name = benches;
    config = Criterion::default();
    targets = benchmark_t_siris
);
criterion_main!(benches);
