use ark_bls12_381::{Bls12_381, Fr};
use ark_ff::UniformRand;
use criterion::{criterion_group, criterion_main, BenchmarkId, Criterion};
use std::time::Duration;
use t_siris::credential::Credential;
use t_siris::credential::CredentialState;
use t_siris::keygen::keygen;
use t_siris::protocol::{UserProtocol, VerifierProtocol};
use t_siris::signature::PartialSignature;
use t_siris::signer::Signer;

/// Benchmark function for threshold PS protocol
fn benchmark_t_utt(c: &mut Criterion) {
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
        // (64, 33, 128),
    ];

    // TokenRequest benchmarks
    {
        let mut group = c.benchmark_group("t_utt");
        group
            .sample_size(100)
            .measurement_time(Duration::from_secs(20));

        for &(n_participants, threshold, l_attributes) in &configs {
            let id_suffix = format!("N{}_t{}_n{}", n_participants, threshold, l_attributes);

            // Setup for this specific configuration
            let mut setup_rng = ark_std::test_rng();
            let (ck, _, _) =
                keygen::<Bls12_381>(threshold, n_participants, l_attributes, &mut setup_rng);

            // Create attributes specific to this configuration
            let attributes: Vec<Fr> = (0..l_attributes)
                .map(|_| Fr::rand(&mut setup_rng))
                .collect();

            // Create credential for this configuration
            let mut credential = Credential::new(ck.clone(), Some(&attributes), &mut setup_rng);

            // Only benchmark the compute_commitments_per_m function
            group.bench_function(BenchmarkId::new("token_request", id_suffix), |b| {
                b.iter(|| {
                    // Need a fresh RNG for each iteration to ensure randomness
                    let mut bench_rng = ark_std::test_rng();

                    // Reset credential state for each iteration
                    credential.state = CredentialState::Initialized;
                    credential.blindings = Vec::new(); // Important to clear this

                    // Only measure the commitment generation
                    credential.compute_commitments_per_m(&mut bench_rng)
                })
            });
        }

        group.finish(); // Only finish the group once after all benchmarks
    }

    // tIssue benchmarks
    {
        let mut group = c.benchmark_group("t_utt");
        group
            .sample_size(100)
            .measurement_time(Duration::from_secs(20));

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
            let (_, credential_request) =
                UserProtocol::request_credential(ck.clone(), Some(&attributes), &mut setup_rng)
                    .expect("Failed to create credential request");

            // Benchmark just the signing operation
            group.bench_function(BenchmarkId::new("t_issue", id_suffix), |b| {
                b.iter(|| {
                    // We'll measure the time it takes for threshold issuers to sign
                    // This collects signature shares from threshold signers
                    let signature_shares = signers
                        .iter()
                        .take(threshold) // Only use the threshold number of signers
                        .map(|signer| {
                            signer
                                .sign_share(
                                    &credential_request.commitments,
                                    &credential_request.proofs,
                                    &credential_request.h,
                                    &mut setup_rng,
                                )
                                .expect("Failed to generate signature share")
                        })
                        .collect::<Vec<_>>();

                    signature_shares
                })
            });
        }

        group.finish();
    }

    {
        let mut group = c.benchmark_group("t_utt");
        group
            .sample_size(100)
            .measurement_time(Duration::from_secs(20));

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
            let (_, credential_request) =
                UserProtocol::request_credential(ck.clone(), Some(&attributes), &mut setup_rng)
                    .expect("Failed to create credential request");

            // Benchmark just the signing operation
            group.bench_function(BenchmarkId::new("t_issue_no_verify", id_suffix), |b| {
                b.iter(|| {
                    // We'll measure the time it takes for threshold issuers to sign
                    // This collects signature shares from threshold signers
                    let signature_shares = signers
                        .iter()
                        .take(threshold) // Only use the threshold number of signers
                        .map(|signer| {
                            signer
                                .sign_share_no_zkp_verify(
                                    &credential_request.commitments,
                                    &credential_request.proofs,
                                    &credential_request.h,
                                    &mut setup_rng,
                                )
                                .expect("Failed to generate signature share")
                        })
                        .collect::<Vec<_>>();

                    signature_shares
                })
            });
        }

        group.finish();
    }

    // aggregate_verify benchmarks
    {
        let mut group = c.benchmark_group("t_utt");
        group
            .sample_size(100)
            .measurement_time(Duration::from_secs(20));

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

            // Create credential and request
            let attributes: Vec<Fr> = (0..l_attributes)
                .map(|_| Fr::rand(&mut setup_rng))
                .collect();
            let (credential, credential_request) =
                UserProtocol::request_credential(ck.clone(), Some(&attributes), &mut setup_rng)
                    .expect("Failed to create credential request");

            // Generate signature shares
            let signature_shares: Vec<(usize, PartialSignature<Bls12_381>)> = signers
                .iter()
                .take(threshold)
                .map(|signer| {
                    let sig = signer
                        .sign_share(
                            &credential_request.commitments,
                            &credential_request.proofs,
                            &credential_request.h,
                            &mut setup_rng,
                        )
                        .expect("Failed to generate signature share");
                    (sig.party_index, sig)
                })
                .collect();

            // Benchmark user verification and aggregation
            group.bench_function(BenchmarkId::new("aggregate_with_verify", id_suffix), |b| {
                b.iter(|| {
                    // Verify signature shares
                    let verified_shares = UserProtocol::verify_signature_shares(
                        &ck,
                        &ts_keys.vk_shares,
                        &credential_request,
                        &signature_shares,
                        threshold,
                    )
                    .expect("Failed to verify signature shares");

                    // Aggregate shares
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

    // aggregate_no_verify benchmarks
    {
        let mut group = c.benchmark_group("t_utt");
        group
            .sample_size(100)
            .measurement_time(Duration::from_secs(20));

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

            // Create credential and request
            let attributes: Vec<Fr> = (0..l_attributes)
                .map(|_| Fr::rand(&mut setup_rng))
                .collect();
            let (credential, credential_request) =
                UserProtocol::request_credential(ck.clone(), Some(&attributes), &mut setup_rng)
                    .expect("Failed to create credential request");

            // Generate signature shares
            let signature_shares: Vec<(usize, PartialSignature<Bls12_381>)> = signers
                .iter()
                .take(threshold)
                .map(|signer| {
                    let sig = signer
                        .sign_share(
                            &credential_request.commitments,
                            &credential_request.proofs,
                            &credential_request.h,
                            &mut setup_rng,
                        )
                        .expect("Failed to generate signature share");
                    (sig.party_index, sig)
                })
                .collect();

            // Verify signature shares
            let verified_shares = UserProtocol::verify_signature_shares(
                &ck,
                &ts_keys.vk_shares,
                &credential_request,
                &signature_shares,
                threshold,
            )
            .expect("Failed to verify signature shares");

            // Benchmark user verification and aggregation
            group.bench_function(BenchmarkId::new("aggregate_no_verify", id_suffix), |b| {
                b.iter(|| {
                    // Aggregate shares
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

    {
        let mut group = c.benchmark_group("t_utt");
        group
            .sample_size(100)
            .measurement_time(Duration::from_secs(20));

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

            // Create credential and request
            let attributes: Vec<Fr> = (0..l_attributes)
                .map(|_| Fr::rand(&mut setup_rng))
                .collect();
            let (mut credential, credential_request) =
                UserProtocol::request_credential(ck.clone(), Some(&attributes), &mut setup_rng)
                    .expect("Failed to create credential request");

            // Generate signature shares
            let signature_shares: Vec<(usize, PartialSignature<Bls12_381>)> = signers
                .iter()
                .take(threshold)
                .map(|signer| {
                    let sig = signer
                        .sign_share(
                            &credential_request.commitments,
                            &credential_request.proofs,
                            &credential_request.h,
                            &mut setup_rng,
                        )
                        .expect("Failed to generate signature share");
                    (sig.party_index, sig)
                })
                .collect();

            // Verify signature shares
            let verified_shares = UserProtocol::verify_signature_shares(
                &ck,
                &ts_keys.vk_shares,
                &credential_request,
                &signature_shares,
                threshold,
            )
            .expect("Failed to verify signature shares");

            // Aggregate shares
            let blindings = credential.get_blinding_factors();
            let threshold_signature = UserProtocol::aggregate_shares(
                &ck,
                &verified_shares,
                &blindings,
                threshold,
                &credential_request.h,
            )
            .expect("Failed to aggregate signature shares");

            // Attach signature to credential
            credential.attach_signature(threshold_signature);

            // Now benchmark only the show/prove function
            group.bench_function(BenchmarkId::new("prove", id_suffix), |b| {
                b.iter(|| {
                    let mut bench_rng = ark_std::test_rng();
                    // Only benchmark the show function which generates the presentation
                    UserProtocol::show(&credential, &mut bench_rng)
                })
            });
        }

        group.finish();
    }

    // Verify benchmarks
    {
        let mut group = c.benchmark_group("t_utt");
        group
            .sample_size(100)
            .measurement_time(Duration::from_secs(20));

        for &(n_participants, threshold, l_attributes) in &configs {
            let id_suffix = format!("N{}_t{}_n{}", n_participants, threshold, l_attributes);

            // Complete setup outside the benchmark
            let mut setup_rng = ark_std::test_rng();

            // Setup keys and parameters
            let (ck, vk, ts_keys) =
                keygen::<Bls12_381>(threshold, n_participants, l_attributes, &mut setup_rng);

            // Create signers
            let signers: Vec<_> = ts_keys
                .sk_shares
                .iter()
                .zip(ts_keys.vk_shares.iter())
                .map(|(sk_share, vk_share)| Signer::new(&ck, sk_share, vk_share))
                .collect();

            // Create credential and request
            let attributes: Vec<Fr> = (0..l_attributes)
                .map(|_| Fr::rand(&mut setup_rng))
                .collect();
            let (mut credential, credential_request) =
                UserProtocol::request_credential(ck.clone(), Some(&attributes), &mut setup_rng)
                    .expect("Failed to create credential request");

            // Generate signature shares
            let signature_shares = UserProtocol::collect_signature_shares(
                &signers,
                &credential_request,
                threshold,
                &mut setup_rng,
            )
            .expect("Failed to collect signature shares");

            // Process signature shares
            let verified_shares = UserProtocol::verify_signature_shares(
                &ck,
                &ts_keys.vk_shares,
                &credential_request,
                &signature_shares,
                threshold,
            )
            .expect("Failed to verify signature shares");

            // Aggregate shares
            let blindings = credential.get_blinding_factors();
            let threshold_signature = UserProtocol::aggregate_shares(
                &ck,
                &verified_shares,
                &blindings,
                threshold,
                &credential_request.h,
            )
            .expect("Failed to aggregate signature shares");

            // Attach signature to credential
            credential.attach_signature(threshold_signature);

            // Optional: Verify once that our setup is working
            let (test_sig, test_cm, test_cm_tilde, test_proof) =
                UserProtocol::show(&credential, &mut setup_rng)
                    .expect("Failed to generate presentation");

            let test_result = VerifierProtocol::verify(
                &ck,
                &vk,
                &test_cm,
                &test_cm_tilde,
                &test_sig,
                &test_proof,
            )
            .expect("Failed to verify credential");

            assert!(
                test_result,
                "Credential verification must succeed before benchmarking"
            );

            // Benchmark only the verification
            group.bench_function(BenchmarkId::new("tverify", id_suffix), |b| {
                b.iter_with_setup(
                    // Setup generates a fresh presentation each time
                    || {
                        let mut rng = ark_std::test_rng();
                        UserProtocol::show(&credential, &mut rng)
                            .expect("Failed to generate presentation")
                    },
                    // Use the fresh presentation for verification
                    |(randomized_sig, commitment, commitment_tilde, proof)| {
                        VerifierProtocol::verify(
                            &ck,
                            &vk,
                            &commitment,
                            &commitment_tilde,
                            &randomized_sig,
                            &proof,
                        )
                        .expect("Failed to verify credential")
                    },
                )
            });
        }

        group.finish();
    }
}

criterion_group!(
    name = benches;
    config = Criterion::default();
    targets = benchmark_t_utt
);
criterion_main!(benches);
