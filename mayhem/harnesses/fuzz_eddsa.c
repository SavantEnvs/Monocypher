// EdDSA (Curve25519 + BLAKE2b): signature verification of attacker-supplied
// signature / public key / message (point decompression, scalar range checks, double
// scalar multiplication), plus key generation, signing and the scalar helpers.
// Layout: sig[64] | pk[32] | seed[32] | a[32] | b[32] | c[32] | message (rest)
#include "monocypher.h"
#include "fuzz_common.h"

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
	fz_reader r; fz_init(&r, data, size);
	uint8_t sig[64]; fz_fixed(&r, sig, 64);
	uint8_t pk[32];  fz_fixed(&r, pk, 32);
	uint8_t seed[32]; fz_fixed(&r, seed, 32);
	uint8_t a[32], b[32], c[32];
	fz_fixed(&r, a, 32); fz_fixed(&r, b, 32); fz_fixed(&r, c, 32);
	size_t n;
	uint8_t *msg = fz_rest(&r, &n);

	// Untrusted verification.
	(void)crypto_eddsa_check(sig, pk, msg, n);
	(void)crypto_eddsa_check_equation(sig, pk, a);
	uint8_t x[32];
	crypto_eddsa_to_x25519(x, pk);

	// Key pair derivation matches its definition: pk = [trim(BLAKE2b(seed)[0..32])]B.
	uint8_t seed_copy[32]; memcpy(seed_copy, seed, 32);
	uint8_t sk[64], pub[32], h[64], t[32], p2[32];
	crypto_eddsa_key_pair(sk, pub, seed_copy);
	crypto_blake2b(h, 64, seed, 32);
	crypto_eddsa_trim_scalar(t, h);
	crypto_eddsa_scalarbase(p2, t);
	FZ_CHECK(memcmp(p2, pub, 32) == 0);
	FZ_CHECK(memcmp(sk, seed, 32) == 0 && memcmp(sk + 32, pub, 32) == 0);

	// Sign / verify round trip; a tampered signature or message is rejected.
	uint8_t s2[64];
	crypto_eddsa_sign(s2, sk, msg, n);
	FZ_CHECK(crypto_eddsa_check(s2, pub, msg, n) == 0);
	uint8_t bad[64]; memcpy(bad, s2, 64);
	bad[a[0] % 64] ^= (uint8_t)(1u << (a[1] % 8));
	FZ_CHECK(crypto_eddsa_check(bad, pub, msg, n) != 0);
	if (n > 0) {
		msg[b[0] % n] ^= (uint8_t)(1u << (b[1] % 8));
		FZ_CHECK(crypto_eddsa_check(s2, pub, msg, n) != 0);
	}

	// Scalar arithmetic mod L: mul_add(a,b,c) == (a*b mod L) + c mod L.
	uint8_t zero[32] = {0}, one[32] = {1}, r1[32], r2[32], r3[32], red[32];
	crypto_eddsa_mul_add(r1, a, b, zero);
	crypto_eddsa_mul_add(r2, one, r1, c);
	crypto_eddsa_mul_add(r3, a, b, c);
	FZ_CHECK(memcmp(r2, r3, 32) == 0);
	// reduce(x) == x*1 + 0 mod L for a 64-byte x whose top half is zero.
	uint8_t wide[64] = {0}; memcpy(wide, a, 32);
	crypto_eddsa_reduce(red, wide);
	crypto_eddsa_mul_add(r1, a, one, zero);
	FZ_CHECK(memcmp(red, r1, 32) == 0);
	crypto_eddsa_reduce(red, sig);
	crypto_eddsa_scalarbase(p2, c);

	free(msg);
	return 0;
}
