// Ed25519 (SHA-512, RFC 8032) from src/optional/monocypher-ed25519.c: verification of
// attacker-supplied signatures (plain and pre-hashed), and sign/verify round trips.
// Layout: sig[64] | pk[32] | seed[32] | prehash[64] | flip byte | message (rest)
#include "monocypher.h"
#include "monocypher-ed25519.h"
#include "fuzz_common.h"

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
	fz_reader r; fz_init(&r, data, size);
	uint8_t sig[64]; fz_fixed(&r, sig, 64);
	uint8_t pk[32];  fz_fixed(&r, pk, 32);
	uint8_t seed[32]; fz_fixed(&r, seed, 32);
	uint8_t ph[64];  fz_fixed(&r, ph, 64);
	uint8_t flip = fz_u8(&r);
	size_t n;
	uint8_t *msg = fz_rest(&r, &n);

	(void)crypto_ed25519_check(sig, pk, msg, n);
	(void)crypto_ed25519_ph_check(sig, pk, ph);

	uint8_t seed_copy[32]; memcpy(seed_copy, seed, 32);
	uint8_t sk[64], pub[32], h[64], t[32], p2[32];
	crypto_ed25519_key_pair(sk, pub, seed_copy);
	// RFC 8032: pk = [clamp(SHA-512(seed)[0..32])]B.
	crypto_sha512(h, seed, 32);
	crypto_eddsa_trim_scalar(t, h);
	crypto_eddsa_scalarbase(p2, t);
	FZ_CHECK(memcmp(p2, pub, 32) == 0);

	uint8_t s2[64], bad[64];
	crypto_ed25519_sign(s2, sk, msg, n);
	FZ_CHECK(crypto_ed25519_check(s2, pub, msg, n) == 0);
	memcpy(bad, s2, 64);
	bad[flip % 64] ^= (uint8_t)(1u << (flip % 8));
	FZ_CHECK(crypto_ed25519_check(bad, pub, msg, n) != 0);

	crypto_ed25519_ph_sign(s2, sk, ph);
	FZ_CHECK(crypto_ed25519_ph_check(s2, pub, ph) == 0);
	// The pre-hashed variant is domain-separated from the plain one.
	FZ_CHECK(crypto_ed25519_check(s2, pub, ph, 64) != 0);
	ph[flip % 64] ^= 1;
	FZ_CHECK(crypto_ed25519_ph_check(s2, pub, ph) != 0);

	free(msg);
	return 0;
}
