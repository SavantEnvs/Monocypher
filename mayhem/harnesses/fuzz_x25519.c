// X25519 key exchange on attacker-supplied public keys, plus the Montgomery-ladder
// helpers (inverse, dirty keys, EdDSA conversion) and Elligator 2 map / reverse map.
// Layout: op byte | sk1[32] | sk2[32] | pk[32] | hidden[32] | seed[32] | tweak byte
// The op byte selects which group of checks runs (bit per group; 0 = all). The curve code
// is constant time, so without this dispatch every input has identical coverage and the
// corpus never grows past one entry.
#include "monocypher.h"
#include "fuzz_common.h"

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
	fz_reader r; fz_init(&r, data, size);
	uint8_t op = fz_u8(&r);
	if (op == 0) op = 0xff;
	uint8_t sk1[32], sk2[32], pk[32], hidden[32], seed[32];
	fz_fixed(&r, sk1, 32); fz_fixed(&r, sk2, 32); fz_fixed(&r, pk, 32);
	fz_fixed(&r, hidden, 32); fz_fixed(&r, seed, 32);
	uint8_t tweak = fz_u8(&r);

	uint8_t out[32], out2[32], pub1[32], pub2[32], base[32] = {9};

	// Untrusted peer key.
	if (op & 0x01) {
		crypto_x25519(out, sk1, pk);
		crypto_x25519_inverse(out2, sk1, pk);
	}

	// Public key = scalar * base point (needed by several groups below).
	crypto_x25519_public_key(pub1, sk1);

	// Both public-key functions agree with the ladder on the base point.
	if (op & 0x02) {
		crypto_x25519(out, sk1, base);
		FZ_CHECK(memcmp(out, pub1, 32) == 0);
		crypto_x25519_public_key_small(out, sk1);
		FZ_CHECK(memcmp(out, pub1, 32) == 0);
	}

	// Diffie-Hellman commutes; inverse undoes the ladder on prime-order points.
	if (op & 0x04) {
		crypto_x25519_public_key(pub2, sk2);
		crypto_x25519(out, sk1, pub2);
		crypto_x25519(out2, sk2, pub1);
		FZ_CHECK(memcmp(out, out2, 32) == 0);
		crypto_x25519_inverse(out2, sk1, out);
		FZ_CHECK(memcmp(out2, pub2, 32) == 0);
	}

	// Dirty keys: small and fast agree; clearing the low 3 bits gives the clean key.
	if (op & 0x08) {
		uint8_t d1[32], d2[32], clean[32];
		crypto_x25519_dirty_small(d1, sk1);
		crypto_x25519_dirty_fast(d2, sk1);
		FZ_CHECK(memcmp(d1, d2, 32) == 0);
		memcpy(clean, sk1, 32); clean[0] &= 248;
		crypto_x25519_dirty_fast(d1, clean);
		FZ_CHECK(memcmp(d1, pub1, 32) == 0);
	}

	// Montgomery u -> Edwards y -> Montgomery u round trip.
	if (op & 0x10) {
		uint8_t ed[32];
		crypto_x25519_to_eddsa(ed, pk);
		crypto_x25519_to_eddsa(ed, pub1);
		crypto_eddsa_to_x25519(out, ed);
		FZ_CHECK(memcmp(out, pub1, 32) == 0);
	}

	// Elligator: map arbitrary representatives; reverse-map then map is the identity.
	uint8_t rep[32];
	if (op & 0x20) {
		uint8_t curve[32];
		crypto_elligator_map(curve, hidden);
		if (crypto_elligator_rev(rep, curve, tweak) == 0) {
			crypto_elligator_map(out, rep);
			FZ_CHECK(memcmp(out, curve, 32) == 0);
		}
	}
	// Reverse map of an attacker-chosen point (may be non-canonical, so no equality check).
	if (op & 0x40) {
		if (crypto_elligator_rev(rep, pk, tweak) == 0)
			crypto_elligator_map(out, rep);
	}
	if (op & 0x80) {
		uint8_t hsk[32];
		crypto_elligator_key_pair(rep, hsk, seed);
		crypto_elligator_map(out, rep);
		crypto_x25519_dirty_fast(out2, hsk);
		FZ_CHECK(memcmp(out, out2, 32) == 0);
	}
	return 0;
}
