// ChaCha20 (djb / ietf / X) and HChaCha20: whole vs split-at-block encryption using the
// returned counter, keystream (NULL plain text) mode, involution, and XChaCha = HChaCha+djb.
// Layout: key[32] | nonce[24] | ctr u64 | split byte | message (rest)
#include "monocypher.h"
#include "fuzz_common.h"

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
	fz_reader r; fz_init(&r, data, size);
	uint8_t key[32];   fz_fixed(&r, key, 32);
	uint8_t nonce[24]; fz_fixed(&r, nonce, 24);
	uint64_t ctr = fz_u64(&r);
	uint8_t split = fz_u8(&r);
	size_t n;
	uint8_t *msg = fz_rest(&r, &n);
	uint8_t *a = fz_alloc(n), *b = fz_alloc(n), *ks = fz_alloc(n), *back = fz_alloc(n);
	// Split point on a 64-byte block boundary (continuing needs whole blocks).
	size_t s = 64 * (split % (n / 64 + 1));
	if (s > n) s = n;

	// doc/crypto_chacha20_djb.3monocypher: "Make sure the counters never wrap around."
	// The ietf counter is 32 bits, the djb / X counters 64 bits; a variant whose counter
	// would wrap over this message is API misuse and is not called.
	uint64_t nblocks = (n + 63) / 64;
	int wrap64 = ctr > UINT64_MAX - nblocks;
	int wrap32 = (uint64_t)(uint32_t)ctr + nblocks > UINT32_MAX;

	for (int v = 0; v < 3; v++) {
		uint64_t c_whole, c1, c2, c_ks;
		if (v == 1 ? wrap32 : wrap64) continue;
		switch (v) {
		case 0:
			c_whole = crypto_chacha20_djb(a, msg, n, key, nonce, ctr);
			c1 = crypto_chacha20_djb(b, msg, s, key, nonce, ctr);
			c2 = crypto_chacha20_djb(b ? b + s : NULL, msg ? msg + s : NULL, n - s, key, nonce, c1);
			c_ks = crypto_chacha20_djb(ks, NULL, n, key, nonce, ctr);
			crypto_chacha20_djb(back, a, n, key, nonce, ctr);
			break;
		case 1: {
			uint32_t c32 = (uint32_t)ctr;
			c_whole = crypto_chacha20_ietf(a, msg, n, key, nonce, c32);
			c1 = crypto_chacha20_ietf(b, msg, s, key, nonce, c32);
			c2 = crypto_chacha20_ietf(b ? b + s : NULL, msg ? msg + s : NULL, n - s, key, nonce, (uint32_t)c1);
			c_ks = crypto_chacha20_ietf(ks, NULL, n, key, nonce, c32);
			crypto_chacha20_ietf(back, a, n, key, nonce, c32);
			break; }
		default: {
			c_whole = crypto_chacha20_x(a, msg, n, key, nonce, ctr);
			c1 = crypto_chacha20_x(b, msg, s, key, nonce, ctr);
			c2 = crypto_chacha20_x(b ? b + s : NULL, msg ? msg + s : NULL, n - s, key, nonce, c1);
			c_ks = crypto_chacha20_x(ks, NULL, n, key, nonce, ctr);
			crypto_chacha20_x(back, a, n, key, nonce, ctr);
			// XChaCha20 is HChaCha20(key, nonce[0..16]) then ChaCha20-djb with nonce[16..24].
			uint8_t sub[32];
			crypto_chacha20_h(sub, key, nonce);
			uint8_t *d = fz_alloc(n);
			uint64_t cd = crypto_chacha20_djb(d, msg, n, sub, nonce + 16, ctr);
			FZ_CHECK(cd == c_whole);
			FZ_CHECK(n == 0 || memcmp(d, a, n) == 0);
			free(d);
			break; }
		}
		FZ_CHECK(c_whole == c2);
		FZ_CHECK(c_whole == c_ks);
		for (size_t i = 0; i < n; i++) {
			FZ_CHECK(a[i] == b[i]);
			FZ_CHECK((uint8_t)(msg[i] ^ ks[i]) == a[i]);
			FZ_CHECK(back[i] == msg[i]);
		}
	}
	free(msg); free(a); free(b); free(ks); free(back);
	return 0;
}
