// Authenticated encryption (XChaCha20-Poly1305 and the streaming djb/ietf/X contexts).
// 1. crypto_aead_unlock on attacker-supplied mac + cipher text (must not touch memory
//    out of bounds; on success the plain text must re-lock to the same mac + cipher text).
// 2. lock -> unlock round trip; a flipped mac bit must be rejected.
// 3. streaming crypto_aead_write / crypto_aead_read over fuzz-sized messages.
// Layout: key[32] | nonce[24] | mac[16] | mode | ad_len | 4 msg sizes | ad | text (rest)
#include "monocypher.h"
#include "fuzz_common.h"

static void init_ctx(crypto_aead_ctx *ctx, int mode, const uint8_t key[32], const uint8_t nonce[24])
{
	switch (mode) {
	case 0:  crypto_aead_init_x   (ctx, key, nonce); break;
	case 1:  crypto_aead_init_djb (ctx, key, nonce); break;
	default: crypto_aead_init_ietf(ctx, key, nonce); break;
	}
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
	fz_reader r; fz_init(&r, data, size);
	uint8_t key[32];   fz_fixed(&r, key, 32);
	uint8_t nonce[24]; fz_fixed(&r, nonce, 24);
	uint8_t mac[16];   fz_fixed(&r, mac, 16);
	int mode = fz_u8(&r) % 3;
	size_t ad_req = fz_u8(&r);
	uint8_t sizes[4];  fz_fixed(&r, sizes, 4);
	size_t ad_size, n;
	uint8_t *ad   = fz_slice(&r, ad_req, &ad_size);
	uint8_t *text = fz_rest(&r, &n);
	uint8_t *pt = fz_alloc(n), *ct = fz_alloc(n), *pt2 = fz_alloc(n);
	uint8_t mac2[16];

	// 1. Attacker-controlled message.
	if (crypto_aead_unlock(pt, mac, key, nonce, ad, ad_size, text, n) == 0) {
		crypto_aead_lock(ct, mac2, key, nonce, ad, ad_size, pt, n);
		FZ_CHECK(memcmp(mac2, mac, 16) == 0);
		FZ_CHECK(n == 0 || memcmp(ct, text, n) == 0);
	}

	// 2. Round trip, then forgery rejection.
	crypto_aead_lock(ct, mac2, key, nonce, ad, ad_size, text, n);
	FZ_CHECK(crypto_aead_unlock(pt2, mac2, key, nonce, ad, ad_size, ct, n) == 0);
	FZ_CHECK(n == 0 || memcmp(pt2, text, n) == 0);
	mac2[sizes[0] % 16] ^= (uint8_t)(1u << (sizes[1] % 8));
	FZ_CHECK(crypto_aead_unlock(pt2, mac2, key, nonce, ad, ad_size, ct, n) != 0);

	// 3. Streaming: the text is cut into messages; each is written with the writer ctx
	//    and read back with a reader ctx. Also try reading the raw input as a message.
	crypto_aead_ctx w, rd, raw;
	init_ctx(&w, mode, key, nonce);
	init_ctx(&rd, mode, key, nonce);
	init_ctx(&raw, mode, key, nonce);
	(void)crypto_aead_read(&raw, pt, mac, ad, ad_size, text, n);
	size_t off = 0, i = 0;
	do {
		size_t s = sizes[i % 4];
		if (s > n - off || i >= 64) s = n - off;
		uint8_t m[16];
		crypto_aead_write(&w, ct ? ct + off : NULL, m, ad, ad_size, text ? text + off : NULL, s);
		FZ_CHECK(crypto_aead_read(&rd, pt2 ? pt2 + off : NULL, m, ad, ad_size, ct ? ct + off : NULL, s) == 0);
		FZ_CHECK(s == 0 || memcmp(pt2 + off, text + off, s) == 0);
		off += s; i++;
	} while (off < n);
	FZ_CHECK(memcmp(&w, &rd, sizeof w) == 0);

	free(ad); free(text); free(pt); free(ct); free(pt2);
	return 0;
}
