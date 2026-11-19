// SHA-512, HMAC-SHA-512 and HKDF-SHA-512 from src/optional/monocypher-ed25519.c:
// one-shot vs incremental (fuzz-chosen chunks), HKDF = extract + expand, and
// expand output prefixes agree across lengths.
// Layout: key_len | salt_len | info_len | okm u16 | 4 chunk sizes | key | salt | info | message
#include "monocypher.h"
#include "monocypher-ed25519.h"
#include "fuzz_common.h"

static void upd(void *ctx, const uint8_t *m, size_t n) { crypto_sha512_update((crypto_sha512_ctx *)ctx, m, n); }
static void hupd(void *ctx, const uint8_t *m, size_t n) { crypto_sha512_hmac_update((crypto_sha512_hmac_ctx *)ctx, m, n); }

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
	fz_reader r; fz_init(&r, data, size);
	size_t kl = fz_u8(&r), sl = fz_u8(&r), il = fz_u8(&r);
	size_t okm_size = fz_u16(&r) % 1100;
	uint8_t sizes[4]; fz_fixed(&r, sizes, 4);
	size_t key_size, salt_size, info_size, n;
	uint8_t *key  = fz_slice(&r, kl, &key_size);
	uint8_t *salt = fz_slice(&r, sl, &salt_size);
	uint8_t *info = fz_slice(&r, il, &info_size);
	uint8_t *msg  = fz_rest(&r, &n);
	uint8_t h1[64], h2[64];

	crypto_sha512(h1, msg, n);
	crypto_sha512_ctx c;
	crypto_sha512_init(&c);
	fz_chunked(&c, upd, msg, n, sizes, 4);
	crypto_sha512_final(&c, h2);
	FZ_CHECK(memcmp(h1, h2, 64) == 0);

	crypto_sha512_hmac(h1, key, key_size, msg, n);
	crypto_sha512_hmac_ctx hc;
	crypto_sha512_hmac_init(&hc, key, key_size);
	fz_chunked(&hc, hupd, msg, n, sizes + 1, 3);
	crypto_sha512_hmac_final(&hc, h2);
	FZ_CHECK(memcmp(h1, h2, 64) == 0);

	// HKDF(ikm=msg) == expand(extract(salt, ikm)).
	uint8_t *okm1 = fz_alloc(okm_size), *okm2 = fz_alloc(okm_size), prk[64];
	crypto_sha512_hkdf(okm1, okm_size, msg, n, salt, salt_size, info, info_size);
	crypto_sha512_hmac(prk, salt, salt_size, msg, n);
	crypto_sha512_hkdf_expand(okm2, okm_size, prk, 64, info, info_size);
	FZ_CHECK(okm_size == 0 || memcmp(okm1, okm2, okm_size) == 0);
	// A shorter expansion is a prefix of the longer one; prk may be any length.
	size_t shorter = okm_size ? sizes[0] % okm_size : 0;
	crypto_sha512_hkdf_expand(okm2, shorter, key, key_size, info, info_size);
	crypto_sha512_hkdf_expand(okm1, okm_size, key, key_size, info, info_size);
	FZ_CHECK(shorter == 0 || memcmp(okm1, okm2, shorter) == 0);

	free(key); free(salt); free(info); free(msg); free(okm1); free(okm2);
	return 0;
}
