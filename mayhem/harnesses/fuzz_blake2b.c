// BLAKE2b: one-shot vs incremental (fuzz-chosen chunking, incl. empty NULL updates).
// Layout: hash_size byte | key_size byte | 4 chunk-size bytes | key | message (rest)
#include "monocypher.h"
#include "fuzz_common.h"

static void upd(void *ctx, const uint8_t *m, size_t n) { crypto_blake2b_update((crypto_blake2b_ctx *)ctx, m, n); }

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
	fz_reader r; fz_init(&r, data, size);
	size_t hash_size = 1 + fz_u8(&r) % 64;   // API contract: 1..64
	size_t key_req   = fz_u8(&r) % 65;       // API contract: 0..64
	uint8_t sizes[4]; fz_fixed(&r, sizes, 4);
	size_t key_size, msg_size;
	uint8_t *key = fz_slice(&r, key_req, &key_size);
	uint8_t *msg = fz_rest(&r, &msg_size);

	uint8_t h1[64], h2[64], h3[64];
	crypto_blake2b_keyed(h1, hash_size, key, key_size, msg, msg_size);

	crypto_blake2b_ctx ctx;
	crypto_blake2b_keyed_init(&ctx, hash_size, key, key_size);
	fz_chunked(&ctx, upd, msg, msg_size, sizes, 4);
	crypto_blake2b_final(&ctx, h2);
	FZ_CHECK(memcmp(h1, h2, hash_size) == 0);

	if (key_size == 0) {
		crypto_blake2b(h3, hash_size, msg, msg_size);
		FZ_CHECK(memcmp(h1, h3, hash_size) == 0);
		crypto_blake2b_init(&ctx, hash_size);
		fz_chunked(&ctx, upd, msg, msg_size, sizes + 2, 2);
		crypto_blake2b_final(&ctx, h3);
		FZ_CHECK(memcmp(h1, h3, hash_size) == 0);
	}
	free(key); free(msg);
	return 0;
}
