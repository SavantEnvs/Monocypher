// Poly1305: one-shot vs incremental (fuzz-chosen chunking, incl. empty NULL updates).
// Layout: key[32] | 4 chunk-size bytes | message (rest)
#include "monocypher.h"
#include "fuzz_common.h"

static void upd(void *ctx, const uint8_t *m, size_t n) { crypto_poly1305_update((crypto_poly1305_ctx *)ctx, m, n); }

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
	fz_reader r; fz_init(&r, data, size);
	uint8_t key[32]; fz_fixed(&r, key, 32);
	uint8_t sizes[4]; fz_fixed(&r, sizes, 4);
	size_t msg_size;
	uint8_t *msg = fz_rest(&r, &msg_size);

	uint8_t m1[16], m2[16];
	crypto_poly1305(m1, msg, msg_size, key);
	crypto_poly1305_ctx ctx;
	crypto_poly1305_init(&ctx, key);
	fz_chunked(&ctx, upd, msg, msg_size, sizes, 4);
	crypto_poly1305_final(&ctx, m2);
	FZ_CHECK(memcmp(m1, m2, 16) == 0);
	free(msg);
	return 0;
}
