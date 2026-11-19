// Argon2 d / i / id password hashing with fuzz-chosen parameters and inputs, one-shot
// vs the init / segment / final API. nb_blocks reaches past 512 for one lane (segment
// size > 128 blocks), the range where upstream fixed an Argon2i overflow (b8b5edda7c).
// Layout: alg | lanes | blocks u16 | passes | hash_size u16 | pass_len | salt_len | key_len |
//         ad_len | pass | salt | key | ad
#include "monocypher.h"
#include "fuzz_common.h"

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
	fz_reader r; fz_init(&r, data, size);
	crypto_argon2_config cfg;
	cfg.algorithm = fz_u8(&r) % 3;
	cfg.nb_lanes  = 1 + fz_u8(&r) % 4;
	// Documented preconditions (monocypher.h): nb_blocks >= 8 * nb_lanes, nb_passes >= 1,
	// hash_size >= 1. The upper bounds only keep one execution fast.
	cfg.nb_blocks = 8 * cfg.nb_lanes + fz_u16(&r) % 1100;
	cfg.nb_passes = 1 + fz_u8(&r) % 3;
	uint32_t hash_size = 1 + fz_u16(&r) % 256;
	size_t pl = fz_u8(&r), sl = fz_u8(&r), kl = fz_u8(&r), al = fz_u8(&r);
	size_t pass_size, salt_size, key_size, ad_size;
	uint8_t *pass = fz_slice(&r, pl, &pass_size);
	uint8_t *salt = fz_slice(&r, sl, &salt_size);
	uint8_t *key  = fz_slice(&r, kl, &key_size);
	uint8_t *ad   = fz_slice(&r, al, &ad_size);

	crypto_argon2_inputs in = { pass, salt, (uint32_t)pass_size, (uint32_t)salt_size };
	crypto_argon2_extras ex = { key, ad, (uint32_t)key_size, (uint32_t)ad_size };
	void *work = malloc((size_t)cfg.nb_blocks * 1024);
	uint8_t *h1 = (uint8_t *)malloc(hash_size), *h2 = (uint8_t *)malloc(hash_size);

	crypto_argon2(h1, hash_size, work, cfg, in, ex);

	// Same hash through the incremental interface, lanes in reverse order per slice
	// (lanes of one slice are independent).
	crypto_argon2_ctx ctx;
	crypto_argon2_init(&ctx, hash_size, work, cfg, in, ex);
	for (uint32_t p = 0; p < cfg.nb_passes; p++)
		for (uint32_t s = 0; s < 4; s++)
			for (uint32_t l = cfg.nb_lanes; l-- > 0;)
				crypto_argon2_segment(&ctx, p, s, l);
	crypto_argon2_final(&ctx, h2);
	FZ_CHECK(memcmp(h1, h2, hash_size) == 0);

	if (key_size == 0 && ad_size == 0) {
		crypto_argon2(h2, hash_size, work, cfg, in, crypto_argon2_no_extras);
		FZ_CHECK(memcmp(h1, h2, hash_size) == 0);
	}
	free(work); free(h1); free(h2); free(pass); free(salt); free(key); free(ad);
	return 0;
}
