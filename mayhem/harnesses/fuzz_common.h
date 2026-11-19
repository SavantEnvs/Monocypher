// Shared helpers for the Monocypher fuzz harnesses (mayhem/ integration layer).
// A tiny byte reader over the fuzzer input: fixed-size fields are taken from the
// front, the variable-length rest is split by length bytes. Missing bytes read as 0,
// so every input is valid and maps deterministically to one API call sequence.
#ifndef MONOCYPHER_FUZZ_COMMON_H
#define MONOCYPHER_FUZZ_COMMON_H
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>

typedef struct {
	const uint8_t *p;
	size_t         n;
} fz_reader;

static inline void fz_init(fz_reader *r, const uint8_t *d, size_t n) { r->p = d; r->n = n; }

static inline uint8_t fz_u8(fz_reader *r)
{
	if (r->n == 0) return 0;
	uint8_t b = r->p[0];
	r->p++; r->n--;
	return b;
}

static inline uint32_t fz_u16(fz_reader *r) { uint32_t a = fz_u8(r); return a | ((uint32_t)fz_u8(r) << 8); }

static inline uint64_t fz_u64(fz_reader *r)
{
	uint64_t v = 0;
	for (int i = 0; i < 8; i++) v |= (uint64_t)fz_u8(r) << (8 * i);
	return v;
}

// Copy exactly `len` bytes into out (zero padded when input runs out).
static inline void fz_fixed(fz_reader *r, uint8_t *out, size_t len)
{
	size_t take = len < r->n ? len : r->n;
	if (take) memcpy(out, r->p, take);
	if (take < len) memset(out + take, 0, len - take);
	r->p += take; r->n -= take;
}

// Up to `len` bytes as a freshly malloc'd buffer (exact size, so ASan sees overreads).
// Returns NULL when the slice is empty: the API allows NULL with size 0, and that is
// exactly the case upstream fixed in 8680b35431 (NULL + 0 pointer arithmetic).
static inline uint8_t *fz_slice(fz_reader *r, size_t len, size_t *out_len)
{
	size_t take = len < r->n ? len : r->n;
	*out_len = take;
	if (take == 0) return NULL;
	uint8_t *b = (uint8_t *)malloc(take);
	memcpy(b, r->p, take);
	r->p += take; r->n -= take;
	return b;
}

static inline uint8_t *fz_rest(fz_reader *r, size_t *out_len) { return fz_slice(r, r->n, out_len); }

// Exact-size heap buffer (non-NULL even for size 0 is not needed: callers pass NULL then).
static inline uint8_t *fz_alloc(size_t len) { return len ? (uint8_t *)malloc(len) : NULL; }

// A differential/roundtrip property failed: that is a wrong result from the library.
#define FZ_CHECK(cond) do { \
	if (!(cond)) { \
		fprintf(stderr, "monocypher fuzz: property violated: %s (%s:%d)\n", #cond, __FILE__, __LINE__); \
		abort(); \
	} \
} while (0)


// Feed msg[0..len) to `upd` in chunks whose sizes cycle through sizes[0..nsizes).
// A size of 0 is a zero-length update with a NULL pointer (allowed by the API).
// After 8 consecutive empty updates the rest goes in one call, so the loop ends.
typedef void (*fz_update_fn)(void *ctx, const uint8_t *m, size_t n);
static inline void fz_chunked(void *ctx, fz_update_fn upd,
                              const uint8_t *msg, size_t len,
                              const uint8_t *sizes, size_t nsizes)
{
	size_t off = 0, i = 0, empties = 0;
	if (len == 0 || nsizes == 0) { upd(ctx, msg, len); return; }
	while (off < len) {
		size_t s = sizes[i++ % nsizes];
		if (s == 0) {
			upd(ctx, NULL, 0);
			if (++empties < 8) continue;
			s = len - off;
		}
		empties = 0;
		if (s > len - off) s = len - off;
		upd(ctx, msg + off, s);
		off += s;
	}
}
#endif
