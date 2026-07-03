#ifndef UNIQ_NTLM_METAL_H
#define UNIQ_NTLM_METAL_H

#include <stdint.h>

// Opaque handle to a Metal NTLM search engine.
typedef struct ntlm_metal ntlm_metal;

// ntlm_metal_new creates an engine: picks the default GPU, compiles the MSL
// kernel, and allocates reusable buffers. charset holds the charset_len
// password characters. out_pw buffers written by ntlm_metal_search hold up to
// max_hits passwords (16 bytes each). On failure returns NULL and writes a
// message into err (err_len bytes).
ntlm_metal* ntlm_metal_new(const char* charset, int charset_len, int max_hits,
                           char* err, int err_len);

// ntlm_metal_free releases all GPU resources.
void ntlm_metal_free(ntlm_metal* m);

// ntlm_metal_search dispatches `threads` GPU threads, each testing `iters`
// candidate passwords (threads*iters candidates total). Seeds derive from
// `base` (callers should advance base by `threads` between calls to avoid
// overlap). prefix_nibbles holds prefix_len target hex nibbles (0-15), matched
// against the uppercase-hex NTLM digest. Matching passwords (16 bytes each)
// are written into out_pw. Returns the number of matches found (which may
// exceed max_hits, though only max_hits passwords are written), or -1 on error.
int ntlm_metal_search(ntlm_metal* m, uint64_t base, uint32_t threads,
                      uint32_t iters, const uint8_t* prefix_nibbles,
                      int prefix_len, uint8_t* out_pw);

#endif
