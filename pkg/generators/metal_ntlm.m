#import <Foundation/Foundation.h>
#import <Metal/Metal.h>
#include "metal_ntlm.h"

// -----------------------------------------------------------------------------
// Metal Shading Language kernel.
//
// This mirrors the Go hot path in ntlm.go exactly so results are identical:
//   * per-thread splitmix64 seed from (base + gid)
//   * xorshift64 -> charset via Lemire reduction (two chars per PRNG step)
//   * fully unrolled single-block MD4 over the 16-char UTF-16LE password
//   * uppercase-hex nibble prefix compare
// -----------------------------------------------------------------------------
static const char* kKernelSrc = R"METAL(
#include <metal_stdlib>
using namespace metal;

inline uint rotl32(uint x, uint n) { return (x << n) | (x >> (32u - n)); }

inline ulong splitmix64(ulong x) {
    x += 0x9e3779b97f4a7c15UL;
    x = (x ^ (x >> 30)) * 0xbf58476d1ce4e5b9UL;
    x = (x ^ (x >> 27)) * 0x94d049bb133111ebUL;
    return x ^ (x >> 31);
}

// Single-block MD4 of a 16-char ASCII password packed as UTF-16LE (32 bytes).
inline void md4_block32(thread const uchar* pw, thread uint* out /*[4]*/) {
    uint x[16];
    for (int j = 0; j < 8; j++) {
        x[j] = (uint)pw[2*j] | ((uint)pw[2*j+1] << 16);
    }
    for (int j = 8; j < 16; j++) x[j] = 0u;
    x[8]  = 0x80u;   // padding byte
    x[14] = 256u;    // bit length (32 bytes)

    const uint a0 = 0x67452301u, b0 = 0xefcdab89u, c0 = 0x98badcfeu, d0 = 0x10325476u;
    uint a = a0, b = b0, c = c0, d = d0;

    // Round 1
    {
        const uint s[4] = {3u, 7u, 11u, 19u};
        for (int i = 0; i < 16; i++) {
            uint f = ((c ^ d) & b) ^ d;
            a = a + f + x[i];
            a = rotl32(a, s[i & 3]);
            uint t = d; d = c; c = b; b = a; a = t;
        }
    }
    // Round 2
    {
        const uint s[4] = {3u, 5u, 9u, 13u};
        const uint idx[16] = {0,4,8,12,1,5,9,13,2,6,10,14,3,7,11,15};
        for (int i = 0; i < 16; i++) {
            uint g = (b & c) | (b & d) | (c & d);
            a = a + g + x[idx[i]] + 0x5a827999u;
            a = rotl32(a, s[i & 3]);
            uint t = d; d = c; c = b; b = a; a = t;
        }
    }
    // Round 3
    {
        const uint s[4] = {3u, 9u, 11u, 15u};
        const uint idx[16] = {0,8,4,12,2,10,6,14,1,9,5,13,3,11,7,15};
        for (int i = 0; i < 16; i++) {
            uint h = b ^ c ^ d;
            a = a + h + x[idx[i]] + 0x6ed9eba1u;
            a = rotl32(a, s[i & 3]);
            uint t = d; d = c; c = b; b = a; a = t;
        }
    }
    out[0] = a + a0; out[1] = b + b0; out[2] = c + c0; out[3] = d + d0;
}

// Byte k (0..15) of the little-endian digest words.
inline uchar digest_byte(thread const uint* w, int k) {
    return (uchar)((w[k >> 2] >> ((k & 3) * 8)) & 0xffu);
}

kernel void ntlm_search(
    constant uchar*  charset      [[buffer(0)]],
    constant uint&   charsetLen   [[buffer(1)]],
    constant ulong&  base         [[buffer(2)]],
    constant uchar*  prefixNib    [[buffer(3)]],
    constant uint&   prefixLen    [[buffer(4)]],
    constant uint&   iters        [[buffer(5)]],
    device   atomic_uint* hitCount[[buffer(6)]],
    device   uchar*  outPw        [[buffer(7)]],
    constant uint&   maxHits      [[buffer(8)]],
    uint gid [[thread_position_in_grid]])
{
    ulong st = splitmix64(base + (ulong)gid);
    if (st == 0) st = 0x9e3779b97f4a7c15UL;

    for (uint it = 0; it < iters; it++) {
        uchar pw[16];
        for (int i = 0; i < 16; i += 2) {
            st ^= st << 13;
            st ^= st >> 7;
            st ^= st << 17;
            pw[i]   = charset[((ulong)((uint)st)        * (ulong)charsetLen) >> 32];
            pw[i+1] = charset[((ulong)((uint)(st >> 32)) * (ulong)charsetLen) >> 32];
        }

        uint w[4];
        md4_block32(pw, w);

        bool match = true;
        for (uint i = 0; i < prefixLen; i++) {
            uchar byte = digest_byte(w, (int)(i >> 1));
            uchar nib = (i & 1u) ? (byte & 0x0fu) : (byte >> 4);
            if (nib != prefixNib[i]) { match = false; break; }
        }
        if (match) {
            uint slot = atomic_fetch_add_explicit(hitCount, 1u, memory_order_relaxed);
            if (slot < maxHits) {
                for (int i = 0; i < 16; i++) outPw[slot * 16 + i] = pw[i];
            }
        }
    }
}
)METAL";

// -----------------------------------------------------------------------------
// Objective-C host. No ARC: we own objects returned by new*/MTLCreateSystem*
// and release them in ntlm_metal_free; transient objects live in an
// @autoreleasepool per call.
// -----------------------------------------------------------------------------
struct ntlm_metal {
    id<MTLDevice>               device;
    id<MTLCommandQueue>         queue;
    id<MTLComputePipelineState> pso;
    id<MTLBuffer>               charsetBuf;
    id<MTLBuffer>               prefixBuf;   // 32 bytes
    id<MTLBuffer>               hitCountBuf; // 1 uint
    id<MTLBuffer>               outPwBuf;    // max_hits * 16
    int                         maxHits;
};

static void set_err(char* err, int err_len, NSString* msg) {
    if (err && err_len > 0) {
        const char* c = msg ? [msg UTF8String] : "unknown error";
        strncpy(err, c, (size_t)(err_len - 1));
        err[err_len - 1] = '\0';
    }
}

ntlm_metal* ntlm_metal_new(const char* charset, int charset_len, int max_hits,
                           char* err, int err_len) {
    @autoreleasepool {
        ntlm_metal* m = (ntlm_metal*)calloc(1, sizeof(ntlm_metal));
        if (!m) { set_err(err, err_len, @"calloc failed"); return NULL; }
        m->maxHits = max_hits;

        m->device = MTLCreateSystemDefaultDevice();
        if (!m->device) { set_err(err, err_len, @"no Metal device"); free(m); return NULL; }

        m->queue = [m->device newCommandQueue];
        if (!m->queue) { set_err(err, err_len, @"newCommandQueue failed"); ntlm_metal_free(m); return NULL; }

        NSError* nerr = nil;
        NSString* src = [NSString stringWithUTF8String:kKernelSrc];
        id<MTLLibrary> lib = [m->device newLibraryWithSource:src options:nil error:&nerr];
        if (!lib) {
            set_err(err, err_len, [NSString stringWithFormat:@"compile failed: %@", nerr]);
            ntlm_metal_free(m);
            return NULL;
        }
        id<MTLFunction> fn = [lib newFunctionWithName:@"ntlm_search"];
        [lib release];
        if (!fn) { set_err(err, err_len, @"missing kernel function"); ntlm_metal_free(m); return NULL; }

        m->pso = [m->device newComputePipelineStateWithFunction:fn error:&nerr];
        [fn release];
        if (!m->pso) {
            set_err(err, err_len, [NSString stringWithFormat:@"pipeline failed: %@", nerr]);
            ntlm_metal_free(m);
            return NULL;
        }

        m->charsetBuf  = [m->device newBufferWithBytes:charset length:(NSUInteger)charset_len options:MTLResourceStorageModeShared];
        m->prefixBuf   = [m->device newBufferWithLength:32 options:MTLResourceStorageModeShared];
        m->hitCountBuf = [m->device newBufferWithLength:sizeof(uint32_t) options:MTLResourceStorageModeShared];
        m->outPwBuf    = [m->device newBufferWithLength:(NSUInteger)(max_hits * 16) options:MTLResourceStorageModeShared];
        if (!m->charsetBuf || !m->prefixBuf || !m->hitCountBuf || !m->outPwBuf) {
            set_err(err, err_len, @"buffer allocation failed");
            ntlm_metal_free(m);
            return NULL;
        }
        return m;
    }
}

void ntlm_metal_free(ntlm_metal* m) {
    if (!m) return;
    [m->outPwBuf release];
    [m->hitCountBuf release];
    [m->prefixBuf release];
    [m->charsetBuf release];
    [m->pso release];
    [m->queue release];
    [m->device release];
    free(m);
}

int ntlm_metal_search(ntlm_metal* m, uint64_t base, uint32_t threads,
                      uint32_t iters, const uint8_t* prefix_nibbles,
                      int prefix_len, uint8_t* out_pw) {
    @autoreleasepool {
        uint32_t charsetLen = (uint32_t)[m->charsetBuf length];
        uint32_t prefixLen = (uint32_t)prefix_len;
        uint32_t maxHits = (uint32_t)m->maxHits;

        // Reset hit counter and stage the prefix nibbles.
        *(uint32_t*)[m->hitCountBuf contents] = 0;
        memcpy([m->prefixBuf contents], prefix_nibbles, (size_t)prefix_len);

        id<MTLCommandBuffer> cmd = [m->queue commandBuffer];
        id<MTLComputeCommandEncoder> enc = [cmd computeCommandEncoder];
        [enc setComputePipelineState:m->pso];
        [enc setBuffer:m->charsetBuf offset:0 atIndex:0];
        [enc setBytes:&charsetLen length:sizeof(charsetLen) atIndex:1];
        [enc setBytes:&base length:sizeof(base) atIndex:2];
        [enc setBuffer:m->prefixBuf offset:0 atIndex:3];
        [enc setBytes:&prefixLen length:sizeof(prefixLen) atIndex:4];
        [enc setBytes:&iters length:sizeof(iters) atIndex:5];
        [enc setBuffer:m->hitCountBuf offset:0 atIndex:6];
        [enc setBuffer:m->outPwBuf offset:0 atIndex:7];
        [enc setBytes:&maxHits length:sizeof(maxHits) atIndex:8];

        NSUInteger tg = m->pso.maxTotalThreadsPerThreadgroup;
        if (tg > 256) tg = 256;
        [enc dispatchThreads:MTLSizeMake(threads, 1, 1)
              threadsPerThreadgroup:MTLSizeMake(tg, 1, 1)];
        [enc endEncoding];
        [cmd commit];
        [cmd waitUntilCompleted];

        if (cmd.status == MTLCommandBufferStatusError) {
            return -1;
        }

        uint32_t hits = *(uint32_t*)[m->hitCountBuf contents];
        uint32_t written = hits < maxHits ? hits : maxHits;
        if (written > 0) {
            memcpy(out_pw, [m->outPwBuf contents], (size_t)(written * 16));
        }
        return (int)hits;
    }
}
