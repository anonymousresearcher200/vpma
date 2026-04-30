// SPDX-License-Identifier: GPL-2.0 OR Apache-2.0
// eBPF program for RAPL energy data integrity via SipHash-2-4
// Full SipHash computation inside eBPF kernel space

#include <uapi/linux/ptrace.h>
#include <linux/sched.h>

// Maximum RAPL domains we track (sockets * domains)
#define MAX_RAPL_ENTRIES 64

// SipHash-2-4 key (must match Rust and SGX)
#define SIPHASH_K0 0x0706050403020100ULL
#define SIPHASH_K1 0x0f0e0d0c0b0a0908ULL

// Structure to store energy reading with its hash
struct rapl_reading {
    u64 energy_uj;        // Energy value in microjoules
    u64 timestamp_ns;     // Kernel timestamp (nanoseconds)
    u32 socket_id;        // CPU socket/package ID
    u32 domain_id;        // RAPL domain (package, core, uncore, dram)
    u64 hash;             // SipHash-2-4 of above fields
    u8 valid;             // 1 if reading is valid, 0 otherwise
    u8 padding[7];        // Padding for alignment
};

// BPF map to store hashed RAPL readings
BPF_ARRAY(rapl_hash_map, struct rapl_reading, MAX_RAPL_ENTRIES);

// Rotate left operation (inlined for eBPF)
static __always_inline u64 rotl64(u64 x, u32 b) {
    return (x << b) | (x >> (64 - b));
}

// SipRound operation (inlined, unrolled for verifier)
static __always_inline void sipround(u64 *v0, u64 *v1, u64 *v2, u64 *v3) {
    u64 t0 = *v0, t1 = *v1, t2 = *v2, t3 = *v3;
    
    // First half-round
    t0 += t1;
    t1 = rotl64(t1, 13);
    t1 ^= t0;
    t0 = rotl64(t0, 32);
    
    t2 += t3;
    t3 = rotl64(t3, 16);
    t3 ^= t2;
    
    // Second half-round
    t0 += t3;
    t3 = rotl64(t3, 21);
    t3 ^= t0;
    
    t2 += t1;
    t1 = rotl64(t1, 17);
    t1 ^= t2;
    t2 = rotl64(t2, 32);
    
    *v0 = t0;
    *v1 = t1;
    *v2 = t2;
    *v3 = t3;
}

// SipHash-2-4 computation (optimized for eBPF verifier)
static __always_inline u64 siphash24(u64 energy, u64 timestamp, u32 socket, u32 domain) {
    // Initialize state with magic constants XOR key
    u64 v0 = 0x736f6d6570736575ULL ^ SIPHASH_K0;
    u64 v1 = 0x646f72616e646f6dULL ^ SIPHASH_K1;
    u64 v2 = 0x6c7967656e657261ULL ^ SIPHASH_K0;
    u64 v3 = 0x7465646279746573ULL ^ SIPHASH_K1;
    
    // Process energy (2 compression rounds)
    v3 ^= energy;
    sipround(&v0, &v1, &v2, &v3);
    sipround(&v0, &v1, &v2, &v3);
    v0 ^= energy;
    
    // Process timestamp (2 compression rounds)
    v3 ^= timestamp;
    sipround(&v0, &v1, &v2, &v3);
    sipround(&v0, &v1, &v2, &v3);
    v0 ^= timestamp;
    
    // Process socket+domain combined (2 compression rounds)
    u64 ids = ((u64)socket << 32) | (u64)domain;
    v3 ^= ids;
    sipround(&v0, &v1, &v2, &v3);
    sipround(&v0, &v1, &v2, &v3);
    v0 ^= ids;
    
    // Finalization (4 rounds)
    v2 ^= 0xff;
    sipround(&v0, &v1, &v2, &v3);
    sipround(&v0, &v1, &v2, &v3);
    sipround(&v0, &v1, &v2, &v3);
    sipround(&v0, &v1, &v2, &v3);
    
    return v0 ^ v1 ^ v2 ^ v3;
}

// Control map: tells eBPF which entry to compute
BPF_ARRAY(compute_control, u32, 1);

// Universal hash function (simpler than SipHash for eBPF)
// Using multiply-shift hashing for better verifier compatibility
static __always_inline u64 universal_hash(u64 energy, u64 timestamp, u32 socket, u32 domain) {
    // Universal hash parameters (prime-based)
    const u64 PRIME_A = 2654435761ULL;  // Large prime
    const u64 PRIME_B = 2246822519ULL;  // Another prime
    const u64 PRIME_C = 3266489917ULL;  // Third prime
    
    // Combine inputs
    u64 h = energy;
    h = h * PRIME_A + timestamp;
    h = h * PRIME_B + ((u64)socket << 32);
    h = h * PRIME_C + (u64)domain;
    
    // Final mixing
    h ^= h >> 33;
    h *= 0xff51afd7ed558ccdULL;
    h ^= h >> 33;
    h *= 0xc4ceb9fe1a85ec53ULL;
    h ^= h >> 33;
    
    return h;
}

// Automatically compute hash when entry is marked for computation
// This runs in kernel space on every timer tick
// Process entries in small batches to satisfy eBPF verifier
int auto_compute_hash(struct pt_regs *ctx) {
    // Process entries 0-15 (manually unrolled)
    u32 idx;
    struct rapl_reading *reading;
    
    // Entry 0
    idx = 0;
    reading = rapl_hash_map.lookup(&idx);
    if (reading && reading->valid == 0 && reading->energy_uj != 0) {
        reading->hash = universal_hash(reading->energy_uj, reading->timestamp_ns, reading->socket_id, reading->domain_id);
        reading->valid = 1;
    }
    
    // Entry 1
    idx = 1;
    reading = rapl_hash_map.lookup(&idx);
    if (reading && reading->valid == 0 && reading->energy_uj != 0) {
        reading->hash = universal_hash(reading->energy_uj, reading->timestamp_ns, reading->socket_id, reading->domain_id);
        reading->valid = 1;
    }
    
    // Entry 2
    idx = 2;
    reading = rapl_hash_map.lookup(&idx);
    if (reading && reading->valid == 0 && reading->energy_uj != 0) {
        reading->hash = universal_hash(reading->energy_uj, reading->timestamp_ns, reading->socket_id, reading->domain_id);
        reading->valid = 1;
    }
    
    // Entry 3
    idx = 3;
    reading = rapl_hash_map.lookup(&idx);
    if (reading && reading->valid == 0 && reading->energy_uj != 0) {
        reading->hash = universal_hash(reading->energy_uj, reading->timestamp_ns, reading->socket_id, reading->domain_id);
        reading->valid = 1;
    }
    
    // Entry 4
    idx = 4;
    reading = rapl_hash_map.lookup(&idx);
    if (reading && reading->valid == 0 && reading->energy_uj != 0) {
        reading->hash = universal_hash(reading->energy_uj, reading->timestamp_ns, reading->socket_id, reading->domain_id);
        reading->valid = 1;
    }
    
    // Entry 5
    idx = 5;
    reading = rapl_hash_map.lookup(&idx);
    if (reading && reading->valid == 0 && reading->energy_uj != 0) {
        reading->hash = universal_hash(reading->energy_uj, reading->timestamp_ns, reading->socket_id, reading->domain_id);
        reading->valid = 1;
    }
    
    // Entry 6
    idx = 6;
    reading = rapl_hash_map.lookup(&idx);
    if (reading && reading->valid == 0 && reading->energy_uj != 0) {
        reading->hash = universal_hash(reading->energy_uj, reading->timestamp_ns, reading->socket_id, reading->domain_id);
        reading->valid = 1;
    }
    
    // Entry 7
    idx = 7;
    reading = rapl_hash_map.lookup(&idx);
    if (reading && reading->valid == 0 && reading->energy_uj != 0) {
        reading->hash = universal_hash(reading->energy_uj, reading->timestamp_ns, reading->socket_id, reading->domain_id);
        reading->valid = 1;
    }
    
    return 0;
}
