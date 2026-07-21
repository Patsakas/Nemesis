#!/usr/bin/env python3
"""Generate hand-crafted seed files for brotli encoder fuzzing.

These seeds target specific encoder code paths and boundary conditions
that generic random seeds miss:
- Hash table degenerate cases (repeated bytes)
- Block splitting boundaries (power-of-2 sizes)
- Entropy coding stress (high/low entropy)
- Dictionary API parsing
- Fuzz-derived quality parameter forcing
"""

import struct
from pathlib import Path


def main() -> None:
    seed_dir = Path(__file__).resolve().parent.parent / "seeds" / "brotli_encoder"
    seed_dir.mkdir(parents=True, exist_ok=True)

    seeds: dict[str, bytes] = {}

    # --- Repeated byte patterns (hash table degenerate cases) ---

    # Single byte × 64KB — hash table collision storm, long match chains
    seeds["repeat_1byte_64k.bin"] = b"\x41" * 65536

    # Single byte × 256KB — block splitting boundary stress
    seeds["repeat_1byte_256k.bin"] = b"\x41" * 262144

    # 4-byte pattern × 16K — hash collision + backward reference chains
    seeds["repeat_pattern_4.bin"] = (b"\xDE\xAD\xBE\xEF") * 16384

    # --- Byte value coverage ---

    # All 256 byte values repeated — minimal compression, full histogram
    seeds["ascending_256.bin"] = bytes(range(256)) * 256

    # --- Power-of-2 boundary sizes (window/block split triggers) ---

    # Deterministic pseudo-random via simple LCG (reproducible without /dev/urandom)
    def lcg_bytes(n: int, seed: int = 0x12345678) -> bytes:
        """Simple LCG pseudo-random byte generator (deterministic)."""
        result = bytearray(n)
        state = seed
        for i in range(n):
            state = (state * 1103515245 + 12345) & 0x7FFFFFFF
            result[i] = (state >> 16) & 0xFF
        return bytes(result)

    # 16384 bytes — window size boundary (lgwin=14)
    seeds["power2_boundary_16k.bin"] = lcg_bytes(16384, seed=0xAAAA)

    # 65536 bytes — window boundary + block split trigger
    seeds["power2_boundary_64k.bin"] = lcg_bytes(65536, seed=0xBBBB)

    # 65535 bytes — off-by-one at 64K boundary
    seeds["power2_minus1.bin"] = lcg_bytes(65535, seed=0xCCCC)

    # --- Entropy extremes ---

    # High entropy 128KB — stress histogram + entropy coding
    seeds["high_entropy_128k.bin"] = lcg_bytes(131072, seed=0xDDDD)

    # Low entropy HTML-like — dictionary reference matching, repetitive structure
    html_chunk = b"<div class=\"item\"><span>data</span></div>\n"
    seeds["low_entropy_html.bin"] = (html_chunk * (65536 // len(html_chunk) + 1))[:65536]

    # --- Mixed patterns (block splitter stress) ---

    # 32K repeating + 32K random — forces block splitter decision at boundary
    seeds["mixed_rep_rand.bin"] = (b"\x42" * 32768) + lcg_bytes(32768, seed=0xEEEE)

    # Near-degenerate: all zeros except last byte — single anomaly
    seeds["all_zeros_minus_one.bin"] = (b"\x00" * 65535) + b"\x01"

    # --- Dictionary API seeds ---

    # Structured dictionary-like data for CreatePreparedDictionary
    # Format: length-prefixed entries (simulates dictionary structure)
    dict_data = bytearray()
    for i in range(256):
        entry = f"dict_entry_{i:04d}_value".encode()
        dict_data.extend(struct.pack("<H", len(entry)))
        dict_data.extend(entry)
    seeds["dict_raw_16k.bin"] = bytes(dict_data[:16384].ljust(16384, b"\x00"))

    # Brotli shared dictionary prefix format data
    # Starts with recognizable prefix patterns that BrotliSharedDictionaryAttach parses
    prefix_data = bytearray(8192)
    # Type marker + size fields (mimics internal dictionary header expectations)
    prefix_data[0:4] = b"\x00\x01\x02\x03"  # type bytes
    struct.pack_into("<I", prefix_data, 4, 4096)  # size field
    # Fill with dictionary-like content
    for i in range(100):
        offset = 64 + i * 80
        if offset + 80 > len(prefix_data):
            break
        word = ["the", "of", "and", "to", "a", "in", "is", "it", "you", "that"][i % 10].encode()
        prefix_data[offset : offset + len(word)] = word
    seeds["dict_prefix_data.bin"] = bytes(prefix_data)

    # --- Quality-forcing seeds (for fuzz-derived harness format: buf[0]=quality) ---

    # Quality 0 (fast fragment path): byte 0 = 0x00, then 4KB data
    seeds["quality_specific_q0.bin"] = b"\x00" + lcg_bytes(4096, seed=0x1111)

    # Quality 10 (Zopfli optimal): byte 0 = 0x0A, then 2KB data (small — Zopfli is slow)
    seeds["quality_specific_q10.bin"] = b"\x0A" + lcg_bytes(2048, seed=0x2222)

    # --- Write all seeds ---

    created = 0
    for name, data in seeds.items():
        path = seed_dir / name
        path.write_bytes(data)
        created += 1
        print(f"  {name:35s} {len(data):>8,d} bytes")

    print(f"\nCreated {created} seeds in {seed_dir}")
    print(f"Total seeds in directory: {len(list(seed_dir.glob('*.bin')))}")


if __name__ == "__main__":
    main()
