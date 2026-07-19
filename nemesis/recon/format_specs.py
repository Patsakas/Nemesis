"""Format-spec snippets for the LLM-driven mutator synthesiser.

Why this exists
---------------
The first iteration of `mutator_synthesis.py` produced shape-correct but
semantics-shallow adapters. For lz4 the LLM treated the byte stream as a
chain of (header, length, data) chunks and wrote edge values at fixed
offsets — but lz4's actual structure is a *token stream* where each
sequence is a variable-width record `<token byte> [literal-len ext]
<literals> <2-byte offset> [match-len ext]`. The structurally meaningful
bytes (the token, the extension chains) are at offsets the LLM never
inspected.

Passing a compact format-spec snippet into the synthesis prompt fixes
this: the LLM now knows *which* bytes carry the encoding decisions for
the bug class (length encodings, Huffman code lengths, type tags, ...)
and can target them in `nm_adapter_apply_targeted`.

Lookup order (Tier 0, 2026-05-07)
---------------------------------
1. **Per-library cache file** at `config/targets/<lib>/format_spec.txt`,
   produced by `nemesis.recon.format_spec_synthesis` during onboarding.
   This is the primary source going forward — it removes the need for a
   code edit when adding a new library.
2. **Legacy `_SPECS` dict** below — kept so the four already-validated
   libraries (libpng, libtiff, lz4, libwebp) keep working without
   re-onboarding. New entries should NOT be added here; let the
   onboarder synthesise instead.
3. Empty string when neither source has an entry; the synthesiser then
   falls back to the LLM's training-data recall.
"""

from __future__ import annotations

from pathlib import Path

_SPECS: dict[str, str] = {
    "lz4": """\
LZ4 Block Format (informally: "the LZ4 sequence stream")

A compressed block is a chain of sequences. Each sequence is variable-width:

  sequence ::= <token byte>
               <literal-length extensions>?
               <literal bytes>
               <2-byte little-endian offset>
               <match-length extensions>?

Token byte (1 byte):
  high nibble = literal length raw (0..15)
  low  nibble = match length raw (0..15)
  An additional minMatch=4 is implicit in the match length.

Literal-length extension chain: ONLY present when literal raw == 15.
  Read 0xFF bytes; the literal length is 15 + sum(0xFF bytes)
  + (final non-0xFF byte). The chain terminates on the first non-0xFF.

Match-length extension chain: ONLY present when match raw == 15.
  Same encoding, except the running sum is added to (15 + minMatch=4).

Bug-class hint (CVE-2021-3520 and friends): the running sum of literal
or match lengths can wrap an int when many 0xFF bytes are present —
this propagates to memmove with a NEGATIVE size argument.

PER-MUTATION COST: keep each mutation tiny — at most ~16 bytes of write.
AFL's havoc/cmplog will compose short runs across iterations to reach the
larger sums organically. Targeted mutations should:
  - flip the literal raw nibble between 0, 14, 15
  - flip the match raw nibble between 0, 14, 15
  - when the chosen sequence already has lit_raw == 15, OVERWRITE the
    next 1..16 bytes (NOT thousands) with 0xFF — this extends the
    extension chain by a few links per mutation; AFL will iterate to
    grow it further when productive
  - replace 1-2 token bytes (NOT entire literal sections) with 0xFF

`nm_adapter_parse` should walk the token stream sequence by sequence,
emitting one `nm_chunk_t` per sequence with `data_off`/`data_len`
covering the sequence's literal bytes and `header_off` pointing at the
token byte. The 2-byte offset and any extension bytes are NOT covered
by `data_len` — use `kind` to mark which bytes are tokens vs literals.

There is no per-sequence checksum in raw lz4 blocks → `nm_adapter_fix_integrity`
is a no-op (just `(void)buf; (void)chunk;`). The LZ4 *frame* format does
have an xxHash32 over the uncompressed block, but `LZ4_decompress_safe`
operates on raw blocks so the frame layer is irrelevant here.
""",

    "libwebp": """\
WebP / VP8L lossless format (relevant slice for fuzzing)

Top-level container: RIFF chunked.
  RIFF header: 'RIFF' <4-byte LE size> 'WEBP'
  followed by chunks:
    'VP8 '  <4-byte LE size> <data>      (lossy bitstream, VP8)
    'VP8L'  <4-byte LE size> <data>      (lossless bitstream, VP8L)
    'VP8X'  <4-byte LE size> <data>      (extended features header)
    'ALPH'  ... 'ANIM' ... 'ANMF' ...    (other chunks; usually irrelevant)

The vulnerable code (CVE-2023-4863) lives in VP8L decoding.

VP8L bitstream sketch:
  signature byte: 0x2F
  14 bits: image width minus 1
  14 bits: image height minus 1
  1 bit: alpha used
  3 bits: version
  followed by: transforms (predictor, color, subtract-green, color-indexing),
  then per-channel Huffman code-length groups and the entropy-coded image data.

The Huffman code-length groups are where the OOB write fires
(VP8LBuildHuffmanTable). Each group encodes a Huffman tree by transmitting
the code length for each symbol. A malformed group can declare more codes
of one length than fit in the table, overrunning the fixed-size group
buffer.

Bug-class hint (CVE-2023-4863): structurally meaningful bytes are inside
VP8L's bit-packed code-length section, not at byte offsets. A useful
mutator strategy:
  - keep RIFF/WEBP/VP8L framing + signature byte + dimensions intact
  - heavily mutate the code-length payload bytes (the bytes that follow
    the dimensions inside the VP8L chunk's data region)
  - inject biased patterns: all-zero runs (lots of unused symbols), all-FF
    runs (oversaturated), single-bit flips inside the first ~64 bytes of
    the VP8L chunk payload

`nm_adapter_parse` should walk the RIFF chunk list (length-prefixed)
and emit one `nm_chunk_t` per chunk. The VP8L chunk in particular needs
its first ~12 header bytes (signature + dims + flags) recorded as
`integrity` (not really a CRC — just "do not mutate these or every
mutation is rejected by the dimensions check"), and the rest as
`data` for `apply_targeted`.

WebP RIFF chunks pad to even byte size but have no per-chunk checksum.
`nm_adapter_fix_integrity` only needs to refresh the outer RIFF size
field after structural edits.
""",

    "libpng": """\
PNG file format (informally: "chunked, CRC-armoured")

File layout:
  signature: \\x89 P N G \\r \\n \\x1A \\n   (8 bytes, fixed)
  followed by chunks:
    chunk ::= <4-byte BE length>
              <4-byte type tag (ASCII, e.g. "IHDR" "IDAT" "IEND")>
              <length bytes of data>
              <4-byte BE CRC32 over (type + data)>

The first chunk MUST be IHDR (13 bytes of data):
  width            (4 bytes BE)
  height           (4 bytes BE)
  bit_depth        (1 byte)
  color_type       (1 byte: 0/2/3/4/6 for gray/rgb/palette/gray+a/rgba)
  compression_type (1 byte, must be 0)
  filter_type      (1 byte, must be 0)
  interlace_type   (1 byte: 0 = none, 1 = Adam7)

The vulnerable code (CVE-2018-13785) lives in png_check_chunk_length:
  row_factor = width * channels * (bit_depth>8 ? 2 : 1)
             + 1 + (interlaced ? 6 : 0);
where channels is derived from color_type (1, 2, 3, 4 for the values
above). The `row_factor` is later divided into UINT32_MAX. If the
multiplication wraps to make `row_factor == 0`, the divide-by-zero fires.

Bug-class hint: with a 32-bit width field that is hard-capped at
PNG_UINT_31_MAX (= 0x7FFFFFFF) by png_get_uint_31, the surviving overflow
solutions are W * (channels * factor) ≡ 0xFFFFFFFF mod 2^32 with
W ≤ 0x7FFFFFFF. The closed-form solutions are 0xFFFFFFFF/N for
N ∈ {3, 4, 6, 8} (the only valid channels*factor combos), giving
W ∈ {0x55555555, 0x3FFFFFFF, 0x2AAAAAAB, 0x1FFFFFFE}.

Mutator strategy:
  - keep signature + IHDR framing intact
  - target IHDR width / height with the math-derived overflow values
  - flip color_type, bit_depth, interlace bytes through their valid
    enumeration plus a few invalid edges (bit_depth = 0, 24, 32)
  - DO recompute the IHDR CRC32 after each mutation — png_check_chunk_length
    only fires after the chunk is accepted, which requires CRC validity
""",

    "libtiff": """\
TIFF file format (informally: "byte-ordered IFD with custom tags")

Header (8 bytes):
  byte order  : 'II' (little-endian) or 'MM' (big-endian)
  magic       : 0x002A (Classic TIFF) or 0x002B (BigTIFF, 64-bit offsets)
  ifd_offset  : 4 bytes (Classic) or 8 bytes (BigTIFF) — file offset of first IFD

IFD (Image File Directory):
  count       : 2 bytes (Classic) or 8 bytes (BigTIFF) — number of entries
  entries     : 12 bytes each (Classic) or 20 bytes each (BigTIFF)
  next_offset : 4/8 bytes — offset of next IFD, 0 = end of chain

Each IFD entry (Classic, 12 bytes):
  tag         : 2 bytes — well-known IDs like 256=ImageWidth, 257=ImageLength,
                258=BitsPerSample, 322=TileWidth, 323=TileLength, 324=TileOffsets
  type        : 2 bytes — 1=BYTE, 2=ASCII, 3=SHORT, 4=LONG, 5=RATIONAL,
                          6=SBYTE, 7=UNDEFINED, 8=SSHORT, 9=SLONG, 10=SRATIONAL,
                          11=FLOAT, 12=DOUBLE, 13=IFD
  count       : 4 bytes — number of values of `type`
  value/offset: 4 bytes — inline value if total size <= 4, else file offset

Bug-class hints relevant to common TIFF CVEs:
  - CVE-2022-3970 (TIFFReadRGBATileExt): integer overflow when computing
    width * height * sizeof(uint32) for the raster buffer, given a tiled
    TIFF where TileWidth/TileLength are present and ImageWidth/ImageLength
    are attacker-controlled.
  - The trigger needs a TIFF that PASSES early validation but supplies
    extreme dimensions — e.g. ImageWidth = 0xFFFF, ImageLength = 0xFFFF,
    plus TileWidth = 0xFFFF (any non-zero value triggers the tiled path).
  - Custom tag types (CVE-2022-22844 class — note: that specific CVE is
    in the tiffset CLI, not the library): the `type` field at offset+2
    inside an IFD entry can claim a non-standard value (e.g. 0x0200) that
    confuses size computation in TIFFFetchNormalTag.

Mutator strategy:
  - keep the 8-byte header intact (magic + IFD offset)
  - walk the IFD: for each entry, record header_off=entry_off,
    data_off=entry_off+8 (the value/offset slot), data_len=4
  - target mutations:
      flip the `type` field (offset+2..3 within entry) through extended
        values 0x0100, 0x0200, 0xFFFF
      flip the `count` field (offset+4..7) with overflow-prone values
        (0xFFFFFFFF, 0x80000000, etc.)
      for ImageWidth/Length (tags 256/257) and TileWidth/Length (322/323)
        write extreme dimensions
  - no per-IFD-entry checksum → `nm_adapter_fix_integrity` is a no-op
""",
}


_DEFAULT_TARGETS_DIR = Path("config/targets")


def get_format_spec(
    library_name: str,
    targets_dir: Path | None = None,
) -> str:
    """Return the format-spec snippet for `library_name`, or "" when none.

    Lookup order:
      1. `<targets_dir>/<library_name>/format_spec.txt` (synthesised at
         onboarding time). `targets_dir` defaults to `config/targets`
         relative to cwd.
      2. The legacy `_SPECS` dict below (case-insensitive, lib-prefix
         tolerant).
      3. "" — caller falls back to the LLM's training-data recall.
    """
    if not library_name:
        return ""

    # 1. Cache file written by nemesis.recon.format_spec_synthesis
    base = targets_dir if targets_dir is not None else _DEFAULT_TARGETS_DIR
    for candidate in (library_name, library_name.lower()):
        cache = base / candidate / "format_spec.txt"
        if cache.is_file():
            try:
                text = cache.read_text(encoding="utf-8").strip()
                if text:
                    return text
            except OSError:
                pass

    # 2. Legacy hardcoded entries
    name = library_name.lower()
    if name in _SPECS:
        return _SPECS[name]
    if name.startswith("lib"):
        bare = name[3:]
        if bare in _SPECS:
            return _SPECS[bare]

    # 3. No spec — caller handles fallback
    return ""
