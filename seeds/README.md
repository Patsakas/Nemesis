# Seeds

Small, curated seed inputs used to bootstrap fuzzing, organized per format:

```
seeds/
├── png/            # PNG inputs
├── tiff/           # TIFF inputs
├── brotli/         # brotli streams
├── brotli_encoder/ # plaintext seeds for encoder targets
├── json/           # JSON inputs
├── zip/  rar5/  sevenzip/  lha/  iso/  cab/  xar/  pax/  uu/  xml/  acl_text/  all_formats/
└── ...
```

A target config points at these via `seeds.formats`, e.g.:

```yaml
seeds:
  formats:
    png: "$HOME/nemesis/seeds/png"
```

## Large OSS-Fuzz corpus (not versioned)

The bulk OSS-Fuzz corpus (`seeds/oss_fuzz_corpus*/`) is **not committed** — it is large
and its inputs carry the upstream projects' own licensing. It is `.gitignore`d.

Point a target at your own copy with `seeds.oss_fuzz_corpus`, or let the pipeline fetch a
project's public corpus at runtime:

```yaml
seeds:
  oss_fuzz_corpus: "$HOME/nemesis/seeds/oss_fuzz_corpus/<project>"
```

The small per-format directories above are enough to run the tool out of the box; the
OSS-Fuzz corpus is an optional accelerator.
