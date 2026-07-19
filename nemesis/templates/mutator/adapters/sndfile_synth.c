#include "../mutator_scaffold.h"
#include "../mutator_bitstream.h"

static const uint8_t WAV_RIFF[4] = {'R','I','F','F'};
static const uint8_t WAV_WAVEfmt[8] = {'W','A','V','E','f','m','t',' '};

static int nm_adapter_has_signature(const uint8_t *buf, size_t size){
  if(size < 12) return 0;
  if(memcmp(buf, WAV_RIFF, 4) == 0 && nm_read_le32(buf+8) == size - 8) return 1;
  if(size >= 16 && memcmp(buf+8, WAV_WAVEfmt, 8) == 0) return 1;
  return 0;
}

#define NM_MAX_CHUNKS 64
#define NM_MAX_DATA 16777216u

enum {
  WAV_KIND_UNKNOWN = 0,
  WAV_KIND_FMT = 1,
  WAV_KIND_DATA = 2,
  WAV_KIND_LIST = 3,
  WAV_KIND_FACT = 4,
  WAV_KIND_SMPL = 5,
};

typedef struct {
  uint32_t ckID;
  uint32_t ckSize;
  uint32_t ckOffset;
} wav_chunk_hdr;

static int nm_adapter_parse(const uint8_t *buf, size_t size, nm_chunk_t *out){
  int n = 0;
  size_t off = 12;
  if(size < 12) return 0;
  if(memcmp(buf, WAV_RIFF, 4) != 0) return 0;

  uint32_t riffSize = nm_read_le32(buf+4);
  if(riffSize + 8 != size) return 0;

  while(n < NM_MAX_CHUNKS && off + 8 <= size){
    if(off + 8 > size) break;
    wav_chunk_hdr hdr;
    memcpy(&hdr.ckID, buf+off, 4);
    hdr.ckSize = nm_read_le32(buf+off+4);
    hdr.ckOffset = (uint32_t)off;

    if(hdr.ckSize > NM_MAX_DATA) break;
    if(off + 8 + hdr.ckSize > size) break;

    out[n].header_off = off;
    out[n].data_off = off + 8;
    out[n].data_len = hdr.ckSize;
    out[n].integrity_off = 0;
    out[n].integrity_len = 0;
    out[n].kind = WAV_KIND_UNKNOWN;
    out[n].flags = 0;

    if(hdr.ckID == 0x20746D66){ /* 'fmt ' */
      out[n].kind = WAV_KIND_FMT;
    } else if(hdr.ckID == 0x61746164){ /* 'data' */
      out[n].kind = WAV_KIND_DATA;
    } else if(hdr.ckID == 0x5453494C){ /* 'LIST' */
      out[n].kind = WAV_KIND_LIST;
    } else if(hdr.ckID == 0x74636166){ /* 'fact' */
      out[n].kind = WAV_KIND_FACT;
    } else if(hdr.ckID == 0x6C706D73){ /* 'smpl' */
      out[n].kind = WAV_KIND_SMPL;
    }

    n++;
    off += 8 + hdr.ckSize;
    if(off == size) break;
  }
  return n;
}

static void nm_adapter_fix_integrity(uint8_t *buf, const nm_chunk_t *chunk){
  (void)buf; (void)chunk;
}

static int nm_adapter_apply_targeted(uint8_t *buf, size_t buf_size, nm_chunk_t *chunks, int n, uint32_t *rng){
  if(n <= 0) return 0;
  int target = -1;
  for(int i=0;i<n;i++){
    if(chunks[i].kind == WAV_KIND_FMT || chunks[i].kind == WAV_KIND_DATA || chunks[i].kind == WAV_KIND_FACT || chunks[i].kind == WAV_KIND_SMPL){
      target = i;
      break;
    }
  }
  if(target == -1) return 0;

  nm_chunk_t *c = &chunks[target];
  size_t d = c->data_off;
  if(d + 4 > buf_size) return 0;

  uint32_t op = nm_xorshift32(rng) % 6;
  switch(op){
    case 0: {
      uint32_t v = nm_xorshift32(rng) % 3;
      if(v == 0) nm_write_le32(buf+d, 0);
      else if(v == 1) nm_write_le32(buf+d, 1);
      else if(v == 2) nm_write_le32(buf+d, 0xFFFFFFFFu);
      break;
    }
    case 1: {
      if(d + 8 <= buf_size){
        uint32_t v = nm_xorshift32(rng) % 3;
        if(v == 0) nm_write_le32(buf+d+4, 0);
        else if(v == 1) nm_write_le32(buf+d+4, 1);
        else if(v == 2) nm_write_le32(buf+d+4, 0xFFFFFFFFu);
      }
      break;
    }
    case 2: {
      if(d + 12 <= buf_size){
        uint32_t v = nm_xorshift32(rng) % 3;
        if(v == 0) nm_write_le32(buf+d+8, 0);
        else if(v == 1) nm_write_le32(buf+d+8, 1);
        else if(v == 2) nm_write_le32(buf+d+8, 0xFFFFFFFFu);
      }
      break;
    }
    case 3: {
      if(d + 16 <= buf_size){
        uint32_t v = nm_xorshift32(rng) % 3;
        if(v == 0) nm_write_le32(buf+d+12, 0);
        else if(v == 1) nm_write_le32(buf+d+12, 1);
        else if(v == 2) nm_write_le32(buf+d+12, 0xFFFFFFFFu);
      }
      break;
    }
    case 4: {
      if(d + 20 <= buf_size){
        uint32_t v = nm_xorshift32(rng) % 3;
        if(v == 0) nm_write_le32(buf+d+16, 0);
        else if(v == 1) nm_write_le32(buf+d+16, 1);
        else if(v == 2) nm_write_le32(buf+d+16, 0xFFFFFFFFu);
      }
      break;
    }
    case 5: {
      if(d + 24 <= buf_size){
        uint32_t v = nm_xorshift32(rng) % 3;
        if(v == 0) nm_write_le32(buf+d+20, 0);
        else if(v == 1) nm_write_le32(buf+d+20, 1);
        else if(v == 2) nm_write_le32(buf+d+20, 0xFFFFFFFFu);
      }
      break;
    }
  }
  return 1;
}