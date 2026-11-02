#include "ota.h"
#include "sha256.h"
#include <stddef.h>
#include <string.h>

#define META_MAGIC 0x4D455441u
#define CHUNK 256u

typedef struct __attribute__((packed)) {
    uint32_t magic, seq;
    uint8_t active, trial, boots_left, pad;
    uint32_t min_version;   /* anti-rollback floor */
    uint32_t crc;
} meta_rec;

static const uint8_t *g_key;
static size_t g_klen;
void ota_init(const uint8_t *key, size_t klen) { g_key = key; g_klen = klen; }

static uint32_t crc32(const void *p, size_t n) {
    const uint8_t *b = p; uint32_t c = ~0u;
    while (n--) { c ^= *b++; for (int k = 0; k < 8; k++) c = (c >> 1) ^ (0xEDB88320u & -(c & 1u)); }
    return ~c;
}
static uint32_t slot_base(int s) { return s ? SLOT1 : SLOT0; }

static int mac_ok(const image_hdr *h) {
#ifdef MUT_D
    (void)h; return 1;                         /* mutant: skip authentication */
#else
    uint8_t m[32];
    hmac_sha256(g_key, g_klen, h, offsetof(image_hdr, mac), m);
    return ct_equal(m, h->mac, 32);
#endif
}

/* Validate an image in RAM before any flash write. */
static int check_buf(const uint8_t *img, size_t len, image_hdr *h) {
    if (len < sizeof *h) return OTA_ERR_SIZE;
    memcpy(h, img, sizeof *h);
    if (h->magic != IMG_MAGIC) return OTA_ERR_AUTH;
    if (h->length > SLOT_SIZE - sizeof *h || len != sizeof *h + h->length) return OTA_ERR_SIZE;
    if (!mac_ok(h)) return OTA_ERR_AUTH;
    uint8_t d[32]; sha256(img + sizeof *h, h->length, d);
    return ct_equal(d, h->digest, 32) ? OTA_OK : OTA_ERR_DIGEST;
}

/* Validate the image stored in a slot, streaming it from flash. */
static int slot_valid(int s, image_hdr *h) {
    uint32_t base = slot_base(s);
    flash_read(base, h, sizeof *h);
    if (h->magic != IMG_MAGIC || h->length > SLOT_SIZE - sizeof *h) return 0;
#ifdef MUT_A
    return 1;                                  /* mutant: trust the header, never verify */
#else
    if (!mac_ok(h)) return 0;
    sha256_ctx c; sha256_init(&c);
    uint8_t buf[CHUNK]; uint32_t off = 0;
    while (off < h->length) {
        uint32_t n = h->length - off; if (n > CHUNK) n = CHUNK;
        flash_read(base + sizeof *h + off, buf, n); sha256_update(&c, buf, n); off += n;
    }
    uint8_t d[32]; sha256_final(&c, d);
    return ct_equal(d, h->digest, 32);
#endif
}

static int meta_valid(const meta_rec *m) {
    return m->magic == META_MAGIC && m->active < 2 && m->crc == crc32(m, offsetof(meta_rec, crc));
}
static int meta_load(meta_rec *best, int *sec) {
    meta_rec r[2];
    flash_read(META_A, &r[0], sizeof r[0]); flash_read(META_B, &r[1], sizeof r[1]);
    int ok0 = meta_valid(&r[0]), ok1 = meta_valid(&r[1]);
    if (!ok0 && !ok1) return 0;
    int pick = (ok0 && ok1) ? (r[1].seq > r[0].seq) : ok1;
    *best = r[pick]; *sec = pick;
    return 1;
}
/* Ping-pong: always write the record into the sector that does NOT hold the current one. */
static int meta_write(meta_rec *m, int sec) {
    m->magic = META_MAGIC; m->crc = crc32(m, offsetof(meta_rec, crc));
    uint32_t base = sec ? META_B : META_A;
    if (flash_erase(base)) return -1;
    return flash_prog(base, m, sizeof *m) ? -1 : 0;
}

static int write_image(int slot, const uint8_t *img, size_t len) {
    uint32_t base = slot_base(slot);
    for (uint32_t s = 0; s < (len + SECTOR - 1) / SECTOR; s++)
        if (flash_erase(base + s * SECTOR)) return -1;
    for (size_t off = 0; off < len; off += CHUNK) {
        size_t n = len - off < CHUNK ? len - off : CHUNK;
        if (flash_prog(base + (uint32_t)off, img + off, n)) return -1;
    }
    return 0;
}

int ota_provision(const uint8_t *img, size_t len) {
    image_hdr h; int rc = check_buf(img, len, &h);
    if (rc) return rc;
    if (write_image(0, img, len)) return OTA_ERR_POWER;
    meta_rec m; memset(&m, 0, sizeof m);
    m.seq = 1; m.min_version = h.version;
    return meta_write(&m, 0) ? OTA_ERR_POWER : OTA_OK;
}

int ota_install(const uint8_t *img, size_t len) {
    image_hdr h; int rc = check_buf(img, len, &h);   /* nothing touches flash until this passes */
    if (rc) return rc;
    meta_rec cur; int sec;
    if (!meta_load(&cur, &sec)) return OTA_ERR_NOBOOT;
#ifndef MUT_C
    image_hdr ah; uint32_t floor_v = cur.min_version;
    if (slot_valid(cur.active, &ah) && ah.version > floor_v) floor_v = ah.version;
    if (h.version <= floor_v) return OTA_ERR_ROLLBACK;   /* anti-rollback */
#endif
    int target = 1 - cur.active;
    meta_rec nm = cur; nm.seq = cur.seq + 1; nm.active = (uint8_t)target; nm.trial = 1; nm.boots_left = 3;
#ifdef MUT_A
    if (meta_write(&nm, 1 - sec)) return OTA_ERR_POWER;  /* mutant: commit before the image exists */
#endif
    if (write_image(target, img, len)) return OTA_ERR_POWER;
    image_hdr rh;
    if (!slot_valid(target, &rh)) return OTA_ERR_VERIFY;   /* read back and verify from flash */
#ifndef MUT_A
    if (meta_write(&nm, 1 - sec)) return OTA_ERR_POWER;    /* single atomic commit */
#endif
    return OTA_OK;
}

int ota_boot(boot_info *bi) {
    meta_rec m; int sec; image_hdr h;
    memset(bi, 0, sizeof *bi);
    if (!meta_load(&m, &sec)) {                            /* no valid metadata: scan the slots */
        int v0 = slot_valid(0, &h), best = 0; uint32_t ver = h.version;
        int v1 = slot_valid(1, &h);
        if (!v0 && !v1) return OTA_ERR_NOBOOT;
        if (v1 && (!v0 || h.version > ver)) { best = 1; ver = h.version; }
        bi->slot = best; bi->version = ver; bi->fell_back = 1;
        return OTA_OK;
    }
    meta_rec nm = m; int slot = m.active, changed = 0;
    if (m.trial) {
        if (m.boots_left > 0) { nm.boots_left--; nm.seq++; changed = 1; }
        else { slot = 1 - m.active; nm.active = (uint8_t)slot; nm.trial = 0; nm.boots_left = 0; nm.seq++;
               changed = 1; bi->rolled_back = 1; }         /* never confirmed: go back */
    }
    if (!slot_valid(slot, &h)) {                           /* chosen image is damaged: use the other */
        slot = 1 - slot;
#ifdef MUT_A
        return OTA_ERR_NOBOOT;
#endif
        if (!slot_valid(slot, &h)) return OTA_ERR_NOBOOT;
        nm = m; nm.active = (uint8_t)slot; nm.trial = 0; nm.boots_left = 0; nm.seq = m.seq + 1;
        changed = 1; bi->fell_back = 1;
    }
    if (changed && meta_write(&nm, 1 - sec)) return OTA_ERR_POWER;
    bi->slot = slot; bi->version = h.version; bi->trial = nm.trial;
    return OTA_OK;
}

int ota_confirm(void) {
    meta_rec m; int sec; image_hdr h;
    if (!meta_load(&m, &sec)) return OTA_ERR_NOBOOT;
    if (!m.trial) return OTA_OK;
    if (!slot_valid(m.active, &h)) return OTA_ERR_VERIFY;
    meta_rec nm = m; nm.trial = 0; nm.boots_left = 0; nm.min_version = h.version; nm.seq = m.seq + 1;
    return meta_write(&nm, 1 - sec) ? OTA_ERR_POWER : OTA_OK;
}
