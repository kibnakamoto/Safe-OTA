/* Exhaustive power-loss and attack tests for the OTA updater. */
#include <stdio.h>
#include <string.h>
#include "ota.h"
#include "sha256.h"

static int fails, shown;
#define CHECK(c, ...) do { if (!(c)) { fails++; if (shown++ < 8) { printf("FAIL %s:%d: ", __FILE__, __LINE__); printf(__VA_ARGS__); printf("\n"); } } } while (0)

static uint8_t KEY[32], V1[SLOT_SIZE + 64], V2[SLOT_SIZE + 64], V3[SLOT_SIZE + 64], BIG[SLOT_SIZE + 256];
static size_t L1, L2, L3;
static uint8_t FACTORY[FLASH_SIZE];
static long n_single, n_double, n_boot, n_conf;

static size_t build(uint8_t *out, uint32_t ver, size_t plen, uint32_t seed) {
    image_hdr h; memset(&h, 0, sizeof h);
    h.magic = IMG_MAGIC; h.version = ver; h.length = (uint32_t)plen;
    uint8_t *p = out + sizeof h; uint32_t x = seed;
    for (size_t i = 0; i < plen; i++) { x = x * 1664525u + 1013904223u; p[i] = (uint8_t)(x >> 24); }
    sha256(p, plen, h.digest);
    hmac_sha256(KEY, sizeof KEY, &h, offsetof(image_hdr, mac), h.mac);
    memcpy(out, &h, sizeof h);
    return sizeof h + plen;
}

/* Independent oracle: verifies a slot straight from flash without using the code under test. */
static int oracle(int slot, uint32_t *ver) {
    static uint8_t buf[SLOT_SIZE]; image_hdr h; uint8_t d[32], m[32];
    uint32_t base = slot ? SLOT1 : SLOT0;
    flash_read(base, &h, sizeof h);
    if (h.magic != IMG_MAGIC || h.length > SLOT_SIZE - sizeof h) return 0;
    flash_read(base + sizeof h, buf, h.length);
    sha256(buf, h.length, d); hmac_sha256(KEY, sizeof KEY, &h, offsetof(image_hdr, mac), m);
    if (memcmp(d, h.digest, 32) || memcmp(m, h.mac, 32)) return 0;
    *ver = h.version; return 1;
}
static void restore(void) { flash_load(FACTORY); flash_power_on(); }

/* After any failure the next boot must succeed with an authentic image of an allowed version. */
static boot_info boot_ok(const char *ctx, unsigned allowed_mask, long a, long b) {
    boot_info bi; int r = ota_boot(&bi); uint32_t v = 0;
    CHECK(r == OTA_OK, "%s (%ld,%ld): boot returned %d (device bricked)", ctx, a, b, r);
    if (r == OTA_OK) {
        CHECK(oracle(bi.slot, &v), "%s (%ld,%ld): booted slot %d fails independent verification", ctx, a, b, bi.slot);
        CHECK(bi.version < 8 && ((1u << bi.version) & allowed_mask), "%s (%ld,%ld): unexpected version %u", ctx, a, b, bi.version);
    }
    return bi;
}

static void test_primitives(void) {
    uint8_t d[32], exp1[32] = {0xba,0x78,0x16,0xbf,0x8f,0x01,0xcf,0xea,0x41,0x41,0x40,0xde,0x5d,0xae,0x22,0x23,
                               0xb0,0x03,0x61,0xa3,0x96,0x17,0x7a,0x9c,0xb4,0x10,0xff,0x61,0xf2,0x00,0x15,0xad};
    sha256("abc", 3, d); CHECK(!memcmp(d, exp1, 32), "sha256(abc)");
    uint8_t key[20], mac[32], exp2[32] = {0xb0,0x34,0x4c,0x61,0xd8,0xdb,0x38,0x53,0x5c,0xa8,0xaf,0xce,0xaf,0x0b,0xf1,0x2b,
                                          0x88,0x1d,0xc2,0x00,0xc9,0x83,0x3d,0xa7,0x26,0xe9,0x37,0x6c,0x2e,0x32,0xcf,0xf7};
    memset(key, 0x0b, sizeof key); hmac_sha256(key, sizeof key, "Hi There", 8, mac);
    CHECK(!memcmp(mac, exp2, 32), "hmac RFC 4231 case 1");
}

static void test_power_cuts(void) {
    restore(); flash_arm_cut(-1, 0); CHECK(ota_install(V2, L2) == OTA_OK, "baseline install");
    long ni = flash_op_count();
    restore(); CHECK(ota_install(V2, L2) == OTA_OK, "install"); flash_arm_cut(-1, 0); boot_info bi; ota_boot(&bi);
    long nb = flash_op_count();
    restore(); ota_install(V2, L2); ota_boot(&bi); flash_arm_cut(-1, 0); ota_confirm();
    long nc = flash_op_count();
    printf("flash ops per update: install=%ld boot=%ld confirm=%ld\n", ni, nb, nc);

    for (long i = 0; i < ni; i++) for (int t = 0; t < 2; t++) {            /* single cut during install */
        restore(); flash_arm_cut(i, t);
        CHECK(ota_install(V2, L2) == OTA_ERR_POWER, "cut %ld not reached", i);
        flash_power_on(); n_single++;
        boot_ok("single", 6, i, t);
        int r = ota_install(V2, L2);                                       /* the update must be retryable */
        CHECK(r == OTA_OK || r == OTA_ERR_ROLLBACK, "retry after cut (%ld,%d) returned %d", i, t, r);
        boot_ok("retry", 6, i, t);
        for (long j = 0; j < 3; j++) for (int t2 = 0; t2 < 2; t2++) {       /* second cut during recovery boot */
            restore(); flash_arm_cut(i, t); ota_install(V2, L2); flash_power_on();
            flash_arm_cut(j, t2); ota_boot(&bi); flash_power_on(); n_double++;
            boot_ok("double", 6, i * 10 + j, t * 10 + t2);
        }
    }
    for (long j = 0; j < nb; j++) for (int t = 0; t < 2; t++) {            /* cut during the first trial boot */
        restore(); CHECK(ota_install(V2, L2) == OTA_OK, "install"); flash_arm_cut(j, t);
        ota_boot(&bi); flash_power_on(); n_boot++;
        boot_ok("boot-cut", 4, j, t);
    }
    for (long j = 0; j < nc; j++) for (int t = 0; t < 2; t++) {            /* cut while confirming */
        restore(); ota_install(V2, L2); ota_boot(&bi); flash_arm_cut(j, t);
        ota_confirm(); flash_power_on(); n_conf++;
        boot_ok("confirm-cut", 4, j, t);
    }
}

static void test_rollback_and_corruption(void) {
    boot_info bi; restore(); ota_install(V2, L2);
    for (int k = 0; k < 3; k++) { bi = boot_ok("trial", 4, k, 0); CHECK(bi.trial == 1, "trial flag"); }
    bi = boot_ok("rollback", 2, 0, 0); CHECK(bi.rolled_back && bi.version == 1, "unconfirmed image must roll back");
    bi = boot_ok("after-rollback", 2, 0, 0); CHECK(!bi.rolled_back && bi.version == 1, "stays on v1");
    CHECK(ota_install(V3, L3) == OTA_OK, "install after rollback");

    restore(); ota_install(V2, L2); ota_boot(&bi); ota_confirm();            /* silent flash corruption */
    flash_poke(SLOT1 + sizeof(image_hdr) + 100, 0x00);
    bi = boot_ok("bitrot", 2, 0, 0); CHECK(bi.fell_back && bi.version == 1, "corrupt active slot must fall back to v1");
}

static void test_attacks(void) {
    uint8_t snap[FLASH_SIZE]; static uint8_t bad[SLOT_SIZE + 64];
    restore(); memcpy(bad, V2, L2); bad[offsetof(image_hdr, mac)] ^= 1;
    CHECK(ota_install(bad, L2) == OTA_ERR_AUTH, "forged MAC accepted");
    memcpy(bad, V2, L2); bad[sizeof(image_hdr) + 5] ^= 1;
    CHECK(ota_install(bad, L2) != OTA_OK, "tampered payload accepted");
    memcpy(bad, V2, L2); bad[offsetof(image_hdr, version)] = 9;               /* header edited, MAC now wrong */
    CHECK(ota_install(bad, L2) == OTA_ERR_AUTH, "edited version accepted");
    size_t lbig = build(BIG, 5, SLOT_SIZE, 7);
    CHECK(ota_install(BIG, lbig) == OTA_ERR_SIZE, "oversized image accepted");
    flash_save(snap); CHECK(!memcmp(snap, FACTORY, FLASH_SIZE), "rejected images must not touch flash");

    restore(); boot_info bi; ota_install(V2, L2); ota_boot(&bi); ota_confirm();
    CHECK(ota_install(V1, L1) == OTA_ERR_ROLLBACK, "downgrade to v1 accepted");
    CHECK(ota_install(V2, L2) == OTA_ERR_ROLLBACK, "re-install of same version accepted");
}

int main(void) {
    for (int i = 0; i < 32; i++) KEY[i] = (uint8_t)(0xA0 + i);
    ota_init(KEY, sizeof KEY);
    L1 = build(V1, 1, 6000, 11); L2 = build(V2, 2, 6200, 22); L3 = build(V3, 3, 6400, 33);
    flash_reset(); CHECK(ota_provision(V1, L1) == OTA_OK, "provision"); flash_save(FACTORY);
    test_primitives(); test_power_cuts(); test_rollback_and_corruption(); test_attacks();
    printf("power-cut scenarios: single=%ld double=%ld first-boot=%ld confirm=%ld (total %ld)\n",
           n_single, n_double, n_boot, n_conf, n_single + n_double + n_boot + n_conf);
    printf("%s (%d failure%s)\n", fails ? "FAILED" : "PASSED", fails, fails == 1 ? "" : "s");
    return fails ? 1 : 0;
}
