#ifndef OTA_H
#define OTA_H
#include <stddef.h>
#include <stdint.h>
#include "flash.h"

/* Flash layout: [meta A][meta B][slot 0: 4 sectors][slot 1: 4 sectors] */
#define META_A 0u
#define META_B SECTOR
#define SLOT_SIZE (4u * SECTOR)
#define SLOT0 (2u * SECTOR)
#define SLOT1 (SLOT0 + SLOT_SIZE)
#define IMG_MAGIC 0x53414645u

enum { OTA_OK = 0, OTA_ERR_POWER = -1, OTA_ERR_AUTH = -2, OTA_ERR_ROLLBACK = -3,
       OTA_ERR_SIZE = -4, OTA_ERR_NOBOOT = -5, OTA_ERR_VERIFY = -6, OTA_ERR_DIGEST = -7 };

typedef struct __attribute__((packed)) {
    uint32_t magic, version, length;  /* length = payload bytes */
    uint8_t digest[32];               /* SHA-256 of the payload */
    uint8_t mac[32];                  /* HMAC-SHA256 over everything above */
} image_hdr;

typedef struct { int slot; uint32_t version; int trial; int rolled_back; int fell_back; } boot_info;

void ota_init(const uint8_t *key, size_t klen);
int ota_provision(const uint8_t *img, size_t len);   /* factory: write slot 0 + first metadata */
int ota_install(const uint8_t *img, size_t len);     /* authenticate, write inactive slot, commit atomically */
int ota_boot(boot_info *bi);                         /* pick, verify and (if needed) roll back / fall back */
int ota_confirm(void);                               /* app reports healthy: end the trial, raise the version floor */
#endif
