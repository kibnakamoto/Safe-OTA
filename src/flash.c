#include "flash.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static uint8_t mem[FLASH_SIZE];
static long ops, cut_at = -1;
static int torn_mode, dead;

static void bounds(uint32_t off, size_t len) {
    if ((size_t)off + len > FLASH_SIZE) { fprintf(stderr, "flash: out of range access\n"); abort(); }
}
void flash_reset(void) { memset(mem, 0xFF, sizeof mem); ops = 0; cut_at = -1; dead = 0; }
int flash_erase(uint32_t off) {
    if (off % SECTOR) { fprintf(stderr, "flash: unaligned erase\n"); abort(); }
    bounds(off, SECTOR);
    if (dead) return -1;
    if (ops++ == cut_at) {
        if (torn_mode) memset(mem + off, 0xFF, SECTOR / 2);
        dead = 1; return -1;
    }
    memset(mem + off, 0xFF, SECTOR);
    return 0;
}
int flash_prog(uint32_t off, const void *data, size_t len) {
    const uint8_t *d = data;
    bounds(off, len);
    if (dead) return -1;
    size_t n = len;
    int cut = (ops++ == cut_at);
    if (cut) n = torn_mode ? len / 2 : 0;
    for (size_t i = 0; i < n; i++) mem[off + i] &= d[i];
    if (cut) { dead = 1; return -1; }
    return 0;
}
void flash_read(uint32_t off, void *dst, size_t len) { bounds(off, len); memcpy(dst, mem + off, len); }
void flash_arm_cut(long nth, int torn) { ops = 0; cut_at = nth; torn_mode = torn; }
long flash_op_count(void) { return ops; }
void flash_power_on(void) { dead = 0; cut_at = -1; ops = 0; }
void flash_save(uint8_t *dst) { memcpy(dst, mem, sizeof mem); }
void flash_load(const uint8_t *src) { memcpy(mem, src, sizeof mem); }
void flash_poke(uint32_t off, uint8_t v) { bounds(off, 1); mem[off] = v; }
