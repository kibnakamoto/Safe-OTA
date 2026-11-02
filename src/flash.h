#ifndef FLASH_H
#define FLASH_H
#include <stddef.h>
#include <stdint.h>
/* Simulated NOR flash: erase sets a 4 KB sector to 0xFF, program can only clear bits (AND).
 * A "power cut" can be injected at the Nth mutating operation, either before it takes effect
 * or torn halfway through; after a cut every later write fails until flash_power_on(). */
#define SECTOR 4096u
#define FLASH_SIZE (SECTOR * 10u)
void flash_reset(void);
int flash_erase(uint32_t sector_off);                         /* 0 ok, -1 power cut */
int flash_prog(uint32_t off, const void *data, size_t len);   /* 0 ok, -1 power cut */
void flash_read(uint32_t off, void *dst, size_t len);
void flash_arm_cut(long nth_op, int torn);  /* nth_op < 0: count only. Resets the op counter. */
long flash_op_count(void);
void flash_power_on(void);                  /* "reboot": clears the dead state, keeps contents */
void flash_save(uint8_t *dst);
void flash_load(const uint8_t *src);
void flash_poke(uint32_t off, uint8_t v);   /* test backdoor: silent bit corruption */
#endif
