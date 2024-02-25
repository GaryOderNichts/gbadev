/*
	mini - a Free Software replacement for the Nintendo/BroadOn IOS.

Copyright (C) 2008, 2009	Haxx Enterprises <bushing@gmail.com>
Copyright (C) 2008, 2009	Sven Peter <svenpeter@gmail.com>
Copyright (C) 2008, 2009	Hector Martin "marcan" <marcan@marcansoft.com>
Copyright (C) 2009			Andre Heider "dhewg" <dhewg@wiibrew.org>
Copyright (C) 2009		John Kelley <wiidev@kelley.ca>

# This code is licensed to you under the terms of the GNU GPL, version 2;
# see file COPYING or http://www.gnu.org/licenses/old-licenses/gpl-2.0.txt
*/

#include "types.h"
#include "utils.h"
#include "start.h"
#include "hollywood.h"
#include "sdhc.h"
#include "string.h"
#include "memory.h"
#include "gecko.h"
#include "ff.h"
#include "panic.h"
#include "irq.h"
#include "exception.h"
#include "crypto.h"

#define PACKED __attribute__((packed))

typedef struct {
	char name[0x100];
	void* data;
	u32 size;
	u32 unk;
	u8 hash[0x14];
	u8 padding[0x0C];
} PACKED prsh_section_t;

typedef struct {
	u32 xor_checksum;
	u32 magic;
	u32 version;
	u32 size;
	u32 unk;
	u32 max_sections;
	u32 num_sections;
	prsh_section_t sections[];
} PACKED prsh_t;

typedef struct {
	u32 xor_checksum;
	u32 size;
	u32 unk;
	u32 magic;
} PACKED prst_t;

/*
 * The normal location of the prsh exploit target
 */
const u32
base_offset = 0x0D40AC6D;

/*
 * IV used for encrypting boot data
 */
static u8
prsh_iv[0x10] =
{
	0x0A, 0xAB, 0xA5, 0x30,
	0x2E, 0x90, 0x12, 0xD9,
	0x08, 0x51, 0x74, 0xE8,
	0x6B, 0x83, 0xEC, 0x22,
};

static u8
ancast_key[0x10] = {
	0xb5,
	#error fill in ancast key here
};

/*
 * Return the xor checksum of an area of size bytes.
 */
static u32
calc_xor_checksum(void *ptr, u32 size)
{
	u32 i, checksum = 0, *wptr = (u32 *)ptr;
	for (i = 0; i < (size / sizeof(u32)); i++) {
		checksum ^= wptr[i];
	}
	return checksum;
}

/*
 * Craft a fake PRSH header containing a boot_info
 * section pointing to the specified address.
 */
void
craft_prsh_header()
{
	prsh_t *prsh;
	prst_t *prst;
	prsh_section_t *boot_info;
	void *prsh_checksum_addr;
	u32 prsh_checksum_size;
	void *prst_checksum_addr;
	u32 prst_checksum_size;

	/* clear previous PRSH data */
	memset(
		(u8 *)0x10000400,
		0x00000000,
		0x7C00
	);

	/* create PRSH */
	prsh = (prsh_t *)0x10005A54;
	prsh->magic = 0x50525348; // "PRSH"
	prsh->version = 1;
	prsh->unk = 1;
	prsh->max_sections = 0x20;
	prsh->num_sections = 0x1;
	prsh->size = sizeof(*prsh);
	prsh->size += prsh->max_sections * sizeof(prsh_section_t);

	/* create boot_info */
	boot_info = &prsh->sections[0];
	strlcpy(boot_info->name, "boot_info", 0x100);
	boot_info->data = (void *) 0x0D40AC6D; //boot_info_addr;
	boot_info->size = 0x58;
	boot_info->unk = 0x80000000;

	/* create PRST */
	prst = (prst_t *)&prsh->sections[prsh->max_sections];
	prst->size = prsh->size;
	prst->unk = 1;
	prst->magic = 0x50525354; // "PRST"

	/* compute PRSH checksum */
	prsh_checksum_addr = (u8 *)prsh + sizeof(prsh->xor_checksum);
	prsh_checksum_size = sizeof(*prsh) - sizeof(prsh->xor_checksum);
	prsh_checksum_size += prsh->num_sections * sizeof(prsh_section_t);

	prsh->xor_checksum = calc_xor_checksum(
		prsh_checksum_addr,
		prsh_checksum_size
	);

	/* compute PRST checksum */
	prst_checksum_addr = (u8 *)prst + sizeof(prst->xor_checksum);
	prst_checksum_size = sizeof(*prst) - sizeof(prst->xor_checksum);

	prst->xor_checksum = calc_xor_checksum(
		prst_checksum_addr,
		prst_checksum_size
	);

	/* encrypt the PRSH header */
	aes_reset();
	aes_set_iv(prsh_iv);
	aes_set_key(ancast_key);

	aes_encrypt(
		(u8 *)0x10000400,
		(u8 *)0x10000400,
		0x7C00 / 0x10,
		0
	);

	dc_invalidaterange(
		(u8 *)0x10000400,
		0x7C00
	);

	dc_flushrange(
		(u8 *)0x10000400,
		0x7C00
	);
}

/*
 * Latte registers.
 * http://wiiubrew.org/wiki/Hardware/Latte_Registers
 */
#define LT_REG_BASE                   (0x0D800000)
#define LT_RESETS                     (LT_REG_BASE + 0x5E0)
#define LT_RESETS_AHMN                (LT_REG_BASE + 0x5E4)
#define LT_ABIF_CPLTL_OFFSET          (LT_REG_BASE + 0x620)
#define LT_ABIF_CPLTL_DATA            (LT_REG_BASE + 0x624)
#define LT_RESETS_AHB                 (LT_REG_BASE + 0x184)
#define LT_RESETS_COMPAT              (LT_REG_BASE + 0x194)


void smc_shutdown(bool reset)
{
    // write16(MEM_FLUSHREQ, 0b1111);
    // while(read16(MEM_FLUSHREQ) & 0b1111);

    // if(read32(LT_RESETS) & 4) {
    //     write32(LT_ABIF_CPLTL_OFFSET, 0xC0008020);
    //     write32(LT_ABIF_CPLTL_DATA, 0xFFFFFFFF);
    //     write32(LT_ABIF_CPLTL_OFFSET, 0xC0000E60);
    //     write32(LT_ABIF_CPLTL_DATA, 0xFFFFFFDB);
    // }

    // write32(LT_RESETS_AHB, 0xFFFFCE71);
    // write32(LT_RESETS_AHMN, 0xFFFFCD70);
    // write32(LT_RESETS_COMPAT, 0xFF8FCDEF);

    // write16(MEM_REFRESH_FLAG, 0);

    // write16(MEM_SEQ_REG_ADDR, 0x18);
    // write16(MEM_SEQ_REG_VAL, 1);
    // write16(MEM_SEQ_REG_ADDR, 0x19);
    // write16(MEM_SEQ_REG_VAL, 0);
    // write16(MEM_SEQ_REG_ADDR, 0x1A);
    // write16(MEM_SEQ_REG_VAL, 1);

    // write16(MEM_SEQ0_REG_ADDR, 0x18);
    // write16(MEM_SEQ0_REG_VAL, 1);
    // write16(MEM_SEQ0_REG_ADDR, 0x19);
    // write16(MEM_SEQ0_REG_VAL, 0);
    // write16(MEM_SEQ0_REG_ADDR, 0x1A);
    // write16(MEM_SEQ0_REG_VAL, 1);

    if(reset) {
        // {
        //     write32(EXI0_CSR, 0x108);
        //     write32(EXI0_DATA, 0xA1000D00);
        //     write32(EXI0_CR, 0x35);
        //     while(!(read32(EXI0_CSR) & 8));

        //     write32(EXI0_CSR, 0x108);
        //     write32(EXI0_DATA, 0x501);
        //     write32(EXI0_CR, 0x35);
        //     while(!(read32(EXI0_CSR) & 8));

        //     write32(EXI0_CSR, 0);
        // }

        // {
        //     write32(EXI0_CSR, 0x108);
        //     write32(EXI0_DATA, 0xA1000100);
        //     write32(EXI0_CR, 0x35);
        //     while(!(read32(EXI0_CSR) & 8));

        //     write32(EXI0_CSR, 0x108);
        //     write32(EXI0_DATA, 0);
        //     write32(EXI0_CR, 0x35);
        //     while(!(read32(EXI0_CSR) & 8));

        //     write32(EXI0_CSR, 0);
        // }

        clear32(LT_RESETS, 1);
    } //else {
    //     {
    //         write32(EXI0_CSR, 0x108);
    //         write32(EXI0_DATA, 0xA1000100);
    //         write32(EXI0_CR, 0x35);
    //         while(!(read32(EXI0_CSR) & 8));

    //         write32(EXI0_CSR, 0x108);
    //         write32(EXI0_DATA, 0);
    //         write32(EXI0_CR, 0x35);
    //         while(!(read32(EXI0_CSR) & 8));

    //         write32(EXI0_CSR, 0);
    //     }

    //     {
    //         write32(EXI0_CSR, 0x108);
    //         write32(EXI0_DATA, 0xA1000D00);
    //         write32(EXI0_CR, 0x35);
    //         while(!(read32(EXI0_CSR) & 8));

    //         write32(EXI0_CSR, 0x108);
    //         write32(EXI0_DATA, 0x101);
    //         write32(EXI0_CR, 0x35);
    //         while(!(read32(EXI0_CSR) & 8));

    //         write32(EXI0_CSR, 0);
    //     }

    //     {
    //         write32(EXI0_CSR, 0x108);
    //         write32(EXI0_DATA, 0xA1000D00);
    //         write32(EXI0_CR, 0x35);
    //         while(!(read32(EXI0_CSR) & 8));

    //         write32(EXI0_CSR, 0x108);
    //         write32(EXI0_DATA, 0x10101);
    //         write32(EXI0_CR, 0x35);
    //         while(!(read32(EXI0_CSR) & 8));

    //         write32(EXI0_CSR, 0);
    //     }
    // }

    while(true);
}

u32 _main(void *base)
{	//sensorPrep();
	FRESULT fres;
	int res;
	u32 vector=0;
	(void)base;

	gecko_printf("Initializing exceptions...\n");
	exception_initialize();
	gecko_printf("Configuring caches and MMU...\n");
	mem_initialize();

	irq_initialize();
//	irq_enable(IRQ_GPIO1B);
	irq_enable(IRQ_GPIO1);
	irq_enable(IRQ_RESET);
	irq_enable(IRQ_TIMER);
	irq_set_alarm(20, 1);
	gecko_printf("Interrupts initialized\n");

	crypto_initialize();
	gecko_printf("crypto support initialized\n");

	craft_prsh_header();

 	gecko_printf("Shutting down interrupts...\n");
	irq_shutdown();
	gecko_printf("Shutting down caches and MMU...\n");
	//mem_shutdown();

	// reset
	smc_shutdown(1);

	gecko_printf("Vectoring to 0x%08x...\n", vector);
	return vector;
}

