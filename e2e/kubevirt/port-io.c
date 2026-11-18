// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

// Minimal x86 port-I/O and MMIO helper for the e2e probes (static musl
// build, compiled at probe time and staged into the guest; it does not
// ship in the guest image).
//
// /dev/port performs byte-granular IN/OUT, but emulated registers like the
// PCI config address (0xcf8) and the ICH9 TCO counters need word/dword
// access — byte writes are silently dropped by the emulation. The guest
// busybox also has no devmem applet, so chipset MMIO (the RCBA/GCS
// register) needs a mapping. This helper performs real OUT instructions
// after iopl(3) and maps physical pages through /dev/mem.
//
// Usage:
//   port-io read8|read16|read32 <port>          -> hex value on stdout
//   port-io write8|write16|write32 <port> <value>
//   port-io mem-read <phys-addr> [width]        width: 8|16|32 (default 32)
//   port-io mem-write <phys-addr> <value> [width]
//
// Ports, addresses, and values are accepted in decimal or 0x-hex. Exits
// non-zero on argument, iopl, or mmap failure.

#include <errno.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <unistd.h>
#include <sys/io.h>

static unsigned long parse_num(const char *text) {
    return strtoul(text, NULL, 0);
}

static int fail_usage(void) {
    fprintf(stderr,
            "usage: port-io read8|read16|read32 <port>\n"
            "       port-io write8|write16|write32 <port> <value>\n"
            "       port-io mem-read <phys-addr> [width]\n"
            "       port-io mem-write <phys-addr> <value> [width]\n");
    return 2;
}

static int mem_access(int argc, char **argv, const char *op) {
    if (argc < 3) {
        return fail_usage();
    }
    unsigned long addr = parse_num(argv[2]);
    long page = (long)(addr & ~(unsigned long)0xfff);
    size_t offset_in_page = (size_t)(addr & 0xfff);
    int width = 32;
    if (strcmp(op, "mem-write") == 0) {
        if (argc < 4) {
            return fail_usage();
        }
        if (argc >= 5) {
            width = (int)parse_num(argv[4]);
        }
    } else if (argc >= 4) {
        width = (int)parse_num(argv[3]);
    }
    int fd = open("/dev/mem", O_RDWR | O_SYNC);
    if (fd < 0) {
        fprintf(stderr, "open /dev/mem failed: %s\n", strerror(errno));
        return 1;
    }
    volatile void *map =
        mmap(NULL, 0x1000, PROT_READ | PROT_WRITE, MAP_SHARED, fd, (off_t)page);
    if (map == MAP_FAILED) {
        fprintf(stderr, "mmap /dev/mem at 0x%lx failed: %s\n",
                (unsigned long)page, strerror(errno));
        close(fd);
        return 1;
    }
    volatile void *reg = (volatile char *)map + offset_in_page;
    int rc = 0;
    if (strcmp(op, "mem-read") == 0) {
        switch (width) {
        case 8:
            printf("0x%02x\n", *(volatile uint8_t *)reg);
            break;
        case 16:
            printf("0x%04x\n", *(volatile uint16_t *)reg);
            break;
        case 32:
            printf("0x%08x\n", *(volatile uint32_t *)reg);
            break;
        default:
            fprintf(stderr, "bad width %d\n", width);
            rc = 2;
        }
    } else {
        unsigned long value = parse_num(argv[3]);
        switch (width) {
        case 8:
            *(volatile uint8_t *)reg = (uint8_t)value;
            break;
        case 16:
            *(volatile uint16_t *)reg = (uint16_t)value;
            break;
        case 32:
            *(volatile uint32_t *)reg = (uint32_t)value;
            break;
        default:
            fprintf(stderr, "bad width %d\n", width);
            rc = 2;
        }
    }
    munmap((void *)map, 0x1000);
    close(fd);
    return rc;
}

int main(int argc, char **argv) {
    if (argc < 3) {
        return fail_usage();
    }
    if (strncmp(argv[1], "mem-", 4) == 0) {
        return mem_access(argc, argv, argv[1]);
    }
    if (iopl(3) != 0) {
        fprintf(stderr, "iopl(3) failed: %s\n", strerror(errno));
        return 1;
    }
    const char *op = argv[1];
    unsigned long port = parse_num(argv[2]);
    if (port > 0xffff) {
        fprintf(stderr, "port out of range: %lu\n", port);
        return 2;
    }

    if (strcmp(op, "read8") == 0) {
        printf("0x%02x\n", inb((unsigned short)port));
        return 0;
    }
    if (strcmp(op, "read16") == 0) {
        printf("0x%04x\n", inw((unsigned short)port));
        return 0;
    }
    if (strcmp(op, "read32") == 0) {
        printf("0x%08x\n", inl((unsigned short)port));
        return 0;
    }
    if (argc < 4) {
        return fail_usage();
    }
    unsigned long value = parse_num(argv[3]);
    if (strcmp(op, "write8") == 0) {
        outb((uint8_t)value, (unsigned short)port);
        return 0;
    }
    if (strcmp(op, "write16") == 0) {
        outw((uint16_t)value, (unsigned short)port);
        return 0;
    }
    if (strcmp(op, "write32") == 0) {
        outl((uint32_t)value, (unsigned short)port);
        return 0;
    }
    return fail_usage();
}
