/* LC-3 Virtual Machine (Windows)
 * Based on "Write your Own Virtual Machine" by Justin Meiners & Ryan Pendleton
 * Tutorial: https://www.jmeiners.com/lc3-vm/
 * Code license: MIT
 *
 * Extras: --trace (instruction tracing), --stats (instruction-mix profiler)
 */
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <Windows.h>
#include <conio.h>  /* _kbhit */

enum
{
    R_R0 = 0,
    R_R1,
    R_R2,
    R_R3,
    R_R4,
    R_R5,
    R_R6,
    R_R7,
    R_PC, /* program counter */
    R_COND,
    R_COUNT
};

enum
{
    FL_POS = 1 << 0, /* P */
    FL_ZRO = 1 << 1, /* Z */
    FL_NEG = 1 << 2  /* N */
};

enum
{
    OP_BR = 0, /* branch */
    OP_ADD,    /* add */
    OP_LD,     /* load */
    OP_ST,     /* store */
    OP_JSR,    /* jump register */
    OP_AND,    /* bitwise and */
    OP_LDR,    /* load register */
    OP_STR,    /* store register */
    OP_RTI,    /* unused */
    OP_NOT,    /* bitwise not */
    OP_LDI,    /* load indirect */
    OP_STI,    /* store indirect */
    OP_JMP,    /* jump */
    OP_RES,    /* reserved (unused) */
    OP_LEA,    /* load effective address */
    OP_TRAP    /* execute trap */
};

enum
{
    MR_KBSR = 0xFE00, /* keyboard status */
    MR_KBDR = 0xFE02  /* keyboard data */
};

enum
{
    TRAP_GETC  = 0x20, /* get character, not echoed */
    TRAP_OUT   = 0x21, /* output a character */
    TRAP_PUTS  = 0x22, /* output a word string */
    TRAP_IN    = 0x23, /* get character, echoed */
    TRAP_PUTSP = 0x24, /* output a byte string */
    TRAP_HALT  = 0x25  /* halt the program */
};

#define MEMORY_MAX (1 << 16)
uint16_t memory[MEMORY_MAX]; /* 65536 locations */
uint16_t reg[R_COUNT];

/* --- extras: instruction trace + mix profiler --- */
int g_trace = 0;   /* --trace: print each instruction as it runs */
int g_stats = 0;   /* --stats: count opcode mix and print at exit */

/* Mnemonic for each of the 16 opcodes (index == top 4 bits of instr). */
static const char* op_name[16] = {
    "BR", "ADD", "LD", "ST", "JSR", "AND", "LDR", "STR",
    "RTI", "NOT", "LDI", "STI", "JMP", "RES", "LEA", "TRAP"
};

/* How many times each opcode executed (for --stats). */
static unsigned long op_count[16];
static unsigned long total_instrs;
static unsigned long count_load;    /* LD, LDR, LDI, LEA */
static unsigned long count_store;   /* ST, STR, STI */
static unsigned long count_branch;  /* BR, JMP, JSR */

HANDLE hStdin = INVALID_HANDLE_VALUE;
DWORD fdwMode, fdwOldMode;

void disable_input_buffering(void)
{
    hStdin = GetStdHandle(STD_INPUT_HANDLE);
    GetConsoleMode(hStdin, &fdwOldMode); /* save old mode */
    fdwMode = fdwOldMode
            ^ ENABLE_ECHO_INPUT  /* no input echo */
            ^ ENABLE_LINE_INPUT; /* return when characters are available */
    SetConsoleMode(hStdin, fdwMode);
    FlushConsoleInputBuffer(hStdin);
}

void restore_input_buffering(void)
{
    SetConsoleMode(hStdin, fdwOldMode);
}

uint16_t check_key(void)
{
    return WaitForSingleObject(hStdin, 1000) == WAIT_OBJECT_0 && _kbhit();
}

uint16_t sign_extend(uint16_t x, int bit_count)
{
    if ((x >> (bit_count - 1)) & 1) {
        x |= (0xFFFF << bit_count);
    }
    return x;
}

uint16_t swap16(uint16_t x)
{
    return (x << 8) | (x >> 8);
}

void update_flags(uint16_t r)
{
    if (reg[r] == 0) {
        reg[R_COND] = FL_ZRO;
    } else if (reg[r] >> 15) { /* leftmost bit set => negative */
        reg[R_COND] = FL_NEG;
    } else {
        reg[R_COND] = FL_POS;
    }
}

/* Decode one 16-bit instruction into a human-readable mnemonic string. */
void disassemble(uint16_t instr, char* out, size_t out_sz)
{
    uint16_t op = instr >> 12;
    uint16_t dr = (instr >> 9) & 0x7;
    uint16_t sr1 = (instr >> 6) & 0x7;

    switch (op) {
        case OP_ADD:
        case OP_AND:
            if ((instr >> 5) & 1) {
                /* immediate mode: ADD/AND DR, SR1, #imm5 */
                int16_t imm5 = (int16_t)sign_extend(instr & 0x1F, 5);
                snprintf(out, out_sz, "%s R%d, R%d, #%d",
                         op_name[op], dr, sr1, imm5);
            } else {
                /* register mode: ADD/AND DR, SR1, SR2 */
                uint16_t sr2 = instr & 0x7;
                snprintf(out, out_sz, "%s R%d, R%d, R%d",
                         op_name[op], dr, sr1, sr2);
            }
            break;
        case OP_NOT:
            snprintf(out, out_sz, "NOT R%d, R%d", dr, sr1);
            break;
        case OP_BR: {
            /* nzp condition bits sit in bits [11:9] */
            char nzp[4] = {0};
            int n = 0;
            if (instr & 0x800) nzp[n++] = 'n';
            if (instr & 0x400) nzp[n++] = 'z';
            if (instr & 0x200) nzp[n++] = 'p';
            if (n == 0) { /* no bits => unconditional BR in practice rarely used */
                strcpy(nzp, "nop");
            }
            int16_t off9 = (int16_t)sign_extend(instr & 0x1FF, 9);
            snprintf(out, out_sz, "BR%s #%d", nzp, off9);
            break;
        }
        case OP_JMP:
            if (sr1 == 7)
                snprintf(out, out_sz, "RET");
            else
                snprintf(out, out_sz, "JMP R%d", sr1);
            break;
        case OP_JSR:
            if ((instr >> 11) & 1) {
                int16_t off11 = (int16_t)sign_extend(instr & 0x7FF, 11);
                snprintf(out, out_sz, "JSR #%d", off11);
            } else {
                snprintf(out, out_sz, "JSRR R%d", sr1);
            }
            break;
        case OP_LD:
        case OP_ST:
        case OP_LDI:
        case OP_STI:
        case OP_LEA: {
            int16_t off9 = (int16_t)sign_extend(instr & 0x1FF, 9);
            snprintf(out, out_sz, "%s R%d, #%d", op_name[op], dr, off9);
            break;
        }
        case OP_LDR:
        case OP_STR: {
            int16_t off6 = (int16_t)sign_extend(instr & 0x3F, 6);
            snprintf(out, out_sz, "%s R%d, R%d, #%d",
                     op_name[op], dr, sr1, off6);
            break;
        }
        case OP_TRAP:
            snprintf(out, out_sz, "TRAP x%02X", instr & 0xFF);
            break;
        default:
            snprintf(out, out_sz, "%s", op_name[op]);
            break;
    }
}

/* One-line dump used by --trace (PC, hex, mnemonic, regs, flags). */
void print_trace(uint16_t pc, uint16_t instr)
{
    char asm_buf[64];
    disassemble(instr, asm_buf, sizeof(asm_buf));

    /* Flag letter from COND register */
    char flag = '?';
    if (reg[R_COND] & FL_NEG) flag = 'N';
    else if (reg[R_COND] & FL_ZRO) flag = 'Z';
    else if (reg[R_COND] & FL_POS) flag = 'P';

    /* Trace goes to stderr so it does not mix into program PUTS/OUT text */
    fprintf(stderr,
            "[TRACE] PC=0x%04X 0x%04X  %-22s "
            "R0=%04X R1=%04X R2=%04X R3=%04X R4=%04X R5=%04X R6=%04X R7=%04X  %c\n",
            pc, instr, asm_buf,
            reg[R_R0], reg[R_R1], reg[R_R2], reg[R_R3],
            reg[R_R4], reg[R_R5], reg[R_R6], reg[R_R7],
            flag);
}

/* Bucket this opcode into load / store / branch for the mix summary. */
void record_stats(uint16_t op)
{
    op_count[op]++;
    total_instrs++;

    switch (op) {
        case OP_LD: case OP_LDR: case OP_LDI: case OP_LEA:
            count_load++;
            break;
        case OP_ST: case OP_STR: case OP_STI:
            count_store++;
            break;
        case OP_BR: case OP_JMP: case OP_JSR:
            count_branch++;
            break;
        default:
            break;
    }
}

void print_stats(void)
{
    unsigned long i;
    fprintf(stderr, "\n=== Instruction mix (--stats) ===\n");
    fprintf(stderr, "Total instructions: %lu\n", total_instrs);
    fprintf(stderr, "Loads: %lu   Stores: %lu   Branches: %lu\n",
            count_load, count_store, count_branch);
    fprintf(stderr, "\nPer-opcode counts:\n");
    for (i = 0; i < 16; i++) {
        if (op_count[i] == 0) continue; /* skip unused opcodes for readability */
        double pct = total_instrs
            ? (100.0 * (double)op_count[i] / (double)total_instrs)
            : 0.0;
        fprintf(stderr, "  %-4s  %8lu  (%5.1f%%)\n",
                op_name[i], op_count[i], pct);
    }
    fprintf(stderr, "=================================\n");
}

void handle_interrupt(int signal)
{
    (void)signal;
    restore_input_buffering();
    printf("\n");
    if (g_stats) {
        print_stats(); /* still show mix if user hits Ctrl+C mid-game */
    }
    exit(-2);
}

void read_image_file(FILE* file)
{
    /* first word is the load address (origin) */
    uint16_t origin;
    fread(&origin, sizeof(origin), 1, file);
    origin = swap16(origin);

    uint16_t max_read = MEMORY_MAX - origin;
    uint16_t* p = memory + origin;
    size_t read = fread(p, sizeof(uint16_t), max_read, file);

    /* .obj files are big-endian; swap to host little-endian */
    while (read-- > 0) {
        *p = swap16(*p);
        ++p;
    }
}

int read_image(const char* image_path)
{
    FILE* file = fopen(image_path, "rb");
    if (!file) { return 0; }
    read_image_file(file);
    fclose(file);
    return 1;
}

void mem_write(uint16_t address, uint16_t val)
{
    memory[address] = val;
}

uint16_t mem_read(uint16_t address)
{
    if (address == MR_KBSR) {
        if (check_key()) {
            memory[MR_KBSR] = (1 << 15);
            memory[MR_KBDR] = getchar();
        } else {
            memory[MR_KBSR] = 0;
        }
    }
    return memory[address];
}

int main(int argc, const char* argv[])
{
    if (argc < 2) {
        printf("Usage: lc3-vm [--trace] [--stats] <image-file> [...]\n");
        printf("Example: lc3-vm --stats roms\\2048.obj\n");
        printf("         lc3-vm --trace roms\\halt.obj\n");
        exit(2);
    }

    /* Parse flags first; remaining args are .obj image paths. */
    int image_argc = 0;
    const char* image_argv[64];

    for (int j = 1; j < argc; ++j) {
        if (strcmp(argv[j], "--trace") == 0) {
            g_trace = 1;
        } else if (strcmp(argv[j], "--stats") == 0) {
            g_stats = 1;
        } else if (strcmp(argv[j], "--help") == 0 || strcmp(argv[j], "-h") == 0) {
            printf("Usage: lc3-vm [--trace] [--stats] <image-file> [...]\n");
            printf("  --trace   print each instruction (PC, hex, mnemonic, regs, flags)\n");
            printf("  --stats   print opcode mix counts when the program ends\n");
            exit(0);
        } else {
            if (image_argc < 64) {
                image_argv[image_argc++] = argv[j];
            }
        }
    }

    if (image_argc == 0) {
        printf("No image file given.\n");
        printf("Usage: lc3-vm [--trace] [--stats] <image-file> [...]\n");
        exit(2);
    }

    for (int j = 0; j < image_argc; ++j) {
        if (!read_image(image_argv[j])) {
            printf("failed to load image: %s\n", image_argv[j]);
            exit(1);
        }
    }

    signal(SIGINT, handle_interrupt);
    disable_input_buffering();

    /* exactly one condition flag should be set; start with Z */
    reg[R_COND] = FL_ZRO;

    /* default program start address */
    enum { PC_START = 0x3000 };
    reg[R_PC] = PC_START;

    int running = 1;
    while (running) {
        /* FETCH — save PC before increment so --trace shows the instr address */
        uint16_t pc_before = reg[R_PC];
        uint16_t instr = mem_read(reg[R_PC]++);
        uint16_t op = instr >> 12;

        if (g_trace) {
            print_trace(pc_before, instr);
        }
        if (g_stats) {
            record_stats(op);
        }

        switch (op) {
            case OP_ADD:
                {
                    uint16_t r0 = (instr >> 9) & 0x7;
                    uint16_t r1 = (instr >> 6) & 0x7;
                    uint16_t imm_flag = (instr >> 5) & 0x1;

                    if (imm_flag) {
                        uint16_t imm5 = sign_extend(instr & 0x1F, 5);
                        reg[r0] = reg[r1] + imm5;
                    } else {
                        uint16_t r2 = instr & 0x7;
                        reg[r0] = reg[r1] + reg[r2];
                    }
                    update_flags(r0);
                }
                break;
            case OP_AND:
                {
                    uint16_t r0 = (instr >> 9) & 0x7;
                    uint16_t r1 = (instr >> 6) & 0x7;
                    uint16_t imm_flag = (instr >> 5) & 0x1;

                    if (imm_flag) {
                        uint16_t imm5 = sign_extend(instr & 0x1F, 5);
                        reg[r0] = reg[r1] & imm5;
                    } else {
                        uint16_t r2 = instr & 0x7;
                        reg[r0] = reg[r1] & reg[r2];
                    }
                    update_flags(r0);
                }
                break;
            case OP_NOT:
                {
                    uint16_t r0 = (instr >> 9) & 0x7;
                    uint16_t r1 = (instr >> 6) & 0x7;
                    reg[r0] = ~reg[r1];
                    update_flags(r0);
                }
                break;
            case OP_BR:
                {
                    uint16_t pc_offset = sign_extend(instr & 0x1FF, 9);
                    uint16_t cond_flag = (instr >> 9) & 0x7;
                    if (cond_flag & reg[R_COND]) {
                        reg[R_PC] += pc_offset;
                    }
                }
                break;
            case OP_JMP:
                {
                    /* also handles RET (JMP R7) */
                    uint16_t r1 = (instr >> 6) & 0x7;
                    reg[R_PC] = reg[r1];
                }
                break;
            case OP_JSR:
                {
                    uint16_t long_flag = (instr >> 11) & 1;
                    reg[R_R7] = reg[R_PC];
                    if (long_flag) {
                        uint16_t long_pc_offset = sign_extend(instr & 0x7FF, 11);
                        reg[R_PC] += long_pc_offset; /* JSR */
                    } else {
                        uint16_t r1 = (instr >> 6) & 0x7;
                        reg[R_PC] = reg[r1]; /* JSRR */
                    }
                }
                break;
            case OP_LD:
                {
                    uint16_t r0 = (instr >> 9) & 0x7;
                    uint16_t pc_offset = sign_extend(instr & 0x1FF, 9);
                    reg[r0] = mem_read(reg[R_PC] + pc_offset);
                    update_flags(r0);
                }
                break;
            case OP_LDI:
                {
                    uint16_t r0 = (instr >> 9) & 0x7;
                    uint16_t pc_offset = sign_extend(instr & 0x1FF, 9);
                    reg[r0] = mem_read(mem_read(reg[R_PC] + pc_offset));
                    update_flags(r0);
                }
                break;
            case OP_LDR:
                {
                    uint16_t r0 = (instr >> 9) & 0x7;
                    uint16_t r1 = (instr >> 6) & 0x7;
                    uint16_t offset = sign_extend(instr & 0x3F, 6);
                    reg[r0] = mem_read(reg[r1] + offset);
                    update_flags(r0);
                }
                break;
            case OP_LEA:
                {
                    uint16_t r0 = (instr >> 9) & 0x7;
                    uint16_t pc_offset = sign_extend(instr & 0x1FF, 9);
                    reg[r0] = reg[R_PC] + pc_offset;
                    update_flags(r0);
                }
                break;
            case OP_ST:
                {
                    uint16_t r0 = (instr >> 9) & 0x7;
                    uint16_t pc_offset = sign_extend(instr & 0x1FF, 9);
                    mem_write(reg[R_PC] + pc_offset, reg[r0]);
                }
                break;
            case OP_STI:
                {
                    uint16_t r0 = (instr >> 9) & 0x7;
                    uint16_t pc_offset = sign_extend(instr & 0x1FF, 9);
                    mem_write(mem_read(reg[R_PC] + pc_offset), reg[r0]);
                }
                break;
            case OP_STR:
                {
                    uint16_t r0 = (instr >> 9) & 0x7;
                    uint16_t r1 = (instr >> 6) & 0x7;
                    uint16_t offset = sign_extend(instr & 0x3F, 6);
                    mem_write(reg[r1] + offset, reg[r0]);
                }
                break;
            case OP_TRAP:
                reg[R_R7] = reg[R_PC];
                switch (instr & 0xFF) {
                    case TRAP_GETC:
                        reg[R_R0] = (uint16_t)getchar();
                        update_flags(R_R0);
                        break;
                    case TRAP_OUT:
                        putc((char)reg[R_R0], stdout);
                        fflush(stdout);
                        break;
                    case TRAP_PUTS:
                        {
                            uint16_t* c = memory + reg[R_R0];
                            while (*c) {
                                putc((char)*c, stdout);
                                ++c;
                            }
                            fflush(stdout);
                        }
                        break;
                    case TRAP_IN:
                        {
                            printf("Enter a character: ");
                            char c = getchar();
                            putc(c, stdout);
                            fflush(stdout);
                            reg[R_R0] = (uint16_t)c;
                            update_flags(R_R0);
                        }
                        break;
                    case TRAP_PUTSP:
                        {
                            /* two ASCII chars packed per word */
                            uint16_t* c = memory + reg[R_R0];
                            while (*c) {
                                char char1 = (*c) & 0xFF;
                                putc(char1, stdout);
                                char char2 = (*c) >> 8;
                                if (char2) putc(char2, stdout);
                                ++c;
                            }
                            fflush(stdout);
                        }
                        break;
                    case TRAP_HALT:
                        puts("HALT");
                        fflush(stdout);
                        running = 0;
                        break;
                }
                break;
            case OP_RES:
            case OP_RTI:
            default:
                abort();
                break;
        }
    }

    restore_input_buffering();
    if (g_stats) {
        print_stats();
    }
    return 0;
}
