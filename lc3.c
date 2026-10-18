/* LC-3 Virtual Machine (Windows)
 * Based on "Write your Own Virtual Machine" by Justin Meiners & Ryan Pendleton
 * Tutorial: https://www.jmeiners.com/lc3-vm/  (MIT code)
 *
 * Analysis extras:
 *   --trace --stats --hotspot --cache --bpred --pipeline --heatmap --fuzz
 */
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <time.h>
#include <Windows.h>
#include <conio.h>

enum { R_R0=0,R_R1,R_R2,R_R3,R_R4,R_R5,R_R6,R_R7,R_PC,R_COND,R_COUNT };
enum { FL_POS=1<<0, FL_ZRO=1<<1, FL_NEG=1<<2 };
enum {
    OP_BR=0,OP_ADD,OP_LD,OP_ST,OP_JSR,OP_AND,OP_LDR,OP_STR,
    OP_RTI,OP_NOT,OP_LDI,OP_STI,OP_JMP,OP_RES,OP_LEA,OP_TRAP
};
enum { MR_KBSR=0xFE00, MR_KBDR=0xFE02 };
enum {
    TRAP_GETC=0x20,TRAP_OUT=0x21,TRAP_PUTS=0x22,
    TRAP_IN=0x23,TRAP_PUTSP=0x24,TRAP_HALT=0x25
};

#define MEMORY_MAX (1 << 16)
uint16_t memory[MEMORY_MAX];
uint16_t reg[R_COUNT];

static const char* op_name[16] = {
    "BR","ADD","LD","ST","JSR","AND","LDR","STR",
    "RTI","NOT","LDI","STI","JMP","RES","LEA","TRAP"
};

/* -------------------- feature flags -------------------- */
int g_trace = 0;
int g_stats = 0;
int g_hotspot = 0;
int g_cache = 0;
int g_bpred = 0;
int g_pipeline = 0;
int g_heatmap = 0;
int g_fuzz_n = 0;          /* >0 means run fuzzer instead of a ROM */
int g_quiet_halt = 0;      /* suppress "HALT" during fuzz */
int g_cache_lines = 64;    /* number of cache lines (direct-mapped) */
int g_block_size = 4;      /* words per line */

/* -------------------- --stats -------------------- */
static unsigned long op_count[16];
static unsigned long total_instrs;
static unsigned long count_load, count_store, count_branch;

/* -------------------- --hotspot -------------------- */
static unsigned long* hotspot; /* [MEMORY_MAX] execution counts by PC */

/* -------------------- --heatmap -------------------- */
static unsigned long* heat_r;  /* reads per address */
static unsigned long* heat_w;  /* writes per address */

/* -------------------- --cache (direct-mapped) -------------------- */
typedef struct {
    int valid;
    uint16_t tag;
} cache_line_t;
static cache_line_t* cache_lines;
static unsigned long cache_hits, cache_misses, cache_accesses;

/* -------------------- --bpred (2-bit saturating) -------------------- */
#define BPRED_ENTRIES 64
static uint8_t bpred_table[BPRED_ENTRIES]; /* 0..3 : SN WN WT ST */
static unsigned long bp_lookups, bp_correct;
static unsigned long br_taken, br_not_taken;

/* -------------------- --pipeline (5-stage CPI model) -------------------- */
static unsigned long pipe_cycles;
static unsigned long pipe_stalls_loaduse;
static unsigned long pipe_flush_ctrl;
static int pipe_prev_was_load;
static uint16_t pipe_prev_load_dr;
static uint16_t pipe_prev_instr;

HANDLE hStdin = INVALID_HANDLE_VALUE;
DWORD fdwMode, fdwOldMode;

/* -------------------- platform -------------------- */
void disable_input_buffering(void)
{
    hStdin = GetStdHandle(STD_INPUT_HANDLE);
    GetConsoleMode(hStdin, &fdwOldMode);
    fdwMode = fdwOldMode ^ ENABLE_ECHO_INPUT ^ ENABLE_LINE_INPUT;
    SetConsoleMode(hStdin, fdwMode);
    FlushConsoleInputBuffer(hStdin);
}

void restore_input_buffering(void)
{
    if (hStdin != INVALID_HANDLE_VALUE)
        SetConsoleMode(hStdin, fdwOldMode);
}

uint16_t check_key(void)
{
    return WaitForSingleObject(hStdin, 1000) == WAIT_OBJECT_0 && _kbhit();
}

uint16_t sign_extend(uint16_t x, int bit_count)
{
    if ((x >> (bit_count - 1)) & 1)
        x |= (uint16_t)(0xFFFF << bit_count);
    return x;
}

uint16_t swap16(uint16_t x) { return (uint16_t)((x << 8) | (x >> 8)); }

void update_flags(uint16_t r)
{
    if (reg[r] == 0) reg[R_COND] = FL_ZRO;
    else if (reg[r] >> 15) reg[R_COND] = FL_NEG;
    else reg[R_COND] = FL_POS;
}

void update_flags_buf(uint16_t* regs, uint16_t r)
{
    if (regs[r] == 0) regs[R_COND] = FL_ZRO;
    else if (regs[r] >> 15) regs[R_COND] = FL_NEG;
    else regs[R_COND] = FL_POS;
}

/* -------------------- disassemble / trace -------------------- */
void disassemble(uint16_t instr, char* out, size_t out_sz)
{
    uint16_t op = instr >> 12;
    uint16_t dr = (instr >> 9) & 0x7;
    uint16_t sr1 = (instr >> 6) & 0x7;

    switch (op) {
        case OP_ADD:
        case OP_AND:
            if ((instr >> 5) & 1) {
                int16_t imm5 = (int16_t)sign_extend(instr & 0x1F, 5);
                snprintf(out, out_sz, "%s R%d, R%d, #%d", op_name[op], dr, sr1, imm5);
            } else {
                snprintf(out, out_sz, "%s R%d, R%d, R%d", op_name[op], dr, sr1, instr & 0x7);
            }
            break;
        case OP_NOT:
            snprintf(out, out_sz, "NOT R%d, R%d", dr, sr1);
            break;
        case OP_BR: {
            char nzp[4] = {0}; int n = 0;
            if (instr & 0x800) nzp[n++] = 'n';
            if (instr & 0x400) nzp[n++] = 'z';
            if (instr & 0x200) nzp[n++] = 'p';
            if (!n) strcpy(nzp, "nop");
            snprintf(out, out_sz, "BR%s #%d", nzp, (int16_t)sign_extend(instr & 0x1FF, 9));
            break;
        }
        case OP_JMP:
            if (sr1 == 7) snprintf(out, out_sz, "RET");
            else snprintf(out, out_sz, "JMP R%d", sr1);
            break;
        case OP_JSR:
            if ((instr >> 11) & 1)
                snprintf(out, out_sz, "JSR #%d", (int16_t)sign_extend(instr & 0x7FF, 11));
            else
                snprintf(out, out_sz, "JSRR R%d", sr1);
            break;
        case OP_LD: case OP_ST: case OP_LDI: case OP_STI: case OP_LEA:
            snprintf(out, out_sz, "%s R%d, #%d", op_name[op], dr,
                     (int16_t)sign_extend(instr & 0x1FF, 9));
            break;
        case OP_LDR: case OP_STR:
            snprintf(out, out_sz, "%s R%d, R%d, #%d", op_name[op], dr, sr1,
                     (int16_t)sign_extend(instr & 0x3F, 6));
            break;
        case OP_TRAP:
            snprintf(out, out_sz, "TRAP x%02X", instr & 0xFF);
            break;
        default:
            snprintf(out, out_sz, "%s", op_name[op]);
            break;
    }
}

void print_trace(uint16_t pc, uint16_t instr)
{
    char asm_buf[64];
    char flag = '?';
    disassemble(instr, asm_buf, sizeof(asm_buf));
    if (reg[R_COND] & FL_NEG) flag = 'N';
    else if (reg[R_COND] & FL_ZRO) flag = 'Z';
    else if (reg[R_COND] & FL_POS) flag = 'P';
    fprintf(stderr,
            "[TRACE] PC=0x%04X 0x%04X  %-22s "
            "R0=%04X R1=%04X R2=%04X R3=%04X R4=%04X R5=%04X R6=%04X R7=%04X  %c\n",
            pc, instr, asm_buf,
            reg[R_R0], reg[R_R1], reg[R_R2], reg[R_R3],
            reg[R_R4], reg[R_R5], reg[R_R6], reg[R_R7], flag);
}

void record_stats(uint16_t op)
{
    op_count[op]++;
    total_instrs++;
    switch (op) {
        case OP_LD: case OP_LDR: case OP_LDI: case OP_LEA: count_load++; break;
        case OP_ST: case OP_STR: case OP_STI: count_store++; break;
        case OP_BR: case OP_JMP: case OP_JSR: count_branch++; break;
        default: break;
    }
}

void print_stats(void)
{
    unsigned long i;
    fprintf(stderr, "\n=== Instruction mix (--stats) ===\n");
    fprintf(stderr, "Total instructions: %lu\n", total_instrs);
    fprintf(stderr, "Loads: %lu   Stores: %lu   Branches: %lu\n",
            count_load, count_store, count_branch);
    for (i = 0; i < 16; i++) {
        if (!op_count[i]) continue;
        fprintf(stderr, "  %-4s  %8lu  (%5.1f%%)\n", op_name[i], op_count[i],
                total_instrs ? 100.0 * op_count[i] / total_instrs : 0.0);
    }
}

/* -------------------- hotspot -------------------- */
void hotspot_init(void)
{
    hotspot = (unsigned long*)calloc(MEMORY_MAX, sizeof(unsigned long));
    if (!hotspot) { fprintf(stderr, "hotspot alloc failed\n"); exit(1); }
}

void hotspot_record(uint16_t pc)
{
    if (hotspot) hotspot[pc]++;
}

void print_hotspot(void)
{
    int top_n = 15;
    int i, j;
    fprintf(stderr, "\n=== Hot-spot profiler (--hotspot) ===\n");
    fprintf(stderr, "Top %d most-executed addresses:\n", top_n);
    for (i = 0; i < top_n; i++) {
        unsigned long best = 0;
        int best_pc = -1;
        for (j = 0; j < MEMORY_MAX; j++) {
            if (hotspot[j] > best) { best = hotspot[j]; best_pc = j; }
        }
        if (best_pc < 0 || best == 0) break;
        {
            char asm_buf[64];
            uint16_t instr = memory[(uint16_t)best_pc];
            disassemble(instr, asm_buf, sizeof(asm_buf));
            fprintf(stderr, "  #%2d  PC=0x%04X  %8lu x  %-22s  (0x%04X)\n",
                    i + 1, best_pc, best, asm_buf, instr);
            hotspot[best_pc] = 0; /* remove so next pass finds next-hottest */
        }
    }
}

/* -------------------- heatmap -------------------- */
void heatmap_init(void)
{
    heat_r = (unsigned long*)calloc(MEMORY_MAX, sizeof(unsigned long));
    heat_w = (unsigned long*)calloc(MEMORY_MAX, sizeof(unsigned long));
    if (!heat_r || !heat_w) { fprintf(stderr, "heatmap alloc failed\n"); exit(1); }
}

void heatmap_read(uint16_t addr)  { if (heat_r) heat_r[addr]++; }
void heatmap_write(uint16_t addr) { if (heat_w) heat_w[addr]++; }

void write_heatmap(void)
{
    /* 64x64 grid, each cell covers 16 addresses (65536/4096=16) */
    enum { G = 64, CELL = 16 };
    unsigned long grid[G][G];
    unsigned long maxv = 1;
    int y, x, k;
    FILE* f;

    memset(grid, 0, sizeof(grid));
    for (k = 0; k < MEMORY_MAX; k++) {
        unsigned long v = (heat_r ? heat_r[k] : 0) + (heat_w ? heat_w[k] : 0);
        int cell = k / CELL;
        y = cell / G;
        x = cell % G;
        if (y >= 0 && y < G && x >= 0 && x < G) {
            grid[y][x] += v;
            if (grid[y][x] > maxv) maxv = grid[y][x];
        }
    }

    f = fopen("heatmap.txt", "w");
    if (f) {
        fprintf(f, "LC-3 memory heatmap (reads+writes). Row-major 64x64, 16 words/cell.\n");
        fprintf(f, "Legend: . cold  +:warm  *:hot  #:hottest\n\n");
        for (y = 0; y < G; y++) {
            for (x = 0; x < G; x++) {
                double t = (double)grid[y][x] / (double)maxv;
                char c = '.';
                if (t > 0.75) c = '#';
                else if (t > 0.40) c = '*';
                else if (t > 0.10) c = '+';
                else if (t > 0.0) c = ':';
                fputc(c, f);
            }
            fputc('\n', f);
        }
        fclose(f);
    }

    f = fopen("heatmap.html", "w");
    if (f) {
        fprintf(f,
            "<!DOCTYPE html><html><head><meta charset=\"utf-8\">"
            "<title>LC-3 Memory Heatmap</title><style>"
            "body{font-family:Segoe UI,sans-serif;background:#0f1419;color:#e7ecf3;}"
            "h1{font-weight:600} .grid{display:grid;grid-template-columns:repeat(64,8px);"
            "gap:1px;width:max-content;border:1px solid #333;padding:8px;background:#1a1f27}"
            ".c{width:8px;height:8px}</style></head><body>"
            "<h1>LC-3 Memory Heatmap</h1>"
            "<p>Each cell = 16 addresses. Color intensity = reads + writes.</p>"
            "<div class=\"grid\">\n");
        for (y = 0; y < G; y++) {
            for (x = 0; x < G; x++) {
                double t = (double)grid[y][x] / (double)maxv;
                int r = (int)(20 + t * 220);
                int gcol = (int)(30 + t * 80);
                int b = (int)(60 + (1.0 - t) * 100);
                fprintf(f, "<div class=\"c\" style=\"background:rgb(%d,%d,%d)\" "
                           "title=\"cell (%d,%d) touches=%lu\"></div>",
                        r, gcol, b, x, y, grid[y][x]);
            }
        }
        fprintf(f, "</div></body></html>\n");
        fclose(f);
    }

    fprintf(stderr, "\n=== Memory heatmap (--heatmap) ===\n");
    fprintf(stderr, "Wrote heatmap.txt and heatmap.html (max cell touches=%lu)\n", maxv);
}

/* -------------------- cache -------------------- */
void cache_init(void)
{
    cache_lines = (cache_line_t*)calloc((size_t)g_cache_lines, sizeof(cache_line_t));
    if (!cache_lines) { fprintf(stderr, "cache alloc failed\n"); exit(1); }
    cache_hits = cache_misses = cache_accesses = 0;
}

void cache_access(uint16_t addr, int is_write)
{
    /* Direct-mapped: line = (addr / block) % lines; tag = addr / (block*lines) */
    uint16_t block = (uint16_t)(addr / g_block_size);
    int idx = (int)(block % (uint16_t)g_cache_lines);
    uint16_t tag = (uint16_t)(block / (uint16_t)g_cache_lines);
    (void)is_write; /* write-allocate / write-through both count as access */

    cache_accesses++;
    if (cache_lines[idx].valid && cache_lines[idx].tag == tag) {
        cache_hits++;
    } else {
        cache_misses++;
        cache_lines[idx].valid = 1;
        cache_lines[idx].tag = tag;
    }
}

void print_cache(void)
{
    double hr = cache_accesses ? 100.0 * cache_hits / cache_accesses : 0.0;
    fprintf(stderr, "\n=== Cache simulator (--cache) ===\n");
    fprintf(stderr, "Direct-mapped: %d lines x %d words/line = %d words\n",
            g_cache_lines, g_block_size, g_cache_lines * g_block_size);
    fprintf(stderr, "Accesses: %lu   Hits: %lu   Misses: %lu   Hit rate: %.2f%%\n",
            cache_accesses, cache_hits, cache_misses, hr);
}

/* -------------------- branch predictor -------------------- */
void bpred_init(void)
{
    int i;
    for (i = 0; i < BPRED_ENTRIES; i++) bpred_table[i] = 1; /* weakly not-taken */
    bp_lookups = bp_correct = br_taken = br_not_taken = 0;
}

void bpred_observe(uint16_t pc, uint16_t op, int taken)
{
    int idx;
    int predict_taken;
    uint8_t* c;

    if (op != OP_BR && op != OP_JMP && op != OP_JSR) return;

    /* JMP/JSR always taken architecturally */
    if (op == OP_JMP || op == OP_JSR) taken = 1;

    if (taken) br_taken++; else br_not_taken++;

    idx = (pc >> 1) & (BPRED_ENTRIES - 1);
    c = &bpred_table[idx];
    predict_taken = (*c >= 2);
    bp_lookups++;
    if (predict_taken == taken) bp_correct++;

    /* 2-bit saturating update */
    if (taken) { if (*c < 3) (*c)++; }
    else       { if (*c > 0) (*c)--; }
}

void print_bpred(void)
{
    double acc = bp_lookups ? 100.0 * bp_correct / bp_lookups : 0.0;
    fprintf(stderr, "\n=== Branch predictor (--bpred) ===\n");
    fprintf(stderr, "2-bit saturating counters, %d entries\n", BPRED_ENTRIES);
    fprintf(stderr, "Branches: taken=%lu  not-taken=%lu\n", br_taken, br_not_taken);
    fprintf(stderr, "Predictions: %lu   Correct: %lu   Accuracy: %.2f%%\n",
            bp_lookups, bp_correct, acc);
}

/* -------------------- pipeline CPI -------------------- */
static int instr_src_uses(uint16_t instr, uint16_t r)
{
    uint16_t op = instr >> 12;
    uint16_t sr1 = (instr >> 6) & 0x7;
    uint16_t sr2 = instr & 0x7;
    int imm = (instr >> 5) & 1;
    switch (op) {
        case OP_ADD: case OP_AND:
            if (sr1 == r) return 1;
            if (!imm && sr2 == r) return 1;
            return 0;
        case OP_NOT: return sr1 == r;
        case OP_LDR: case OP_STR: return sr1 == r;
        case OP_JMP: return sr1 == r;
        case OP_JSR: return ((instr >> 11) & 1) ? 0 : (sr1 == r);
        case OP_ST: case OP_STI: return ((instr >> 9) & 0x7) == r; /* SR */
        default: return 0;
    }
}

static int is_load_op(uint16_t op)
{
    return op == OP_LD || op == OP_LDR || op == OP_LDI;
}

void pipeline_observe(uint16_t instr, int branch_taken)
{
    uint16_t op = instr >> 12;
    uint16_t dr = (instr >> 9) & 0x7;
    /* base: 1 cycle commit in a classic 5-stage peak throughput model */
    pipe_cycles += 1;

    /* load-use hazard: previous was load and this uses its DR */
    if (pipe_prev_was_load && instr_src_uses(instr, pipe_prev_load_dr)) {
        pipe_cycles += 1;
        pipe_stalls_loaduse++;
    }

    /* control hazard: taken branch/jump flushes 2 stages */
    if (branch_taken && (op == OP_BR || op == OP_JMP || op == OP_JSR)) {
        pipe_cycles += 2;
        pipe_flush_ctrl++;
    }

    pipe_prev_was_load = is_load_op(op);
    pipe_prev_load_dr = dr;
    pipe_prev_instr = instr;
}

void print_pipeline(void)
{
    double cpi = total_instrs ? (double)pipe_cycles / (double)total_instrs : 0.0;
    fprintf(stderr, "\n=== Pipeline model (--pipeline) ===\n");
    fprintf(stderr, "5-stage model: IF ID EX MEM WB\n");
    fprintf(stderr, "Instructions: %lu   Cycles: %lu   CPI: %.3f\n",
            total_instrs, pipe_cycles, cpi);
    fprintf(stderr, "Load-use stalls: %lu   Control flushes: %lu\n",
            pipe_stalls_loaduse, pipe_flush_ctrl);
}

/* -------------------- memory with hooks -------------------- */
void mem_write(uint16_t address, uint16_t val)
{
    if (g_heatmap) heatmap_write(address);
    if (g_cache) cache_access(address, 1);
    memory[address] = val;
}

uint16_t mem_read(uint16_t address)
{
    if (g_heatmap) heatmap_read(address);
    if (g_cache) cache_access(address, 0);

    if (address == MR_KBSR) {
        if (check_key()) {
            memory[MR_KBSR] = (1 << 15);
            memory[MR_KBDR] = (uint16_t)getchar();
        } else {
            memory[MR_KBSR] = 0;
        }
    }
    return memory[address];
}

/* Raw memory for fuzzer reference model (no MMIO / no cache side effects). */
uint16_t mem_read_raw(uint16_t address) { return memory[address]; }
void mem_write_raw(uint16_t address, uint16_t val) { memory[address] = val; }

/* -------------------- execute one instruction -------------------- */
/* Returns 1 if a control transfer was taken (for bpred/pipeline). */
int exec_instr(uint16_t instr, int* running)
{
    uint16_t op = instr >> 12;
    int taken = 0;

    switch (op) {
        case OP_ADD: {
            uint16_t r0 = (instr >> 9) & 0x7;
            uint16_t r1 = (instr >> 6) & 0x7;
            if ((instr >> 5) & 1)
                reg[r0] = reg[r1] + sign_extend(instr & 0x1F, 5);
            else
                reg[r0] = reg[r1] + reg[instr & 0x7];
            update_flags(r0);
            break;
        }
        case OP_AND: {
            uint16_t r0 = (instr >> 9) & 0x7;
            uint16_t r1 = (instr >> 6) & 0x7;
            if ((instr >> 5) & 1)
                reg[r0] = reg[r1] & sign_extend(instr & 0x1F, 5);
            else
                reg[r0] = reg[r1] & reg[instr & 0x7];
            update_flags(r0);
            break;
        }
        case OP_NOT: {
            uint16_t r0 = (instr >> 9) & 0x7;
            uint16_t r1 = (instr >> 6) & 0x7;
            reg[r0] = ~reg[r1];
            update_flags(r0);
            break;
        }
        case OP_BR: {
            uint16_t pc_offset = sign_extend(instr & 0x1FF, 9);
            uint16_t cond_flag = (instr >> 9) & 0x7;
            if (cond_flag & reg[R_COND]) {
                reg[R_PC] += pc_offset;
                taken = 1;
            }
            break;
        }
        case OP_JMP: {
            reg[R_PC] = reg[(instr >> 6) & 0x7];
            taken = 1;
            break;
        }
        case OP_JSR: {
            uint16_t long_flag = (instr >> 11) & 1;
            reg[R_R7] = reg[R_PC];
            if (long_flag)
                reg[R_PC] += sign_extend(instr & 0x7FF, 11);
            else
                reg[R_PC] = reg[(instr >> 6) & 0x7];
            taken = 1;
            break;
        }
        case OP_LD: {
            uint16_t r0 = (instr >> 9) & 0x7;
            reg[r0] = mem_read(reg[R_PC] + sign_extend(instr & 0x1FF, 9));
            update_flags(r0);
            break;
        }
        case OP_LDI: {
            uint16_t r0 = (instr >> 9) & 0x7;
            reg[r0] = mem_read(mem_read(reg[R_PC] + sign_extend(instr & 0x1FF, 9)));
            update_flags(r0);
            break;
        }
        case OP_LDR: {
            uint16_t r0 = (instr >> 9) & 0x7;
            uint16_t r1 = (instr >> 6) & 0x7;
            reg[r0] = mem_read(reg[r1] + sign_extend(instr & 0x3F, 6));
            update_flags(r0);
            break;
        }
        case OP_LEA: {
            uint16_t r0 = (instr >> 9) & 0x7;
            reg[r0] = reg[R_PC] + sign_extend(instr & 0x1FF, 9);
            update_flags(r0);
            break;
        }
        case OP_ST: {
            uint16_t r0 = (instr >> 9) & 0x7;
            mem_write(reg[R_PC] + sign_extend(instr & 0x1FF, 9), reg[r0]);
            break;
        }
        case OP_STI: {
            uint16_t r0 = (instr >> 9) & 0x7;
            mem_write(mem_read(reg[R_PC] + sign_extend(instr & 0x1FF, 9)), reg[r0]);
            break;
        }
        case OP_STR: {
            uint16_t r0 = (instr >> 9) & 0x7;
            uint16_t r1 = (instr >> 6) & 0x7;
            mem_write(reg[r1] + sign_extend(instr & 0x3F, 6), reg[r0]);
            break;
        }
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
                case TRAP_PUTS: {
                    uint16_t* c = memory + reg[R_R0];
                    while (*c) { putc((char)*c, stdout); ++c; }
                    fflush(stdout);
                    break;
                }
                case TRAP_IN: {
                    printf("Enter a character: ");
                    {
                        char c = getchar();
                        putc(c, stdout);
                        fflush(stdout);
                        reg[R_R0] = (uint16_t)c;
                        update_flags(R_R0);
                    }
                    break;
                }
                case TRAP_PUTSP: {
                    uint16_t* c = memory + reg[R_R0];
                    while (*c) {
                        char char1 = (*c) & 0xFF;
                        putc(char1, stdout);
                        {
                            char char2 = (*c) >> 8;
                            if (char2) putc(char2, stdout);
                        }
                        ++c;
                    }
                    fflush(stdout);
                    break;
                }
                case TRAP_HALT:
                    if (!g_quiet_halt) {
                        puts("HALT");
                        fflush(stdout);
                    }
                    *running = 0;
                    break;
            }
            break;
        case OP_RES:
        case OP_RTI:
        default:
            abort();
    }
    return taken;
}

/* -------------------- reference model (differential testing) -------------------- */
void ref_exec(uint16_t instr, uint16_t* R, uint16_t* M)
{
    uint16_t op = instr >> 12;
    switch (op) {
        case OP_ADD: {
            uint16_t d=(instr>>9)&7, a=(instr>>6)&7;
            if ((instr>>5)&1) R[d]=R[a]+sign_extend(instr&0x1F,5);
            else R[d]=R[a]+R[instr&7];
            update_flags_buf(R,d);
            break;
        }
        case OP_AND: {
            uint16_t d=(instr>>9)&7, a=(instr>>6)&7;
            if ((instr>>5)&1) R[d]=R[a]&sign_extend(instr&0x1F,5);
            else R[d]=R[a]&R[instr&7];
            update_flags_buf(R,d);
            break;
        }
        case OP_NOT: {
            uint16_t d=(instr>>9)&7, a=(instr>>6)&7;
            R[d] = (uint16_t)~R[a];
            update_flags_buf(R,d);
            break;
        }
        case OP_LEA: {
            uint16_t d=(instr>>9)&7;
            R[d] = R[R_PC] + sign_extend(instr&0x1FF,9);
            update_flags_buf(R,d);
            break;
        }
        case OP_LD: {
            uint16_t d=(instr>>9)&7;
            R[d] = M[(uint16_t)(R[R_PC] + sign_extend(instr&0x1FF,9))];
            update_flags_buf(R,d);
            break;
        }
        case OP_ST: {
            uint16_t s=(instr>>9)&7;
            M[(uint16_t)(R[R_PC] + sign_extend(instr&0x1FF,9))] = R[s];
            break;
        }
        case OP_LDR: {
            uint16_t d=(instr>>9)&7, b=(instr>>6)&7;
            R[d] = M[(uint16_t)(R[b] + sign_extend(instr&0x3F,6))];
            update_flags_buf(R,d);
            break;
        }
        case OP_STR: {
            uint16_t s=(instr>>9)&7, b=(instr>>6)&7;
            M[(uint16_t)(R[b] + sign_extend(instr&0x3F,6))] = R[s];
            break;
        }
        case OP_BR: {
            if (((instr>>9)&7) & R[R_COND])
                R[R_PC] += sign_extend(instr&0x1FF,9);
            break;
        }
        case OP_JMP:
            R[R_PC] = R[(instr>>6)&7];
            break;
        default:
            break; /* fuzz only emits supported ops */
    }
}

static uint16_t rnd16(void) { return (uint16_t)(rand() & 0xFFFF); }

uint16_t fuzz_make_instr(void)
{
    /* Random but valid encodings for differential testing subset */
    int kind = rand() % 9;
    uint16_t dr = rand() % 8;
    uint16_t sr = rand() % 8;
    uint16_t sr2 = rand() % 8;
    switch (kind) {
        case 0: /* ADD imm */
            return (uint16_t)((OP_ADD<<12)|(dr<<9)|(sr<<6)|0x20|(rand()&0x1F));
        case 1: /* ADD reg */
            return (uint16_t)((OP_ADD<<12)|(dr<<9)|(sr<<6)|sr2);
        case 2: /* AND imm */
            return (uint16_t)((OP_AND<<12)|(dr<<9)|(sr<<6)|0x20|(rand()&0x1F));
        case 3: /* AND reg */
            return (uint16_t)((OP_AND<<12)|(dr<<9)|(sr<<6)|sr2);
        case 4: /* NOT */
            return (uint16_t)((OP_NOT<<12)|(dr<<9)|(sr<<6)|0x3F);
        case 5: /* LEA */
            return (uint16_t)((OP_LEA<<12)|(dr<<9)|(rand()&0x1FF));
        case 6: /* LD from scratch near PC — keep offset small */
            return (uint16_t)((OP_LD<<12)|(dr<<9)|(rand()&0x1F));
        case 7: /* ST */
            return (uint16_t)((OP_ST<<12)|(dr<<9)|(rand()&0x1F));
        default: { /* BR with random nzp; offset small */
            uint16_t nzp = (uint16_t)((rand()%7)+1);
            return (uint16_t)((OP_BR<<12)|(nzp<<9)|(rand()&0x1F));
        }
    }
}

int run_fuzzer(int n)
{
    int i, fails = 0;
    uint16_t ref_r[R_COUNT];
    uint16_t* ref_m;
    int saved_cache = g_cache, saved_heat = g_heatmap;

    /* Disable side-effect analyzers during differential compare */
    g_cache = 0;
    g_heatmap = 0;
    g_quiet_halt = 1;

    ref_m = (uint16_t*)malloc(MEMORY_MAX * sizeof(uint16_t));
    if (!ref_m) { fprintf(stderr, "fuzz alloc failed\n"); return 1; }

    fprintf(stderr, "=== Differential fuzzer (--fuzz %d) ===\n", n);
    srand((unsigned)time(NULL));

    for (i = 0; i < n; i++) {
        int r;
        uint16_t instr;
        int running;
        /* Fresh scratch image */
        memset(memory, 0, sizeof(memory));
        for (r = 0; r < R_COUNT; r++) reg[r] = rnd16();
        reg[R_COND] = FL_ZRO;
        reg[R_PC] = 0x3000;
        /* Put some data near PC for LD/ST */
        for (r = 0; r < 64; r++)
            memory[0x3000 + 32 + r] = rnd16();

        memcpy(ref_r, reg, sizeof(ref_r));
        memcpy(ref_m, memory, MEMORY_MAX * sizeof(uint16_t));

        instr = fuzz_make_instr();
        /* Place instr at PC; PC already 0x3000; exec assumes PC was post-incremented */
        /* Mimic fetch: PC points past instr */
        memory[0x3000] = instr;
        reg[R_PC] = 0x3001;
        ref_r[R_PC] = 0x3001;
        ref_m[0x3000] = instr;

        running = 1;
        exec_instr(instr, &running);
        ref_exec(instr, ref_r, ref_m);

        if (memcmp(reg, ref_r, sizeof(reg)) != 0) {
            char buf[64];
            disassemble(instr, buf, sizeof(buf));
            fprintf(stderr, "FAIL #%d instr=0x%04X (%s) register mismatch\n", i, instr, buf);
            fails++;
            if (fails >= 10) break;
            continue;
        }
        /* Compare data region that LD/ST may touch */
        if (memcmp(memory + 0x3000, ref_m + 0x3000, 128 * sizeof(uint16_t)) != 0) {
            fprintf(stderr, "FAIL #%d instr=0x%04X memory mismatch\n", i, instr);
            fails++;
            if (fails >= 10) break;
        }
    }

    free(ref_m);
    g_cache = saved_cache;
    g_heatmap = saved_heat;
    g_quiet_halt = 0;

    fprintf(stderr, "Fuzz cases: %d   Failures: %d   %s\n",
            i, fails, fails ? "VERIFICATION FAILED" : "OK — matches reference model");
    return fails ? 1 : 0;
}

/* -------------------- reports / interrupt -------------------- */
void print_all_reports(void)
{
    if (g_stats) print_stats();
    if (g_hotspot) print_hotspot();
    if (g_cache) print_cache();
    if (g_bpred) print_bpred();
    if (g_pipeline) print_pipeline();
    if (g_heatmap) write_heatmap();
}

void handle_interrupt(int signal)
{
    (void)signal;
    restore_input_buffering();
    printf("\n");
    print_all_reports();
    exit(-2);
}

void read_image_file(FILE* file)
{
    uint16_t origin;
    uint16_t max_read;
    uint16_t* p;
    size_t read;
    fread(&origin, sizeof(origin), 1, file);
    origin = swap16(origin);
    max_read = MEMORY_MAX - origin;
    p = memory + origin;
    read = fread(p, sizeof(uint16_t), max_read, file);
    while (read-- > 0) { *p = swap16(*p); ++p; }
}

int read_image(const char* image_path)
{
    FILE* file = fopen(image_path, "rb");
    if (!file) return 0;
    read_image_file(file);
    fclose(file);
    return 1;
}

void print_usage(void)
{
    printf("Usage: lc3-vm [options] <image-file>\n");
    printf("       lc3-vm --fuzz <N>\n\n");
    printf("Options:\n");
    printf("  --trace              instruction trace\n");
    printf("  --stats              opcode mix profiler\n");
    printf("  --hotspot            hottest PC addresses\n");
    printf("  --cache              direct-mapped cache sim\n");
    printf("  --cache-lines <N>    cache lines (default 64)\n");
    printf("  --block-size <N>     words/line (default 4)\n");
    printf("  --bpred              2-bit branch predictor stats\n");
    printf("  --pipeline           5-stage CPI estimate\n");
    printf("  --heatmap            write heatmap.txt + heatmap.html\n");
    printf("  --fuzz <N>           differential test N random instrs\n");
    printf("  --analyze            enable stats+hotspot+cache+bpred+pipeline+heatmap\n");
}

int main(int argc, const char* argv[])
{
    int image_argc = 0;
    const char* image_argv[64];
    int j;

    if (argc < 2) { print_usage(); exit(2); }

    for (j = 1; j < argc; ++j) {
        if (strcmp(argv[j], "--trace") == 0) g_trace = 1;
        else if (strcmp(argv[j], "--stats") == 0) g_stats = 1;
        else if (strcmp(argv[j], "--hotspot") == 0) g_hotspot = 1;
        else if (strcmp(argv[j], "--cache") == 0) g_cache = 1;
        else if (strcmp(argv[j], "--bpred") == 0) g_bpred = 1;
        else if (strcmp(argv[j], "--pipeline") == 0) g_pipeline = 1;
        else if (strcmp(argv[j], "--heatmap") == 0) g_heatmap = 1;
        else if (strcmp(argv[j], "--analyze") == 0) {
            g_stats = g_hotspot = g_cache = g_bpred = g_pipeline = g_heatmap = 1;
        }
        else if (strcmp(argv[j], "--cache-lines") == 0 && j + 1 < argc) {
            g_cache_lines = atoi(argv[++j]);
            if (g_cache_lines < 1) g_cache_lines = 1;
            g_cache = 1;
        }
        else if (strcmp(argv[j], "--block-size") == 0 && j + 1 < argc) {
            g_block_size = atoi(argv[++j]);
            if (g_block_size < 1) g_block_size = 1;
            g_cache = 1;
        }
        else if (strcmp(argv[j], "--fuzz") == 0 && j + 1 < argc) {
            g_fuzz_n = atoi(argv[++j]);
            if (g_fuzz_n < 1) g_fuzz_n = 1;
        }
        else if (strcmp(argv[j], "--help") == 0 || strcmp(argv[j], "-h") == 0) {
            print_usage();
            exit(0);
        }
        else if (argv[j][0] == '-' && argv[j][1] == '-') {
            printf("Unknown option: %s\n", argv[j]);
            print_usage();
            exit(2);
        }
        else {
            if (image_argc < 64) image_argv[image_argc++] = argv[j];
        }
    }

    if (g_fuzz_n > 0) {
        return run_fuzzer(g_fuzz_n);
    }

    if (image_argc == 0) { print_usage(); exit(2); }

    if (g_hotspot) hotspot_init();
    if (g_heatmap) heatmap_init();
    if (g_cache) cache_init();
    if (g_bpred) bpred_init();
    pipe_cycles = pipe_stalls_loaduse = pipe_flush_ctrl = 0;
    pipe_prev_was_load = 0;

    for (j = 0; j < image_argc; ++j) {
        if (!read_image(image_argv[j])) {
            printf("failed to load image: %s\n", image_argv[j]);
            exit(1);
        }
    }

    signal(SIGINT, handle_interrupt);
    disable_input_buffering();

    reg[R_COND] = FL_ZRO;
    reg[R_PC] = 0x3000;

    {
        int running = 1;
        while (running) {
            uint16_t pc_before = reg[R_PC];
            uint16_t instr = mem_read(reg[R_PC]++);
            uint16_t op = instr >> 12;
            int taken;

            if (g_trace) print_trace(pc_before, instr);
            if (g_stats || g_pipeline) record_stats(op);
            else if (g_hotspot || g_bpred) total_instrs++; /* keep a count if needed */
            if (g_hotspot) hotspot_record(pc_before);

            taken = exec_instr(instr, &running);

            if (g_bpred) bpred_observe(pc_before, op, taken);
            if (g_pipeline) pipeline_observe(instr, taken);
        }
    }

    restore_input_buffering();
    print_all_reports();
    return 0;
}
