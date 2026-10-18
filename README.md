# LC-3 Virtual Machine

A 16-bit [LC-3](https://en.wikipedia.org/wiki/Little_Computer_3) emulator in C for Windows, following [Write your Own Virtual Machine](https://www.jmeiners.com/lc3-vm/).

## What it implements

- 65,536 × 16-bit memory (programs load at `0x3000`)
- Registers: R0–R7, PC, COND (N/Z/P)
- All 16 opcodes (RTI/RES abort)
- Addressing: immediate, register, PC-relative, indirect, base+offset
- Fetch–decode–execute loop
- Traps: GETC, OUT, PUTS, IN, PUTSP, HALT
- Memory-mapped keyboard (KBSR `0xFE00`, KBDR `0xFE02`)
- `.obj` loading with big-endian byte swap
- Unbuffered console input + Ctrl+C cleanup

## Build

Uses the MinGW already on this machine. MinGW’s `bin` must be on `PATH` for that shell session (DLLs), but nothing is installed permanently:

```powershell
.\build.bat
```

Or manually:

```powershell
$env:PATH = "C:\MinGW\bin;" + $env:PATH
gcc -Wall -Wextra -O2 lc3.c -o lc3-vm.exe
```

## Run demos

```powershell
.\lc3-vm.exe roms\2048.obj
.\lc3-vm.exe roms\rogue.obj
```

- **2048:** WASD to move; answer `y` if prompted about ANSI
- **Rogue:** arrow-key style movement in the terminal
- **Ctrl+C:** restores the console and exits

## Layout

```
lc3.c           VM source
lc3-vm.exe      built binary
roms/2048.obj   demo game
roms/rogue.obj  demo game
```

Demo `.obj` files are from [justinmeiners/lc3-vm](https://github.com/justinmeiners/lc3-vm) (`docs/supplies/`).

## Extras

```powershell
.\lc3-vm.exe --trace roms\halt.obj          # every instruction decoded
.\lc3-vm.exe --stats roms\2048.obj          # opcode mix on exit / Ctrl+C
.\lc3-vm.exe --trace --stats roms\halt.obj  # both
```

- `--trace` — PC, raw hex, mnemonic, R0–R7, N/Z/P (to stderr)
- `--stats` — total instrs, loads/stores/branches, per-opcode counts

Still planned: cache simulator, branch predictor, unit tests, IPS benchmark.
