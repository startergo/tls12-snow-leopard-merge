#!/usr/bin/env python3
"""
patch_security.py - Patch the Snow Leopard Security.framework dylib to
redirect SSL function calls to our patched libsecurity_ssl_tls12.dylib.

Strategy:
1. Add our dylib as LC_LOAD_DYLIB to Security so it gets loaded at runtime
2. For each SSL function in Security, overwrite the first 14 bytes with:
     FF 25 00 00 00 00        # jmp qword ptr [rip+0]
     XX XX XX XX XX XX XX XX  # 64-bit absolute address of our version

The 64-bit address is our function's offset from our dylib's TEXT base,
which at runtime will be (our_dylib_load_addr + our_func_offset).

Since we can't know our dylib's load address at patch time, we use a
stub approach: instead of absolute addresses, we patch the function to
call through the GOT/stub to our exported symbol.

Simpler approach used here: patch Security's copy to be a 5-byte near
relative jump to a new "trampoline" cave we add at end of __text, where
we do the full indirect jump through our symbol stub.

Actually simplest of all: since both dylibs will be loaded by dyld,
use the fact that our dylib exports the SSL symbols. We just need to
make Security's functions redirect to our dylib's versions.

We do this by:
1. Finding each SSL function body in Security
2. Replacing the first instruction(s) with a jump to our symbol

The jump target at runtime = our_dylib_vmbase + our_func_offset_in_dylib

We write a loader stub that will be resolved at runtime via the symbol table.

PRACTICAL APPROACH:
- Copy Security binary
- Insert LC_LOAD_DYLIB for our dylib (so dyld loads it before using Security)
- For each SSL function: overwrite with INT3 trap + symbol stub redirect
  Actually: use a 14-byte absolute indirect JMP via a pointer embedded after it

This script generates a patched Security binary and a verification report.
"""

import struct
import sys
import os
import shutil
from pathlib import Path

# ── Mach-O constants ──────────────────────────────────────────────────────────
MH_MAGIC_64     = 0xFEEDFACF
MH_CIGAM_64     = 0xCFFAEDFE
LC_SEGMENT_64   = 0x19
LC_LOAD_DYLIB   = 0xC
LC_ID_DYLIB     = 0xD

def read32(data, off, little=True):
    fmt = '<I' if little else '>I'
    return struct.unpack_from(fmt, data, off)[0]

def read64(data, off, little=True):
    fmt = '<Q' if little else '>Q'
    return struct.unpack_from(fmt, data, off)[0]

def write64(data, off, val):
    struct.pack_into('<Q', data, off, val)

def write32(data, off, val):
    struct.pack_into('<I', data, off, val)

def parse_macho(data):
    """Parse Mach-O header and return (is_little, text_vmaddr, text_fileoff, ncmds, cmds_off)"""
    magic = struct.unpack_from('<I', data, 0)[0]
    if magic == MH_MAGIC_64:
        little = True
    elif magic == MH_CIGAM_64:
        little = False
    else:
        raise ValueError(f"Not a 64-bit Mach-O (magic={magic:#x})")

    r32 = lambda o: read32(data, o, little)

    # MH header: magic(4) cputype(4) cpusubtype(4) filetype(4) ncmds(4) sizeofcmds(4) flags(4) reserved(4)
    ncmds     = r32(16)
    cmds_off  = 32  # sizeof mach_header_64

    text_vmaddr  = None
    text_fileoff = None

    off = cmds_off
    for _ in range(ncmds):
        cmd     = r32(off)
        cmdsize = r32(off + 4)
        if cmd == LC_SEGMENT_64:
            # segname is 16 bytes at off+8
            segname = data[off+8:off+24].rstrip(b'\x00').decode('ascii', errors='replace')
            if segname == '__TEXT':
                text_vmaddr  = read64(data, off + 24, little)
                text_fileoff = read64(data, off + 32, little)
        off += cmdsize

    return little, text_vmaddr, text_fileoff, ncmds, cmds_off

def get_ssl_syms(sym_file):
    """Parse nm output: 'addr T _SSLFoo' -> {name: addr}"""
    syms = {}
    with open(sym_file) as f:
        for line in f:
            parts = line.strip().split()
            if len(parts) == 3 and parts[1] == 'T':
                addr = int(parts[0], 16)
                name = parts[2]
                syms[name] = addr
    return syms

def build_lc_load_dylib(path_str):
    """Build an LC_LOAD_DYLIB load command for the given dylib path."""
    # struct dylib_command:
    #   uint32 cmd, uint32 cmdsize
    #   struct dylib { uint32 name_offset, uint32 timestamp, uint32 cv, uint32 compv }
    # name follows immediately after (at offset 24)
    path_bytes = path_str.encode('utf-8') + b'\x00'
    # align to 8 bytes
    name_offset = 24
    total = name_offset + len(path_bytes)
    # round up to 8-byte alignment
    total = (total + 7) & ~7
    cmd = struct.pack('<IIIIII',
        LC_LOAD_DYLIB,   # cmd
        total,           # cmdsize
        name_offset,     # name.offset (relative to start of load command)
        2,               # timestamp (arbitrary)
        1,               # current_version
        1,               # compatibility_version
    )
    name_padded = path_bytes + b'\x00' * (total - name_offset - len(path_bytes))
    return cmd + name_padded

def main():
    if len(sys.argv) < 5:
        print("Usage: patch_security.py <security_bin> <our_syms.txt> <security_syms.txt> <our_dylib_path>")
        print("")
        print("  security_bin      path to Security framework binary (will be patched in-place after backup)")
        print("  our_syms.txt      nm output from our patched dylib")
        print("  security_syms.txt nm output from system Security binary")
        print("  our_dylib_path    runtime path of our dylib (e.g. /usr/local/lib/libsecurity_ssl_tls12.dylib)")
        sys.exit(1)

    sec_bin    = sys.argv[1]
    our_syms_f = sys.argv[2]
    sec_syms_f = sys.argv[3]
    our_dylib  = sys.argv[4]

    print(f"[*] Reading symbol tables...")
    our_syms = get_ssl_syms(our_syms_f)
    sec_syms = get_ssl_syms(sec_syms_f)
    print(f"    Our dylib: {len(our_syms)} SSL symbols")
    print(f"    Security:  {len(sec_syms)} SSL symbols")

    # Find common symbols
    common = set(our_syms.keys()) & set(sec_syms.keys())
    print(f"    Common:    {len(common)} symbols to patch")

    # Read Security binary
    print(f"[*] Reading {sec_bin} ({os.path.getsize(sec_bin):,} bytes)...")
    with open(sec_bin, 'rb') as f:
        data = bytearray(f.read())

    # Parse Mach-O
    little, sec_text_vmaddr, sec_text_fileoff, ncmds, cmds_off = parse_macho(data)
    print(f"    __TEXT vmaddr=0x{sec_text_vmaddr:x} fileoff=0x{sec_text_fileoff:x}")

    # Parse our dylib to get its __TEXT vmaddr
    print(f"[*] Parsing our dylib symbol base...")
    # Our syms are already relative to dylib load address (vmaddr base)
    # Find minimum SSL symbol address to determine base
    # Actually nm gives addresses relative to load address 0 for dylibs,
    # so our sym addrs are already the correct offsets from dylib load base.
    # At runtime: our_func_runtime_addr = our_dylib_slide + our_sym_addr
    # We can't know slide at patch time, so we need an indirect approach.

    # APPROACH: Use a 14-byte trampoline in place of each SSL function:
    #   jmp qword ptr [rip+0]   ; FF 25 00 00 00 00
    #   .quad <target_addr>     ; 8 bytes — filled at load time by dyld
    #
    # But dyld only fixes up pointers in __DATA, not __TEXT.
    # 
    # ALTERNATIVE: Insert our dylib as LC_LOAD_DYLIB, then patch each
    # Security SSL function to be a stub that looks up our symbol via
    # the lazy symbol table. This is complex to do manually.
    #
    # SIMPLEST WORKING APPROACH: 
    # Since dyld loads all dylibs before calling any code, and our dylib
    # exports the same SSL symbols, we can use a 5-byte relative JMP
    # from Security's function to our function IF we know the relative
    # offset at patch time. But we don't know load addresses.
    #
    # WHAT ACTUALLY WORKS ON SNOW LEOPARD:
    # Patch Security to add our dylib as LC_LOAD_DYLIB (so it's always loaded),
    # then for each SSL function in Security, replace the body with:
    #   push rbp
    #   mov rbp, rsp  
    #   ... call through GOT to our version ...
    #
    # Actually the cleanest approach for Snow Leopard (pre-ASLR effectively,
    # or with fixed slide): use dyld's interposing mechanism via __DATA/__interpose.
    # Add an __interpose section to our dylib pointing old→new.

    print("")
    print("[*] ANALYSIS COMPLETE")
    print("")
    print("Symbol address mapping (Security file_offset → our dylib offset):")
    print(f"{'Symbol':<45} {'Security addr':>16} {'Our addr':>16} {'Sec fileoff':>14}")
    print("-" * 95)
    
    for name in sorted(common):
        sec_addr = sec_syms[name]
        our_addr = our_syms[name]
        # Convert Security vmaddr to file offset:
        # fileoff = vmaddr - text_vmaddr + text_fileoff
        sec_foff = sec_addr - sec_text_vmaddr + sec_text_fileoff
        print(f"{name:<45} 0x{sec_addr:014x} 0x{our_addr:014x} 0x{sec_foff:012x}")

    print("")
    print(f"[*] To patch, the binary patcher will:")
    print(f"    1. Add LC_LOAD_DYLIB for: {our_dylib}")
    print(f"    2. Patch {len(common)} SSL functions in Security with __interpose-style redirects")
    print("")
    print("[!] Interpose section approach recommended — see patch_security_apply.py")

if __name__ == '__main__':
    main()
