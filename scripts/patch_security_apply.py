#!/usr/bin/env python
# -*- coding: ascii -*-
"""
patch_security_apply.py - Binary-patch Security.framework fat binary to
redirect SSL calls to our patched libsecurity_ssl_tls12.dylib.

Works on the fat binary directly - patches x86_64 slice in-place,
preserving i386 and ppc7400 slices so the system boots correctly.

Usage:
  python patch_security_apply.py \\
    /System/Library/Frameworks/Security.framework/Versions/A/Security \\
    /tmp/our_ssl_syms.txt \\
    /tmp/security_ssl_syms.txt \\
    /usr/local/lib/libsecurity_ssl_tls12.dylib \\
    0 \\
    /tmp/Security.patched

  Pass 0 as vmbase for a dry run.
  Pass 100004000 (or actual load addr from vmmap) to apply patches.
"""

import struct
import sys
import os

MH_MAGIC_64  = 0xFEEDFACF
LC_SEGMENT_64 = 0x19
LC_LOAD_DYLIB      = 0xC
LC_LOAD_WEAK_DYLIB = 0x18  # dyld continues if dylib not found (safe for boot)
FAT_MAGIC     = 0xcafebabe

def r32be(d, o): return struct.unpack_from('>I', bytes(d[o:o+4]))[0]
def r32(d, o):   return struct.unpack_from('<I', bytes(d[o:o+4]))[0]
def r64(d, o):   return struct.unpack_from('<Q', bytes(d[o:o+8]))[0]
def ri32(d, o):  return struct.unpack_from('<i', bytes(d[o:o+4]))[0]
def w32(d, o, v): struct.pack_into('<I', d, o, v)

def extract_x86_64_slice(data):
    """Return (offset, size) of x86_64 slice in fat binary, or (0, len) if thin."""
    magic = r32be(data, 0)
    if magic != FAT_MAGIC:
        return 0, len(data)
    narch = r32be(data, 4)
    off = 8
    for _ in range(narch):
        cputype = struct.unpack_from('>i', bytes(data[off:off+4]))[0]
        foffset = r32be(data, off + 8)
        fsize   = r32be(data, off + 12)
        if cputype == 0x01000007:  # CPU_TYPE_X86_64
            return foffset, fsize
        off += 20
    raise ValueError('No x86_64 slice in fat binary')

def parse_text_segment(s):
    """Parse __TEXT vmaddr and fileoff from a thin Mach-O slice (bytearray or bytes)."""
    assert r32(s, 0) == MH_MAGIC_64, "Not 64-bit LE Mach-O: magic=0x%x" % r32(s, 0)
    ncmds = r32(s, 16)
    off = 32
    for _ in range(ncmds):
        cmd     = r32(s, off)
        cmdsize = r32(s, off + 4)
        if cmd == LC_SEGMENT_64:
            segname = bytes(s[off+8:off+24]).rstrip(b'\x00').decode('ascii', 'replace')
            if segname == '__TEXT':
                vmaddr  = r64(s, off + 24)
                fileoff = r64(s, off + 32)
                return vmaddr, fileoff
        off += cmdsize
    raise ValueError('No __TEXT segment')

def get_header_info(s):
    """Return (header_end, ncmds, sizeofcmds) for a thin Mach-O."""
    ncmds      = r32(s, 16)
    sizeofcmds = r32(s, 20)
    return 32 + sizeofcmds, ncmds, sizeofcmds

def get_first_section_fileoff(s):
    """Find the lowest non-zero section fileoffset in the slice."""
    ncmds = r32(s, 16)
    off = 32
    first = None
    for _ in range(ncmds):
        cmd     = r32(s, off)
        cmdsize = r32(s, off + 4)
        if cmd == LC_SEGMENT_64:
            nsects = r32(s, off + 64)
            for i in range(nsects):
                soff = off + 68 + i * 80
                sect_foff = r64(s, soff + 48)
                if sect_foff > 0 and (first is None or sect_foff < first):
                    first = sect_foff
        off += cmdsize
    return first

def build_lc_load_dylib(path_str):
    path_bytes = path_str.encode('ascii') + b'\x00'
    name_off = 24
    total = (name_off + len(path_bytes) + 7) & ~7
    lc = struct.pack('<IIIIII',
        LC_LOAD_WEAK_DYLIB, total, name_off, 2, 0x10000, 0x10000)
    pad = total - name_off - len(path_bytes)
    return lc + path_bytes + b'\x00' * pad

def get_ssl_syms(path):
    syms = {}
    with open(path) as f:
        for line in f:
            parts = line.strip().split()
            if len(parts) == 3 and parts[1] == 'T':
                syms[parts[2]] = int(parts[0], 16)
    return syms

def main():
    if len(sys.argv) < 7:
        print(__doc__)
        sys.exit(1)

    sec_in     = sys.argv[1]
    our_syms_f = sys.argv[2]
    sec_syms_f = sys.argv[3]
    our_dylib  = sys.argv[4]
    our_base   = int(sys.argv[5], 16)
    sec_out    = sys.argv[6]

    our_syms = get_ssl_syms(our_syms_f)
    sec_syms = get_ssl_syms(sec_syms_f)
    common   = sorted(set(our_syms.keys()) & set(sec_syms.keys()))
    print("[*] %d SSL symbols to patch" % len(common))

    print("[*] Reading %s (%d bytes)..." % (sec_in, os.path.getsize(sec_in)))
    with open(sec_in, 'rb') as f:
        data = bytearray(f.read())

    # Find x86_64 slice within fat binary
    sl_off, sl_size = extract_x86_64_slice(data)
    print("[*] x86_64 slice at file offset 0x%x, size 0x%x" % (sl_off, sl_size))
    sl = data[sl_off:sl_off + sl_size]  # read-only view for parsing

    # Parse __TEXT from slice
    text_vmaddr, text_fileoff_in_slice = parse_text_segment(sl)
    # text_fileoff in the full file:
    text_fileoff_abs = text_fileoff_in_slice + sl_off
    print("[*] __TEXT vmaddr=0x%x fileoff_in_slice=0x%x fileoff_abs=0x%x" % (
        text_vmaddr, text_fileoff_in_slice, text_fileoff_abs))

    # Insert LC_LOAD_DYLIB into x86_64 slice header
    hdr_end, ncmds, sizeofcmds = get_header_info(sl)
    first_sect = get_first_section_fileoff(sl)
    new_lc   = build_lc_load_dylib(our_dylib)
    lc_size  = len(new_lc)
    avail    = (first_sect - hdr_end) if first_sect else 0

    print("[*] Slice header ends at 0x%x, first section at 0x%x, avail=%d need=%d" % (
        hdr_end, first_sect or 0, avail, lc_size))

    if avail >= lc_size:
        ins = sl_off + hdr_end
        data[ins:ins + lc_size] = new_lc
        w32(data, sl_off + 16, ncmds + 1)
        w32(data, sl_off + 20, sizeofcmds + lc_size)
        print("[+] Inserted LC_LOAD_DYLIB for %s" % our_dylib)
    else:
        print("[!] Not enough room for LC_LOAD_DYLIB (%d < %d)" % (avail, lc_size))

    # Patch each SSL function with 14-byte absolute JMP trampoline
    if our_base == 0:
        print("\n[DRY RUN] showing mapping (re-run with vmbase to apply):")
        print("%-45s %-18s %-18s %-14s" % (
            "Symbol", "Sec vmaddr", "Our offset", "Sec abs foff"))
        print("-" * 99)
        for name in common:
            sec_addr = sec_syms[name]
            our_off  = our_syms[name]
            foff_abs = (sec_addr - text_vmaddr) + text_fileoff_abs
            print("%-45s 0x%016x 0x%016x 0x%012x" % (
                name, sec_addr, our_off, foff_abs))
        print("\n[*] Find load addr with:")
        print("    DYLD_INSERT_LIBRARIES=%s sleep 60 &" % our_dylib)
        print("    vmmap $! | grep libsecurity_ssl_tls12")
        return

    patched = 0
    skipped = 0
    for name in common:
        sec_addr    = sec_syms[name]
        our_runtime = our_base + our_syms[name]
        foff_abs    = (sec_addr - text_vmaddr) + text_fileoff_abs

        if foff_abs < 0 or foff_abs + 14 > len(data):
            print("[!] %s: abs foff 0x%x out of range" % (name, foff_abs))
            skipped += 1
            continue

        # FF 25 00 00 00 00 = JMP QWORD PTR [RIP+0]; then 8-byte abs target
        tramp = b'\xff\x25\x00\x00\x00\x00' + struct.pack('<Q', our_runtime)
        data[foff_abs:foff_abs + 14] = tramp
        patched += 1

    print("[+] Patched %d functions, skipped %d" % (patched, skipped))

    # Verify fat binary magic is preserved
    assert r32be(data, 0) == FAT_MAGIC, "Fat magic clobbered!"

    with open(sec_out, 'wb') as f:
        f.write(data)
    os.chmod(sec_out, 0755)
    print("[+] Written: %s (%d bytes)" % (sec_out, len(data)))
    print("")
    print("[*] Verify with: lipo -info %s" % sec_out)
    print("[*] Deploy:")
    print("    sudo cp %s \\" % sec_out)
    print("      /System/Library/Frameworks/Security.framework/Versions/A/Security")

if __name__ == '__main__':
    main()
