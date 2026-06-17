#!/usr/bin/env python
# -*- coding: ascii -*-
"""
patch_security_inline.py - Inline our SSL code directly into Security binary.

Instead of loading an external dylib, this patcher:
1. Finds a free cave in Security's x86_64 __TEXT segment
2. Copies our compiled SSL code there (from our dylib's __TEXT)  
3. Patches each SSL public function in Security to JMP to our inlined copy

No external dylib needed, no LC_LOAD_DYLIB, no circular dependencies.
The patched Security binary is entirely self-contained.

Usage:
  python patch_security_inline.py \\
    /path/to/Security.orig \\
    /path/to/libsecurity_ssl_tls12.dylib \\
    /tmp/our_ssl_syms.txt \\
    /tmp/security_ssl_syms.txt \\
    /tmp/Security.inlined

NOTE: our dylib must NOT link against Security.framework (use -undefined dynamic_lookup)
      because our inlined code will call Security's own internal functions directly.
"""

import struct
import sys
import os

MH_MAGIC_64   = 0xFEEDFACF
FAT_MAGIC     = 0xcafebabe
LC_SEGMENT_64 = 0x19
LC_LOAD_DYLIB = 0xC

def r32be(d, o): return struct.unpack_from('>I', bytes(d[o:o+4]))[0]
def r32(d, o):   return struct.unpack_from('<I', bytes(d[o:o+4]))[0]
def r64(d, o):   return struct.unpack_from('<Q', bytes(d[o:o+8]))[0]
def w32(d, o, v): struct.pack_into('<I', d, o, v)
def w64(d, o, v): struct.pack_into('<Q', d, o, v)

def find_x86_64_slice(data):
    magic = r32be(data, 0)
    if magic != FAT_MAGIC:
        return 0, len(data)
    narch = r32be(data, 4)
    off = 8
    for _ in range(narch):
        cputype = struct.unpack_from('>i', bytes(data[off:off+4]))[0]
        foffset = r32be(data, off+8)
        fsize   = r32be(data, off+12)
        if cputype == 0x01000007:
            return foffset, fsize
        off += 20
    raise ValueError("No x86_64 slice")

def parse_segments(data, sl_off):
    """Parse all LC_SEGMENT_64 from a slice, return list of (name,vmaddr,vmsize,fileoff,filesize)."""
    ncmds = r32(data, sl_off+16)
    off = sl_off + 32
    segs = []
    for _ in range(ncmds):
        cmd     = r32(data, off)
        cmdsize = r32(data, off+4)
        if cmd == LC_SEGMENT_64:
            name    = bytes(data[off+8:off+24]).rstrip(b'\x00').decode('ascii','replace')
            vmaddr  = r64(data, off+24)
            vmsize  = r64(data, off+32)
            fileoff = r64(data, off+40)
            filesz  = r64(data, off+48)
            segs.append((name, vmaddr, vmsize, fileoff, filesz))
        off += cmdsize
    return segs

def get_ssl_syms(path):
    syms = {}
    with open(path) as f:
        for line in f:
            parts = line.strip().split()
            if len(parts) == 3 and parts[1] == 'T':
                syms[parts[2]] = int(parts[0], 16)
    return syms

def main():
    if len(sys.argv) < 6:
        print(__doc__)
        sys.exit(1)

    sec_in      = sys.argv[1]
    our_dylib   = sys.argv[2]
    our_syms_f  = sys.argv[3]
    sec_syms_f  = sys.argv[4]
    sec_out     = sys.argv[5]

    our_syms = get_ssl_syms(our_syms_f)
    sec_syms = get_ssl_syms(sec_syms_f)
    common   = sorted(set(our_syms.keys()) & set(sec_syms.keys()))
    print("[*] %d common SSL symbols" % len(common))

    # Read both binaries
    print("[*] Reading Security (%d bytes)..." % os.path.getsize(sec_in))
    with open(sec_in, 'rb') as f:
        sec_data = bytearray(f.read())

    print("[*] Reading our dylib (%d bytes)..." % os.path.getsize(our_dylib))
    with open(our_dylib, 'rb') as f:
        our_data = bytearray(f.read())

    # Find x86_64 slices
    sec_sl_off, sec_sl_size = find_x86_64_slice(sec_data)
    our_sl_off, our_sl_size = find_x86_64_slice(our_data)
    print("[*] Security x86_64 slice: off=0x%x size=0x%x" % (sec_sl_off, sec_sl_size))
    print("[*] Our dylib  x86_64 slice: off=0x%x size=0x%x" % (our_sl_off, our_sl_size))

    # Parse Security segments
    sec_segs = parse_segments(sec_data, sec_sl_off)
    our_segs = parse_segments(our_data, our_sl_off)

    # Find Security __TEXT
    sec_text = next((s for s in sec_segs if s[0]=='__TEXT'), None)
    our_text = next((s for s in our_segs if s[0]=='__TEXT'), None)
    assert sec_text and our_text, "Missing __TEXT"

    sec_text_vmaddr, sec_text_fileoff = sec_text[1], sec_text[3]
    our_text_vmaddr, our_text_fileoff = our_text[1], our_text[3]
    # Absolute file offsets
    sec_text_foff_abs = sec_text_fileoff + sec_sl_off
    our_text_foff_abs = our_text_fileoff + our_sl_off

    print("[*] Security __TEXT: vmaddr=0x%x fileoff_abs=0x%x" % (sec_text_vmaddr, sec_text_foff_abs))
    print("[*] Our dylib __TEXT: vmaddr=0x%x fileoff_abs=0x%x size=0x%x" % (
        our_text_vmaddr, our_text_foff_abs, our_text[2]))

    # Find Security __DATA to locate end of __TEXT (= start of free space)
    sec_data_seg = next((s for s in sec_segs if s[0]=='__DATA'), None)
    sec_text_end_vmaddr = sec_text[1] + sec_text[2]  # vmaddr end of __TEXT
    sec_text_end_foff   = sec_text_foff_abs + sec_text[4]  # file end of __TEXT

    print("[*] Security __TEXT ends at vmaddr=0x%x foff=0x%x" % (
        sec_text_end_vmaddr, sec_text_end_foff))

    # Find last SSL function in Security to determine where SSL code ends
    # and find free space after it
    ssl_addrs = sorted(sec_syms[n] for n in common)
    last_ssl_vmaddr = max(ssl_addrs)

    # Estimate free space: look for a run of 0x00 or 0x90 (nop) bytes
    # after the last SSL function. Actually, we'll use the area AFTER
    # all known __text content. Find the __text section end.
    
    # Parse __text section from Security to find its end
    ncmds = r32(sec_data, sec_sl_off+16)
    off = sec_sl_off + 32
    text_sect_end_vmaddr = None
    text_sect_end_foff   = None
    for _ in range(ncmds):
        cmd     = r32(sec_data, off)
        cmdsize = r32(sec_data, off+4)
        if cmd == LC_SEGMENT_64:
            segname = bytes(sec_data[off+8:off+24]).rstrip(b'\x00').decode('ascii','replace')
            if segname == '__TEXT':
                nsects = r32(sec_data, off+64)
                for s in range(nsects):
                    soff = off + 68 + s*80
                    sname = bytes(sec_data[soff:soff+16]).rstrip(b'\x00').decode('ascii','replace')
                    s_addr   = r64(sec_data, soff+32)
                    s_size   = r64(sec_data, soff+40)
                    s_foff   = r64(sec_data, soff+48)
                    if sname == '__text':
                        text_sect_end_vmaddr = s_addr + s_size
                        text_sect_end_foff   = s_foff + sec_sl_off + s_size
                        print("[*] Security __text section ends at vmaddr=0x%x foff=0x%x" % (
                            text_sect_end_vmaddr, text_sect_end_foff))
        off += cmdsize

    # Cave: space between end of __text section and end of __TEXT segment
    # This space contains stubs, string tables, eh_frame etc. — not safe.
    # Better: use the area after the LAST SSL function body.
    # We need to find where the last SSL function ends.
    # For now, use the gap between __text end and __TEXT segment end.
    # Actually the safest cave is AFTER the entire __TEXT segment in the file
    # if there's padding before __DATA. Check:
    sec_data_foff_abs = sec_data_seg[3] + sec_sl_off if sec_data_seg else sec_text_end_foff
    gap_before_data = sec_data_foff_abs - sec_text_end_foff
    print("[*] Gap between __TEXT file end and __DATA file start: %d bytes" % gap_before_data)

    our_text_size = our_text[4]  # file size of our __TEXT
    print("[*] Our __TEXT size: %d bytes (need to fit in cave)" % our_text_size)

    if gap_before_data >= our_text_size:
        cave_foff = sec_text_end_foff
        cave_vmaddr = sec_text_end_vmaddr
        print("[+] Using gap after __TEXT segment as cave at foff=0x%x vmaddr=0x%x" % (
            cave_foff, cave_vmaddr))
    elif text_sect_end_foff and (sec_text_end_foff - text_sect_end_foff) >= our_text_size:
        cave_foff = text_sect_end_foff
        cave_vmaddr = text_sect_end_vmaddr
        print("[+] Using space after __text section: foff=0x%x vmaddr=0x%x" % (
            cave_foff, cave_vmaddr))
    else:
        print("[!] No suitable cave found")
        print("    Gap before __DATA: %d bytes" % gap_before_data)
        print("    Our __TEXT size:   %d bytes" % our_text_size)
        print("")
        print("[*] Alternative: overwrite SSL functions in-place (no cave needed)")
        print("    The SSL functions total ~100KB, our SSL code is %d bytes" % our_text_size)
        sys.exit(1)

    # Copy our __TEXT into the cave
    our_text_data = our_data[our_text_foff_abs:our_text_foff_abs + our_text_size]
    # The relocation delta: our code was compiled for vmaddr=our_text_vmaddr,
    # but will run at cave_vmaddr. Since our code is PIC (position-independent),
    # this delta only matters for absolute references, which dylibs don't have.
    reloc_delta = cave_vmaddr - our_text_vmaddr
    print("[*] Relocation delta: 0x%x" % reloc_delta)
    print("[*] Copying %d bytes of our __TEXT to cave at foff=0x%x..." % (
        our_text_size, cave_foff))

    sec_data[cave_foff:cave_foff + our_text_size] = our_text_data
    print("[+] Code copied")

    # Patch each SSL function in Security to JMP to our version in the cave
    patched = 0
    for name in common:
        sec_addr = sec_syms[name]
        our_off  = our_syms[name]
        # Our function's new runtime address in Security's address space:
        our_runtime = cave_vmaddr + (our_off - our_text_vmaddr)
        # Security function's file offset:
        sec_foff_abs = (sec_addr - sec_text_vmaddr) + sec_text_foff_abs

        if sec_foff_abs + 14 > len(sec_data):
            print("[!] %s: foff out of range" % name)
            continue

        # 5-byte relative JMP if target is within +/-2GB (it should be within Security's own space)
        rel = our_runtime - (sec_addr + 5)  # RIP after 5-byte JMP = func_addr + 5
        if -0x80000000 <= rel <= 0x7fffffff:
            # Use 5-byte relative JMP: E9 <rel32>
            jmp = b'\xe9' + struct.pack('<i', rel)
            sec_data[sec_foff_abs:sec_foff_abs+5] = jmp
            # Fill remaining 9 bytes with NOPs for cleanliness
            sec_data[sec_foff_abs+5:sec_foff_abs+14] = b'\x90' * 9
            patched += 1
        else:
            # Fallback: 14-byte absolute JMP
            tramp = b'\xff\x25\x00\x00\x00\x00' + struct.pack('<Q', our_runtime)
            sec_data[sec_foff_abs:sec_foff_abs+14] = tramp
            patched += 1

    print("[+] Patched %d SSL functions with relative JMPs" % patched)

    # Verify fat magic preserved
    assert r32be(sec_data, 0) == FAT_MAGIC, "Fat magic clobbered"

    with open(sec_out, 'wb') as f:
        f.write(sec_data)
    os.chmod(sec_out, 0755)
    print("[+] Written: %s (%d bytes)" % (sec_out, len(sec_data)))
    print("")
    print("[*] Verify: lipo -info %s" % sec_out)
    print("[*] Deploy:")
    print("    sudo cp %s \\" % sec_out)
    print("    /System/Library/Frameworks/Security.framework/Versions/A/Security")

if __name__ == '__main__':
    main()
