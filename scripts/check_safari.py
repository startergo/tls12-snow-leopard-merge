#!/usr/bin/env python
# Check Safari binary state
import struct, subprocess, os

safari_dir = '/Applications/Safari.app/Contents/MacOS'
files = os.listdir(safari_dir)
for f in files:
    path = os.path.join(safari_dir, f)
    size = os.path.getsize(path)
    print('%s (%d bytes)' % (f, size))
    if size < 1000:
        print('  contents: ' + open(path).read())

print('')

# Check Safari.real for LC_LOAD_WEAK_DYLIB
real = os.path.join(safari_dir, 'Safari.real')
with open(real, 'rb') as f:
    data = f.read()

# Find x86_64 slice
narch = struct.unpack('>I', data[4:8])[0]
off = 8
sl_off = None
for i in range(narch):
    cputype = struct.unpack('>i', data[off:off+4])[0]
    foffset = struct.unpack('>I', data[off+8:off+12])[0]
    if cputype == 0x01000007:
        sl_off = foffset
    off += 20

if sl_off:
    ncmds = struct.unpack('<I', data[sl_off+16:sl_off+20])[0]
    p = sl_off + 32
    found = []
    for _ in range(ncmds):
        cmd = struct.unpack('<I', data[p:p+4])[0]
        cmdsize = struct.unpack('<I', data[p+4:p+8])[0]
        if cmd == 0x18:
            name_off = struct.unpack('<I', data[p+8:p+12])[0]
            name = data[p+name_off:p+cmdsize].rstrip(b'\x00')
            found.append(name)
        p += cmdsize
    if found:
        print('Safari.real has LC_LOAD_WEAK_DYLIB: ' + str(found))
    else:
        print('Safari.real is clean (no LC_LOAD_WEAK_DYLIB)')

# Check Info.plist
import subprocess
r = subprocess.Popen(['defaults', 'read',
    '/Applications/Safari.app/Contents/Info.plist',
    'LSArchitecturePriority'],
    stdout=subprocess.PIPE, stderr=subprocess.PIPE)
out, err = r.communicate()
if out.strip():
    print('LSArchitecturePriority: ' + out.strip())
else:
    print('LSArchitecturePriority: not set')
