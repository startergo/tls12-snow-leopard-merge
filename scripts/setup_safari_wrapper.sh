#!/bin/sh
set -e

# Copy dylib to permanent location
mkdir -p /usr/local/lib
cp /tmp/libsecurity_ssl_tls12.dylib /usr/local/lib/libsecurity_ssl_tls12.dylib
echo "Dylib installed to /usr/local/lib/"

# Backup original Safari binary (only if not already backed up)
if [ ! -f /Applications/Safari.app/Contents/MacOS/Safari.real ]; then
    cp /Applications/Safari.app/Contents/MacOS/Safari \
       /Applications/Safari.app/Contents/MacOS/Safari.real
    echo "Safari binary backed up"
else
    echo "Safari backup already exists, skipping"
fi

# Write wrapper script
printf '#!/bin/sh\nexport DYLD_INSERT_LIBRARIES=/usr/local/lib/libsecurity_ssl_tls12.dylib\nexport DYLD_FORCE_FLAT_NAMESPACE=1\nexec /Applications/Safari.app/Contents/MacOS/Safari.real "$@"\n' \
    > /Applications/Safari.app/Contents/MacOS/Safari

chmod +x /Applications/Safari.app/Contents/MacOS/Safari
echo "Safari wrapper installed"
echo ""
echo "Safari MacOS dir:"
ls -la /Applications/Safari.app/Contents/MacOS/
echo ""
echo "Dylib:"
ls -la /usr/local/lib/libsecurity_ssl_tls12.dylib
