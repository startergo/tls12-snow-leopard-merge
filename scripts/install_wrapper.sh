#!/bin/sh
set -e

# Install dylib permanently
mkdir -p /usr/local/lib
cp /tmp/libsecurity_ssl_tls12.dylib /usr/local/lib/libsecurity_ssl_tls12.dylib
echo "Dylib installed to /usr/local/lib/"

# Backup original Safari binary
SAFARI=/Applications/Safari.app/Contents/MacOS/Safari
if [ ! -f "${SAFARI}.real" ]; then
    cp "$SAFARI" "${SAFARI}.real"
    echo "Safari binary backed up to Safari.real"
else
    echo "Backup already exists, skipping"
fi

# Write wrapper (using printf to avoid heredoc issues)
printf '%s\n' \
    '#!/bin/sh' \
    'export DYLD_INSERT_LIBRARIES=/usr/local/lib/libsecurity_ssl_tls12.dylib' \
    'export DYLD_FORCE_FLAT_NAMESPACE=1' \
    'exec /Applications/Safari.app/Contents/MacOS/Safari.real "$@"' \
    > "$SAFARI"

chmod +x "$SAFARI"
echo "Wrapper installed"
echo ""
ls -la /Applications/Safari.app/Contents/MacOS/
echo ""
ls -la /usr/local/lib/libsecurity_ssl_tls12.dylib
