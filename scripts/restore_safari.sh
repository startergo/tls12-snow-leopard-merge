#!/bin/sh
# Restore Safari to original binary
SAFARI=/Applications/Safari.app/Contents/MacOS/Safari

if [ -f "${SAFARI}.real" ]; then
    cp "${SAFARI}.real" "${SAFARI}"
    echo "Safari restored from backup"
else
    echo "No backup found at ${SAFARI}.real"
fi

ls -la /Applications/Safari.app/Contents/MacOS/
