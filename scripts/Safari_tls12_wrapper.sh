#!/bin/sh
export DYLD_INSERT_LIBRARIES=/usr/local/lib/libsecurity_ssl_tls12.dylib
exec arch -x86_64 /Applications/Safari.app/Contents/MacOS/Safari.real "$@"
