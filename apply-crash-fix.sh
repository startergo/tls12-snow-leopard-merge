#!/bin/bash
set -u
VM="${VM:-$(cd "$(dirname "$0")" && pwd)}"
LIB="${KCHAIN_LIB:-$VM/libsecurity_keychain-55017/lib}"
H="$LIB/Keychains.h"
CPP="$LIB/Keychains.cpp"
[ -f "$H" ]   || { echo "FATAL: $H not found (run setup.sh first)"; exit 1; }
[ -f "$CPP" ] || { echo "FATAL: $CPP not found (run setup.sh first)"; exit 1; }

if grep -q "aboutToDestruct" "$H"; then
  echo "Already patched (aboutToDestruct present in Keychains.h). Nothing to do."
  exit 0
fi

[ -f "$H.orig" ]   || cp "$H" "$H.orig"
[ -f "$CPP.orig" ] || cp "$CPP" "$CPP.orig"
echo "backups: $H.orig  $CPP.orig"

python - "$H" << 'PYEOF'
import sys
path = sys.argv[1]
src = open(path).read()
anchor = "virtual ~KeychainImpl();"
if anchor not in src:
    print("FATAL: header anchor 'virtual ~KeychainImpl();' not found"); sys.exit(2)
add = anchor + "\n\n    virtual void aboutToDestruct();"
src = src.replace(anchor, add, 1)
open(path, "w").write(src)
print("header: aboutToDestruct declaration inserted")
PYEOF
[ $? -eq 0 ] || { echo "header edit failed"; exit 3; }

python - "$CPP" << 'PYEOF'
import sys
path = sys.argv[1]
src = open(path).read()
anchor = "bool\nKeychainImpl::operator ==(const KeychainImpl &keychain) const"
if anchor not in src:
    anchor2 = "KeychainImpl::operator ==(const KeychainImpl &keychain) const"
    if anchor2 not in src:
        print("FATAL: impl anchor (operator ==) not found"); sys.exit(2)
    anchor = anchor2
impl = """void
KeychainImpl::aboutToDestruct()
{
    if (inCache())
    {
        globals().storageManager.removeKeychain(dlDbIdentifier(), this);
    }
}

"""
src = src.replace(anchor, impl + anchor, 1)
open(path, "w").write(src)
print("impl: aboutToDestruct definition inserted")
PYEOF
[ $? -eq 0 ] || { echo "impl edit failed"; exit 3; }

echo ""
echo "verify:"
echo "  header decl: $(grep -c aboutToDestruct "$H")"
echo "  impl lines:  $(grep -c aboutToDestruct "$CPP")"
echo "done."
