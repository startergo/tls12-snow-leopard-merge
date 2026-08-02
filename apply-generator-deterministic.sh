#!/bin/bash
# apply-generator-deterministic.sh
# Make the CSSM plugin/transition code generators deterministic.
#
# Two generator.pl scripts emit ABI-critical code (vtable orders, dispatch tables,
# handle-tracking) by iterating Perl hashes with `each %hash` / unsorted `keys %hash`
# -- NON-DETERMINISTIC order. Components generated in different runs get mismatched
# vtables / dispatch, causing:
#   * cdsa_plugin generator -> SSDLSession vtable mismatch -> cssm_Authenticate
#     dispatches into FreeUniqueRecord -> SIGSEGV in killSSUniqueRecord.
#   * cssm generator -> transition.gen dispatch/handle mismatch ->
#     CSSMERR_DL_INVALID_DB_HANDLE on keychain unlock.
# Fix: replace `each %hash` and `keys %hash` with `sort keys %hash` in every emit
# loop so all generations produce identical, consistent output.
#
# Idempotent. Run from the repository root with VM set, or let it self-locate.
set -u
VM="${VM:-$(cd "$(dirname "$0")" && pwd)}"

fix_generator() {
  local F="$1"
  [ -f "$F" ] || { echo "  (skip, not found: $F)"; return 0; }
  if ! grep -q "each %\|(keys %" "$F"; then
    echo "  already deterministic: $F"
    return 0
  fi
  [ -f "$F.pre-sortfix" ] || cp "$F" "$F.pre-sortfix"
  python - "$F" << 'PYEOF'
import sys, re
p = sys.argv[1]
lines = open(p).readlines()
for i, ln in enumerate(lines):
    m = re.match(r'^(\s*)while \(\(\$(\w+), \$(\w+)\) = each %(\w+)\) \{', ln)
    if m:
        ind,k,v,h = m.groups()
        lines[i] = ind+"foreach $"+k+" (sort keys %"+h+") {\n"+ind+"    $"+v+" = $"+h+"{$"+k+"};\n"
        continue
    m2 = re.match(r'^(\s*)while \(\(\$(\w+), \$_\) = each %(\w+)\) \{', ln)
    if m2:
        ind,k,h = m2.groups()
        lines[i] = ind+"foreach $"+k+" (sort keys %"+h+") {\n"+ind+"    $_ = $"+h+"{$"+k+"};\n"
        continue
    m3 = re.match(r'^(\s*)(for|foreach) \$(\w+) \(keys %(\w+)\)', ln)
    if m3:
        ind,kw,k,h = m3.groups()
        lines[i] = ln.replace("(keys %"+h+")", "(sort keys %"+h+")")
open(p,"w").writelines(lines)
PYEOF
  local rem=$(grep -c "each %\|(keys %" "$F")
  local ok=$(perl -c "$F" 2>&1 | grep -c "syntax OK")
  echo "  fixed: $F  (remaining each/keys: $rem, perl syntax OK: $ok)"
}

echo "=== make CSSM code generators deterministic ==="
for gp in "$VM"/libsecurity_cdsa_plugin-*/lib/generator.pl "$VM"/libsecurity_cssm-*/lib/generator.pl; do
  fix_generator "$gp"
done
echo "done. Rebuild cdsa_plugin + cssm (regenerate deterministically) before the DL/CSP components."
