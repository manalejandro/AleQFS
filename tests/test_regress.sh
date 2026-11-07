#!/bin/bash
# Regression tests for bugs fixed in the 2.0.x hardening pass.
set -u

ALEFS=./aleqfs
IMG=/tmp/aleqfs-regress-$$.bin
PASS=0
FAIL=0

cleanup() { rm -f "$IMG" /tmp/aleqfs-regress-content-$$.txt; }
trap cleanup EXIT

ok()   { echo "ok   - $1"; PASS=$((PASS+1)); }
bad()  { echo "FAIL - $1"; FAIL=$((FAIL+1)); }

expect_ok()  { # desc, cmd...
    local d="$1"; shift
    if "$@" >/dev/null 2>&1; then ok "$d"; else bad "$d"; fi
}
expect_fail() {
    local d="$1"; shift
    if "$@" >/dev/null 2>&1; then bad "$d (expected failure)"; else ok "$d"; fi
}

echo "=== AleQFS Regression Suite ==="
$ALEFS format "$IMG" 64 >/dev/null || { echo "format failed"; exit 1; }

# --- 1. directory entry removal must not hide later entries (compaction) ---
$ALEFS mkdir "$IMG" /d >/dev/null
$ALEFS create "$IMG" /d/aaa >/dev/null
$ALEFS create "$IMG" /d/bbb >/dev/null
$ALEFS create "$IMG" /d/ccc >/dev/null
$ALEFS rm "$IMG" /d/aaa >/dev/null
if $ALEFS ls "$IMG" /d 2>/dev/null | grep -q bbb && \
   $ALEFS ls "$IMG" /d 2>/dev/null | grep -q ccc; then
    ok "entries after a removed one stay visible"
else
    bad "entries after a removed one stay visible"
fi
expect_ok   "lookup after deletion works" $ALEFS stat "$IMG" /d/ccc
expect_fail "removed entry is gone"       $ALEFS stat "$IMG" /d/aaa

# --- 2. duplicate mkdir / create must fail (no silent replace) ---
expect_fail "duplicate mkdir fails"  $ALEFS mkdir  "$IMG" /d
expect_fail "duplicate create fails" $ALEFS create "$IMG" /d/bbb

# --- 3. cp-in overwrite semantics ---
echo "version-one" > /tmp/aleqfs-regress-content-$$.txt
$ALEFS cp-in "$IMG" /tmp/aleqfs-regress-content-$$.txt /d/bbb >/dev/null
echo "version-two-longer" > /tmp/aleqfs-regress-content-$$.txt
$ALEFS cp-in "$IMG" /tmp/aleqfs-regress-content-$$.txt /d/bbb >/dev/null
content=$($ALEFS cat "$IMG" /d/bbb 2>/dev/null)
[ "$content" = "version-two-longer" ] && ok "cp-in overwrite replaces content" \
                                      || bad "cp-in overwrite replaces content"

# --- 4. rmdir refuses non-empty directories ---
expect_fail "rmdir non-empty fails" $ALEFS rmdir "$IMG" /d
expect_ok   "mkdir for rmdir test"  $ALEFS mkdir "$IMG" /x
expect_ok   "rmdir empty works"     $ALEFS rmdir "$IMG" /x

# --- 5. mv semantics ---
$ALEFS create "$IMG" /d/mvsrc >/dev/null
echo "mvdata" > /tmp/aleqfs-regress-content-$$.txt
$ALEFS cp-in "$IMG" /tmp/aleqfs-regress-content-$$.txt /d/mvsrc >/dev/null
expect_ok "mv onto existing file overwrites" $ALEFS mv "$IMG" /d/mvsrc /d/ccc
content=$($ALEFS cat "$IMG" /d/ccc 2>/dev/null)
[ "$content" = "mvdata" ] && ok "mv overwrite keeps source content" \
                          || bad "mv overwrite keeps source content"
expect_ok "mv to self is a no-op" $ALEFS mv "$IMG" /d/ccc /d/ccc
expect_fail "mv of missing file fails" $ALEFS mv "$IMG" /d/nope /d/other

# --- 6. large file roundtrip (extent growth + journal coalescing) ---
dd if=/dev/urandom of=/tmp/aleqfs-regress-content-$$.txt bs=1M count=3 status=none
$ALEFS cp-in "$IMG" /tmp/aleqfs-regress-content-$$.txt /big.bin >/dev/null
if cmp -s <($ALEFS cat "$IMG" /big.bin 2>/dev/null) /tmp/aleqfs-regress-content-$$.txt; then
    ok "3 MiB file roundtrips byte-for-byte"
else
    bad "3 MiB file roundtrips byte-for-byte"
fi

# --- 7. grover index is populated and searchable ---
n=$($ALEFS grover "$IMG" 0 2>/dev/null | head -1 | grep -o '[0-9]* result' | grep -o '[0-9]*')
[ "${n:-0}" -ge 3 ] && ok "grover index has entries (pattern 0 matches all)" \
                    || bad "grover index has entries (got ${n:-0})"

# --- 8. decoherence detection ---
$ALEFS stat "$IMG" /big.bin 2>/dev/null | grep -q "Coherence: coherent" \
    && ok "fresh file reports coherent" || bad "fresh file reports coherent"
$ALEFS decohere "$IMG" /big.bin >/dev/null
$ALEFS stat "$IMG" /big.bin 2>/dev/null | grep -q "DECOHERENT" \
    && ok "decohere makes checksum fail" || bad "decohere makes checksum fail"

# --- 9. long names are rejected, not truncated ---
long=$(printf 'x%.0s' $(seq 1 300))
expect_fail "overlong path component rejected" $ALEFS create "$IMG" "/$long"

# --- 10. corrupt image: commands must not crash or hang ---
cp "$IMG" /tmp/aleqfs-regress-corrupt-$$.bin
CIMG=/tmp/aleqfs-regress-corrupt-$$.bin
# corrupt the data area and inode table with pseudo-random garbage
python3 - "$CIMG" <<'EOF'
import sys, random
random.seed(1234)
with open(sys.argv[1], "r+b") as f:
    for _ in range(400):
        off = random.randrange(4096, 64*1024*1024)
        f.seek(off)
        f.write(bytes(random.getrandbits(8) for _ in range(random.randrange(1, 64))))
EOF
crashed=0
# note: img is the 2nd arg for most commands, path the 3rd
for spec in "dump:" "qstatus:" "ls:/" "tree:/" "stat:/d/ccc" "cat:/big.bin" "grover:1" "observe:/d/ccc" "decohere:/d/ccc"; do
    c=${spec%%:*}; a=${spec#*:}
    if command -v timeout >/dev/null; then
        timeout 10 ./aleqfs "$c" "$CIMG" ${a:+"$a"} >/dev/null 2>&1
    else
        ./aleqfs "$c" "$CIMG" ${a:+"$a"} >/dev/null 2>&1
    fi
    rc=$?
    if [ $rc -ge 128 ]; then crashed=1; echo "  command '$c' died with signal ($rc)"; fi
done
# a valid image with corrupted *contents* must still open cleanly or fail
# cleanly; we only require: no signals, no hangs
[ $crashed -eq 0 ] && ok "corrupt image: no crashes/hangs" || bad "corrupt image: no crashes/hangs"
rm -f "$CIMG"

# --- 11. no block/inode leaks across create-delete cycles ---
# note: the grover hash chain allocates up to ~7 structural blocks lazily
# on first inserts; everything else must be accounted for exactly.
dd if=/dev/urandom of=/tmp/aleqfs-regress-content-$$.txt bs=102400 count=1 2>/dev/null
run_cycle() {
    local tag="$1"
    for i in 1 2 3 4 5; do
        $ALEFS cp-in "$IMG" /tmp/aleqfs-regress-content-$$.txt /leak-$tag-$i.bin >/dev/null
        $ALEFS rm "$IMG" /leak-$tag-$i.bin >/dev/null
        $ALEFS mkdir "$IMG" /leakdir-$tag-$i >/dev/null
        $ALEFS rmdir "$IMG" /leakdir-$tag-$i >/dev/null
    done
}
run_cycle a
free1=$($ALEFS qstatus "$IMG" | awk '/Free Blocks/{print $NF}')
ino1=$($ALEFS qstatus "$IMG" | awk '/Free Inodes/{print $NF}')
run_cycle b
free2=$($ALEFS qstatus "$IMG" | awk '/Free Blocks/{print $NF}')
ino2=$($ALEFS qstatus "$IMG" | awk '/Free Inodes/{print $NF}')
leaked=$((free1 - free2))
if [ "$ino1" = "$ino2" ] && [ "$leaked" -le 7 ]; then
    ok "no block/inode leaks across create-delete cycles"
else
    bad "no block/inode leaks across create-delete cycles (blocks $free1->$free2, inodes $ino1->$ino2)"
fi

# --- 12. deep paths (multi-level parents) resolve correctly ---
expect_ok "mkdir deep 1"  $ALEFS mkdir  "$IMG" /deep
expect_ok "mkdir deep 2"  $ALEFS mkdir  "$IMG" /deep/a
expect_ok "mkdir deep 3"  $ALEFS mkdir  "$IMG" /deep/a/b
expect_ok "create deep"   $ALEFS create "$IMG" /deep/a/b/file
$ALEFS ls "$IMG" /deep/a/b 2>/dev/null | grep -q "file" \
    && ok "file lands in the deepest directory" \
    || bad "file lands in the deepest directory"
$ALEFS ls "$IMG" /deep 2>/dev/null | grep -q "file" \
    && bad "file leaked into an intermediate directory" \
    || ok "file not visible in intermediate directory"
expect_ok "mv from deep path"   $ALEFS mv  "$IMG" /deep/a/b/file /deep/moved
expect_ok "cat moved deep file" $ALEFS cat "$IMG" /deep/a/../moved
$ALEFS ls "$IMG" /deep/a/b 2>/dev/null | grep -q "file" \
    && bad "deep mv removed source" || ok "deep mv removed source"

echo
echo "=== Regression suite: $PASS passed, $FAIL failed ==="
[ $FAIL -eq 0 ]
