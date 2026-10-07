#!/usr/bin/env bash
# Rebuilds the committed smoke samples from their assembly source. Needs SDCC (sdas8051, sdld,
# makebin; Fedora prefixes them sdcc-). CI never runs this: it tests the committed binaries.
#
#   keil8051-smoke.bin        MStar-style flash image: an sBoot marker naming firmware SMOKE1,
#                             module 1 at file 0x100 and module 2 at file 0x10200 (128-aligned,
#                             deliberately not 64K-aligned), 0xff fill in between
#   keil8051-smoke-based.bin  module 1 alone, linked at 0x8000, for a raw import at that base
set -euo pipefail

here="$(cd "$(dirname "$0")" && pwd)"
work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT

tool() {
	for name in "$1" "sdcc-$1"; do
		if command -v "$name" >/dev/null; then
			echo "$name"
			return
		fi
	done
	echo "build.sh: $1 not found; install SDCC" >&2
	exit 1
}
as="$(tool sdas8051)"
ld="$(tool sdld)"
makebin="$(tool makebin)"

# assemble <source> <linked base>: <work>/<source>.bin holds the image from <linked base> up.
assemble() {
	local name="${1%.asm}"
	cp "$here/$1" "$here/module1.inc" "$work/"
	(cd "$work" && "$as" -plosgff "$name.rel" "$1" && "$ld" -i "$name.ihx" "$name.rel" >/dev/null)
	"$makebin" -p -s 65536 -o "$2" "$work/$name.ihx" "$work/$name.bin"
}

fill() {
	head -c "$1" /dev/zero | tr '\0' '\377'
}

# pad <file> <size>: the file's bytes, then 0xff up to <size>.
pad() {
	cat "$1"
	fill $(($2 - $(stat -c %s "$1")))
}

assemble smoke-m1.asm 0
assemble smoke-m2.asm 0
assemble smoke-based.asm 32768

# The analyzer recognises ?C?CCASE by its exact body; a sample that assembles it differently tests
# nothing. This is the signature in KeilCaseHelper.CCASE.
ccase="d0 83 d0 82 f8 e4 93 70 12 74 01 93 70 0d a3 a3 93 f8 74 01 93 f5 82 88 83 e4 73"
ccase+=" 74 02 93 68 60 ef a3 a3 a3 80 df"
for bin in smoke-m1.bin smoke-based.bin; do
	got="$(od -An -tx1 -v -j $((0x380)) -N 38 "$work/$bin" | tr -d ' \n')"
	if [[ "$got" != "${ccase// /}" ]]; then
		echo "build.sh: ?C?CCASE in $bin assembled as $got" >&2
		exit 1
	fi
done

{
	# sBoot marker at 0, its info block at +0x20, the 6-character firmware ID at info +0x78.
	printf 'MSVC0000S3'
	fill $((0x98 - 10))
	printf 'SMOKE1'
	fill $((0x100 - 0x98 - 6))
	pad "$work/smoke-m1.bin" $((0x10200 - 0x100))
	cat "$work/smoke-m2.bin"
} >"$here/keil8051-smoke.bin"

cp "$work/smoke-based.bin" "$here/keil8051-smoke-based.bin"
sha256sum "$here"/keil8051-smoke*.bin
