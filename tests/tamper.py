#!/usr/bin/env python3
"""tamper.py <in> <out> <op> [arg]
op = flip <offset> flip the lowest bit of the byte at <offset>
(negative offsets count from the end: -1 = last byte)
truncate <n> remove the last n bytes
append <n> append n zero bytes
setbytes <offset> <hex> overwrite bytes at <offset>"""
import sys

def main() -> int:
    if len(sys.argv) < 4:
        print(__doc__, file=sys.stderr)
        return 1
    src, dst, op = sys.argv[1], sys.argv[2], sys.argv[3]
    rest = sys.argv[4:]
    data = bytearray(open(src, "rb").read())

    if op == "flip":
        data[int(rest[0])] ^= 0x01
    elif op == "truncate":
        del data[len(data) - int(rest[0]):]
    elif op == "append":
        data += bytes(int(rest[0]))
    elif op == "setbytes":
        off, new = int(rest[0]), bytes.fromhex(rest[1])
        data[off:off + len(new)] = new
    else:
        print(__doc__, file=sys.stderr)
        return 1

    open(dst, "wb").write(data)
    return 0

if __name__ == "__main__":
    sys.exit(main())
