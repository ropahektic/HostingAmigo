#!/usr/bin/env python3
from __future__ import annotations
import sys
from pathlib import Path

def main() -> int:
    path = Path(sys.argv[1])
    data = path.read_bytes()
    if data[:4] != b'SCHM':
        print('ERROR: not a WSC file')
        return 1
    body = data[5:]
    print('file:', path)
    print('size:', len(data), 'version:', data[4], 'body:', len(body))
    if len(body) > 0x14:
        print('manual_placement:', body[0x14])
    if len(body) > 0x18:
        print('victories:', body[0x18])
    return 0

if __name__ == '__main__':
    raise SystemExit(main())
