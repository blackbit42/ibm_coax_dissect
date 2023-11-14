"""
12.1 Down Stream Loading
All requests employed in down stream loading use a one byte file identifier.
"""

import os
import sys
from collections import namedtuple

START = 0x0a
STEP = 0x0a
DIR = "tmp"
DUMP_FILES = False

if len(sys.argv) != 2:
    print(f"Usage: {sys.argv[0]} <DSL file>")
    sys.exit(1)

if DUMP_FILES:
    try:
        os.mkdir(DIR)
    except FileExistsError:
        pass

list_ = []

with open(sys.argv[1], mode='rb') as dsl:
    content = dsl.read()
    for i in range(0x40):
        entry = namedtuple('entry', ['id', 'offset', 'length'])
        offset = int.from_bytes(content[START+STEP*i:START+STEP*i+4])
        length = int.from_bytes(content[START+STEP*i+4:START+STEP*i+8])
        list_.append(entry(i+1, offset, length))
        end = offset + length

        if DUMP_FILES:
            if offset == 0x0:
                continue

            with open(f"tmp/{i+1:02x}", mode='wb') as file:
                subfile = content[offset:end]
                file.write(subfile)


for i, v in enumerate(list_):
    if v.offset == 0x0 and v.length == 0x0:
        print(f"id: 0x{v.id:02x}: ---")
        continue

    print(f"id: 0x{v.id:02x}: "
          f"Offset: 0x{v.offset:09x} "
          f"Length: 0x{v.length:09x} "
          f"End: 0x{v.offset + v.length:09x}", end="")

    if i > 0:
        x = 1
        while list_[i-x].offset == 0x0 and list_[i-x].length == 0x0:
            x = x + 1

        if v.offset != list_[i-x].offset + list_[i-x].length:
            print(" Offset!", end="")

    print()
