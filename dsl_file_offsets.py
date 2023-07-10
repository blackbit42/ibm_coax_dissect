"""
12.1 Down Stream Loading
All requests employed in down stream loading use a one byte file identifier.
"""

import os
import sys

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

with open(sys.argv[1], mode='rb') as dsl:
    content = dsl.read()
    for i in range(0x40):
        offset = int.from_bytes(content[START+STEP*i:START+STEP*i+4])
        length = int.from_bytes(content[START+STEP*i+4:START+STEP*i+8])
        end = offset + length
        print(f"File 0x{i+1:02x}: "
              f"Offset: 0x{offset:08x} "
              f"Length: 0x{length:08x} "
              f"End: 0x{end:08x}")

        if DUMP_FILES:
            if offset == 0x0:
                continue

            with open(f"tmp/{i+1:02x}", mode='wb') as file:
                subfile = content[offset:end]
                file.write(subfile)
