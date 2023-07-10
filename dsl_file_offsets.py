"""
12.1 Down Stream Loading
All requests employed in down stream loading use a one byte file identifier.
"""

import sys

START = 0x0a
STEP = 0x0a

if len(sys.argv) != 2:
    print(f"Usage: {sys.argv[0]} <DSL file>")
    sys.exit(1)

with open(sys.argv[1], mode='rb') as dsl:
    content = dsl.read()
    for i in range(0x40):
        offset = content[START+STEP*i:START+STEP*i+4]
        length = content[START+STEP*i+4:START+STEP*i+8]
        # print("offset:", offset, type(offset))
        end = int.from_bytes(offset) + int.from_bytes(length)
        # print(end, type(end))
        print(f"File 0x{i+1:02x}: "
              f"Offset: 0x{offset.hex()} "
              f"Length: 0x{length.hex()} "
              f"End: 0x{end:08x}")
