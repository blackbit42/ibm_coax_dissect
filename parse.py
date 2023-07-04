
import sys, os, struct

ebcdic2ascii = [
    ' ', ' ', ' ', ' ', ' ', ' ', ' ', ' ', ' ', ' ', ' ', ' ', ' ', ' ', ' ', ' ',
    ' ', ' ', ' ', ' ', ' ', ' ', ' ', ' ', ' ', ' ', ' ', ' ', ' ', ' ', ' ', ' ',
    ' ', ' ', ' ', ' ', ' ', ' ', ' ', ' ', ' ', ' ', ' ', ' ', ' ', ' ', ' ', ' ',
    ' ', ' ', ' ', ' ', ' ', ' ', ' ', ' ', ' ', ' ', ' ', ' ', ' ', ' ', ' ', ' ',
    ' ', ' ', ' ', ' ', ' ', ' ', ' ', ' ', ' ', ' ', ' ', '.', '<', '(', '+', '|',
    '&', ' ', ' ', ' ', ' ', ' ', ' ', ' ', ' ', ' ', '!', '$', '*', ')', ';', ' ',
    '-', '/', ' ', ' ', ' ', ' ', ' ', ' ', ' ', ' ', ' ', ',', '%', '_', '>', '?',
    ' ', ' ', ' ', ' ', ' ', ' ', ' ', ' ', ' ', '`', ':', '#', '@', "'", '=', '"',
    ' ', 'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', ' ', ' ', ' ', ' ', ' ', ' ',
    ' ', 'j', 'k', 'l', 'm', 'n', 'o', 'p', 'q', 'r', ' ', ' ', ' ', ' ', ' ', ' ',
    ' ', '~', 's', 't', 'u', 'v', 'w', 'x', 'y', 'z', ' ', ' ', ' ', ' ', ' ', ' ',
    '^', ' ', ' ', ' ', ' ', ' ', ' ', ' ', ' ', ' ', '[', ']', ' ', ' ', ' ', ' ',
    '{', 'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I', ' ', ' ', ' ', ' ', ' ', ' ',
    '}', 'J', 'K', 'L', 'M', 'N', 'O', 'P', 'Q', 'R', ' ', ' ', ' ', ' ', ' ', ' ',
    '\\',' ', 'S', 'T', 'U', 'V', 'W', 'X', 'Y', 'Z', ' ', ' ', ' ', ' ', ' ', ' ',
    '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', ' ', ' ', ' ', ' ', ' ', ' '
]

def main():

    if len(sys.argv) != 2:
        print("Usage: python parse.py [ila_file]")

    with open(sys.argv[1], "r") as f:

        counter = 0
        is_response = False
        packet = []
        response = []
        prev_cmd = None

        for x, line in enumerate(f.readlines()):
            if x >= 2:
                parts = line.split(',')
                tdata = parts[4]
                tlast = parts[8]

                tdata = int(tdata, 16)
                tlast = int(tlast, 16)

                is_response = True if (tdata & 0x8000) else False

                if counter == 0:
                    if not is_response:
                        packet = []
                    else:
                        response = []

                if not is_response:
                    packet.append(tdata)
                else:
                    response.append(tdata)

                if tlast:

                    if is_response:
                        prev_cmd = interp_packet(packet, response, prev_cmd)

                    counter = 0
                else:
                    counter += 1


def interp_packet(packet, response, prev_cmd):
    command_names = {
        0x01: "POLL",
        0x03: "READ DATA",
        0x09: "READ TERMINAL ID",
        0x11: "POLL/ACK",
        0x0b: "READ MULTIPLE",
        0x02: "RESET",
        0x0c: "WRITE DATA",
        0x04: "LOAD ADDRESS COUNTER HIGH",
        0x14: "LOAD ADDRESS COUNTER LOW",
        0x08: "START OPERATION",
        0x1c: "DIAGNOSTIC RESET"
    }

    if (packet[0] & 0x002):
        # This is a new command

        addr = (packet[0] & 0x700) >> 8
        cmd = (packet[0] & 0x0F8) >> 3

        if cmd == 0x01:
            return cmd

        if cmd not in command_names.keys():
            print("%s (0x%.2x)" % ("###UNKNOWN###", cmd))
        else:
            print("%s" % (command_names[cmd]))

        if len(packet) > 1:
            payload = extract_bytes(packet[1:])
            pretty_print(payload)
        if cmd in [0x03, 0x09, 0x0b]:
            pretty_print(extract_bytes(response))

        return cmd

    else:

        print("Continuing '%s'" % (command_names[prev_cmd]))
        pretty_print(extract_bytes(packet))

        return prev_cmd

def extract_bytes(words):
    r = []
    for x in words:
        r.append((x & 0x7F8) >> 3)
    return bytes(r)

def pretty_print(data):
    line = ""
    count = 0
    for (i,x) in enumerate(data):
        print("%.2x " % x, end='')
        line += ebcdic2ascii[x]
        if (i % 16 == 15):
            print(" " + line)
            line = ""
        elif (i % 8 == 7):
            print("  ", end='')
        count += 1

    if (count % 16):
        print("   " * (16 - (count % 16)), end='')
        print(" " + line)
    else:
        print("\n", end='')


if __name__ == "__main__":
    main()