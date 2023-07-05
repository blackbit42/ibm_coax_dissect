
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

class TerminalState():

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
        0x1a: "LOAD SECONDARY CONTROL REGISTER",
        0x1c: "DIAGNOSTIC RESET"
    }

    function_requests = {
        0x01: "CNOP",
        0x02: "WCUS",
        0x03: "WDAT", 
        0x04: "WDBD", 
        0x05: "RDCOPY", 
        0x06: "WLCC", 
        0x07: "LOCK", 
        0x08: "RDAT", 
        0x09: "WCTL", 
        0x0a: "PDAT", 
        0x0b: "CTCCS", 
        0x0c: "RDBD", 
        0x0d: "RPID" 
    }

    def __init__(self):
        self.tca_buffer = [0] * 4096
        self.address_counter = 0
        self.secondary_control_register = 0
        self.prev_cmd = None

    def update_tca_buffer(self, data):
        if not isinstance(data, bytes):
            raise TypeError("data must be bytes")

        for x in data:
            self.tca_buffer[self.address_counter] = x
            self.address_counter += 1

    def set_address_counter_high(self, ah):
        if not isinstance(ah, bytes):
            raise TypeError("ah must be bytes")
        if len(ah) != 1:
                print("Load address counter high has unexpected number of payload bytes")
        else:
            self.address_counter = (self.address_counter & 0xff) | (ah[0] << 8)

    def set_address_counter_low(self, al):
        if not isinstance(al, bytes):
            raise TypeError("al must be bytes")
        if len(al) != 1:
                print("Load address counter low has unexpected number of payload bytes")
        else:
            self.address_counter = (self.address_counter & 0xff00) | (al[0])

    def interp_packet(self, packet, response):
        if (packet[0] & 0x002):
            # This is a new command

            addr = (packet[0] & 0x700) >> 8
            cmd = (packet[0] & 0x0F8) >> 3
            
            self.prev_cmd = cmd

            if cmd == 0x01:
                return

            if cmd not in TerminalState.command_names.keys():
                print("%s (0x%.2x)" % ("###UNKNOWN###", cmd))
            else:
                print("%s" % (TerminalState.command_names[cmd]))

            payload = None
            response_payload = None

            if len(packet) > 1:
                payload = extract_bytes(packet[1:])
                pretty_print(payload)
            if cmd in [0x03, 0x09, 0x0b]:       # Read commands excluding the polls
                response_payload = extract_bytes(response)
                pretty_print(response_payload)

            if cmd == 0x04:
                self.set_address_counter_high(payload)

            if cmd == 0x14:
                self.set_address_counter_low(payload)

            if cmd in [0x03, 0x0b]:
                self.update_tca_buffer(response_payload)

            if cmd == 0x0c and payload is not None:
                self.update_tca_buffer(payload)

            if cmd == 0x08:
                self.print_function_request()
            

        else:
            print("Continuing '%s'" % (TerminalState.command_names[self.prev_cmd]))
            payload = extract_bytes(packet)
            pretty_print(payload)
            if self.prev_cmd == 0x0c:
                self.update_tca_buffer(payload)

    def print_function_request(self):
        cufrv = self.tca_buffer[0x44]
        if cufrv not in TerminalState.function_requests.keys():
            print("CU Function Request: Unknown (%.2x)" % (cufrv))
            return

        print("CU Function Request: %s" % (TerminalState.function_requests[cufrv]))

        if cufrv == 0x03:
            print("    Logical Terminal = %.2x" % self.tca_buffer[0x42])
            cudp = (self.tca_buffer[0x40] << 8) | self.tca_buffer[0x41]
            print("    Data Pointer = %.4x" % cudp)
            length = (self.tca_buffer[cudp] << 8) | self.tca_buffer[cudp+1]
            print("    Length = %.4x" % length)

def main():

    if len(sys.argv) != 2:
        print("Usage: python parse.py [ila_file]")

    with open(sys.argv[1], "r") as f:

        counter = 0
        is_response = False
        packet = []
        response = []

        state = TerminalState()

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
                        state.interp_packet(packet, response)

                    counter = 0
                else:
                    counter += 1
        pretty_print(state.tca_buffer)

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