
import sys
from enum import Enum

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


class TCA_Fields(Enum):

    # Device owned area.
    DPASTAT = 0x00  # Asynchronous status present flag
    DPSSTAT = 0x01  # Synchronous status present flag
    DSSV = 0x02     # Synchronous status value
    DSSP = 0x03     # Synchronous status paramenter 1
    DSSP2 = 0x04    # Synchronous status paramenter 2
    DSSP3 = 0x05    # Synchronous status paramenter 3
    DALTAD = 0x06   # Logical Terminal Address
    DAEV = 0x07     # Asyncronous status event value
    DAEP = 0x08     # Asyncronous status event parameter 1
    DAEP2 = 0x09    # Asyncronous status event parameter 2
    DAEP3 = 0x0a    # Asyncronous status event parameter 3
    DAEP4 = 0x0b    # Asyncronous status event parameter 4
    DTID1 = 0x0c    # Terminal ID
    DTID2 = 0x0d    # Product ID Qualifier
    DTID3 = 0x0e    # Reserved
    DTID4 = 0x0f    # Reserved
    DBUF = 0x10     # Device buffer size in bytes (Valid after POR)
    # Bytes 0x12..0x1f Reserved
    EXFLT = 0x20    # LT Address
    EXFRQ = 0x21    # Expedited Status value
    EXFP1 = 0x22    # Expedited Status paramenter 1
    EXFP2 = 0x23    # Expedited Status paramenter 2
    EXFP3 = 0x24    # Expedited Status paramenter 3
    EXFP4 = 0x25    # Expedited Status paramenter 4
    EXFAK = 0x26    # Post/Acknowledgement flag byte
    # Bytes 0x27..0x3f Reserved

    # Controller owned area.
    CUDP = 0x40     # Data address within the device buffer
    CULTAD = 0x42   # Logical Terminal Address
    CUFRV = 0x44    # Syncronous function request value
    CUSYN = 0x45    # Request synchronization switch (toggle)
    CUFRP1 = 0x46   # Synchronous Function Request Paramenter 1
    CUFRP2 = 0x47   # Synchronous Function Request Paramenter 2
    CUFRP3 = 0x48   # Synchronous Function Request Paramenter 3
    CUFRP4 = 0x49   # Synchronous Function Request Paramenter 4
    # Bytes 0x4a..0x4f Reserved
    CUDPORT = 0x50  # Device Port Number (0 - 31)
    CUAT = 0x51     # Control unit host attachment protocol
    CUDSER = 0x52   # Error code value for last-ditch-command-queue
    CULTA1 = 0x54   # LT Address 1
    CULTA2 = 0x55   # LT Address 2
    CULTA3 = 0x56   # LT Address 3
    CULTA4 = 0x57   # LT Address 4
    CULTA5 = 0x58   # LT Address 5
    # Bytes 0x59..0x5b Reserved
    EXFD1 = 0x5c    # Expedited Status Response paramenter 1 (if needed)
    EXFD2 = 0x5d    # Expedited Status Response paramenter 2 (if needed)
    EXFD3 = 0x5e    # Expedited Status Response paramenter 3 (if needed)
    EXFD4 = 0x5f    # Expedited Status Response paramenter 4 (if needed)
    EXTIME = 0x60   # Host transaction timing
    CUDSL = 0x61    # DSL Type
    # Bytes 0x62..0x7d Reserved
    CUSLVL = 0x7e   # Controller TCA Support Level
    CUDATA = 0x80   # Data Area


TCA_MAP = {
        **{field.value: field for field in TCA_Fields}
}


class Function_Requests(Enum):
    CNOP = 0x01    # Control No-Operation
    WCUS = 0x02    # Write Control Unit Status
    WDAT = 0x03    # Write Data from Host
    WDBD = 0x04    # Write Data-Base Data
    RDCOPY = 0x05  # Read block of SNA Character String (SCS)
    WLCC = 0x06    # Write Local Channel Command
    LOCK = 0x07    # Non-SNA host selection, device ready request
    RDAT = 0x08    # Generate inbound (Read) Data for host
    WCTL = 0x09    # Write printer Characteristics for Local Copy
    PDAT = 0x0a    # Prepare read Data prior to host notification
    CTCCS = 0x0b   # Terminate Chained Command Sequence
    RDBD = 0x0c    # Request Data-Base Data
    RPID = 0x0d    # Read Printer Identification
    # Bytes 0x0e..0xff Reserved

FR_MAP = {
    **{fr.value: fr for fr in Function_Requests}
}


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
        if cufrv not in FR_MAP.keys():
            print("CU Function Request: Unknown (%.2x)" % (cufrv))
            return

        print("CU Function Request: %s" % (FR_MAP[cufrv]))

        if cufrv == Function_Requests.WDAT.value:
            print("    Logical Terminal = %.2x" % self.tca_buffer[TCA_Fields.CULTAD.value])
            cudp = (self.tca_buffer[TCA_Fields.CUDP.value] << 8) | self.tca_buffer[TCA_Fields.CUDP.value + 1]
            print("    Data Pointer = %.4x" % cudp)
            length = (self.tca_buffer[cudp] << 8) | self.tca_buffer[cudp+1]
            print("    Length = %.4x" % length)

        if cufrv == Function_Requests.WDBD.value:
            print("    File Identifier = %.2x" % self.tca_buffer[TCA_Fields.CUFRP1.value])
            if self.tca_buffer[TCA_Fields.CUFRP2.value] == 0x00:
                print("    File retrieved from Disk")
            elif self.tca_buffer[TCA_Fields.CUFRP2.value] == 0x80:
                print("    File retrieved from CU Memory")
            else:
                print("    File retrieved unknown value %.1x" % self.tca_buffer[TCA_Fields.CUFRP2.value])
            print("    Address of Data Area: %.4x" % self.tca_buffer[TCA_Fields.CUDP.value])

        if cufrv == Function_Requests.RDAT.value:
            cufrp12 = (self.tca_buffer[TCA_Fields.CUFRP1.value] << 8) | \
                  self.tca_buffer[TCA_Fields.CUFRP2.value]
            print("    Number of Data segments = %.4x" % cufrp12)
            cufrp34 = (self.tca_buffer[TCA_Fields.CUFRP3.value] << 8) | \
                  self.tca_buffer[TCA_Fields.CUFRP4.value]
            print("    Maximum Segment Length = %.4x" % cufrp34)
            print("    Logical Terminal Address = %.2x" %
                  self.tca_buffer[TCA_Fields.CULTAD.value])
            cudp = (self.tca_buffer[TCA_Fields.CUDP.value] << 8) | \
                    self.tca_buffer[TCA_Fields.CUDP.value + 1]
            print("    Address of Data Area = %.4x" % cudp)


        if cufrv == Function_Requests.WCUS.value:
            pass

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
