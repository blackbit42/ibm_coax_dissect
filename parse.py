
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

def e2a(ebcdic_bytes):
    ascii = ""
    for x in ebcdic_bytes:
        ascii += ebcdic2ascii[x]
    return ascii

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


class WCUS_Conditions(Enum):
    # Input Inhibit
    MACHINE_CHECK = 0x01
    COMMUN_CHECK_REMINDER = 0x02
    PROGRAM_CHECK = 0x03
    # Readiness Group
    CU_READY = 0x10
    # Identity
    DEVICE_IDENTIFICATION = 0x20
    # Reminders
    COMMUNICATIONS_CHECK = 0x30
    NO_REMINDER = 0x31
    DISK_NOT_READY_CO = 0x60
    DISK_NOT_READY_CC = 0x61
    # LU Status
    LU_ACTIVE = 0x40
    LU_NOT_ACTIVE = 0x41
    RTM_PARAMETERS = 0x42
    # Local Copy
    REQUEST_QUEUED = 0x51
    LONG_TERM_BUSY = 0x52
    FIXME = 0x53                      # XXX FIXME
    INVALID_PRINTER_NUMBER = 0x54
    ASSIGNMENT_NOT_ALLOWED = 0x55
    PRINTER_ASSIGNED = 0x56
    PRINTER_AVAILABLE = 0x57
    PRINTING_STARTED = 0x58
    REQUEST_DEQUEUED = 0x59
    LOCAL_COPY_UNCONFIGURED = 0x5a
    PRINT_COMPLETE = 0x5b
    PRINTER_OPERATIONAL = 0x5c
    # Disk Completion
    DISK_COMPLETION1 = 0x70
    DISK_COMPLETION2 = 0x71


WCUS_C_MAP = {
        **{field.value: field for field in WCUS_Conditions}
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


class Command_Names(Enum):
    POLL = 0x01
    RESET = 0x02
    READ_DATA = 0x03
    LOAD_ADDRESS_COUNTER_HIGH = 0x04
    START_OPERATION = 0x08
    READ_TERMINAL_ID = 0x09
    READ_MULTIPLE = 0x0b
    WRITE_DATA = 0x0c
    POLL_ACK = 0x11
    LOAD_ADDRESS_COUNTER_LOW = 0x14
    LOAD_SECONDARY_CONTROL_REGISTER = 0x1a
    DIAGNOSTIC_RESET = 0x1c


CN_MAP = {
    **{cn.value: cn for cn in Command_Names}
}


class TerminalState():

    def __init__(self):
        self.tca_buffer = [0] * 4096
        self.dirty_flags = [0] * 4096
        self.address_counter = 0
        self.secondary_control_register = 0
        self.prev_cmd = None
        self.last_read_dp = None
        self.da_length_read = False

    def update_tca_buffer(self, data):
        if not isinstance(data, bytes):
            raise TypeError("data must be bytes")

        for x in data:
            self.tca_buffer[self.address_counter] = x
            self.dirty_flags[self.address_counter] = 0
            self.address_counter += 1

            # Check to see if we are looking for the Data area Length and Flags and if it is not clean
            if not self.da_length_read and self.last_read_dp is not None and (sum(self.dirty_flags[self.last_read_dp:self.last_read_dp+4]) == 0):
                self.da_length_read = True
                # The length in this register includes the 4 bytes of header for a data area
                actual_length = (self.tca_buffer[self.last_read_dp] >> 16) | self.tca_buffer[self.last_read_dp+1]
                # Now that we know the length, mark the rest of the data area as dirty
                for x in range(4, actual_length):
                    self.dirty_flags[self.last_read_dp+x] = 1
                    
        # Check to see if the data portion of the data area is now clean
        if self.last_read_dp is not None and (sum(self.dirty_flags) == 0):
            actual_length = (self.tca_buffer[self.last_read_dp] >> 16) | self.tca_buffer[self.last_read_dp+1] - 4
            print("RDAT Completed:")
            print("    Actual length returned = %d" % (actual_length))
            pretty_print(self.tca_buffer[self.last_read_dp+4:self.last_read_dp+4+actual_length])
            self.last_read_dp = None

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

            if cmd == Command_Names.POLL.value:
                return

            if cmd not in CN_MAP.keys():
                print("%s (0x%.2x)" % ("###UNKNOWN###", cmd))
            else:
                print("%s" % (CN_MAP[cmd]))

            payload = None
            response_payload = None

            if len(packet) > 1:
                payload = extract_bytes(packet[1:])
                pretty_print(payload)
            # Read commands excluding the polls
            if cmd in [
                    Command_Names.READ_DATA.value,
                    Command_Names.READ_TERMINAL_ID.value,
                    Command_Names.READ_MULTIPLE.value,
                    ]:

                response_payload = extract_bytes(response)
                pretty_print(response_payload)

            if cmd == Command_Names.LOAD_ADDRESS_COUNTER_HIGH.value:
                self.set_address_counter_high(payload)

            if cmd == Command_Names.LOAD_ADDRESS_COUNTER_LOW.value:
                self.set_address_counter_low(payload)

            if cmd in [
                    Command_Names.READ_DATA.value,
                    Command_Names.READ_MULTIPLE.value,
                    ]:
                self.update_tca_buffer(response_payload)

            if cmd == Command_Names.WRITE_DATA.value and payload is not None:
                self.update_tca_buffer(payload)

            if cmd == Command_Names.START_OPERATION.value:
                self.print_function_request()
            

        else:
            print("Continuing '%s'" % (CN_MAP[self.prev_cmd]))
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

        cudp = (self.tca_buffer[TCA_Fields.CUDP.value] << 8) | self.tca_buffer[TCA_Fields.CUDP.value + 1]

        if cufrv == Function_Requests.WDAT.value:
            print("    Logical Terminal = %.2x" % self.tca_buffer[TCA_Fields.CULTAD.value])
            print("    Data Pointer = %.4x" % cudp)
            length = (self.tca_buffer[cudp] << 8) | self.tca_buffer[cudp+1]
            flags = (self.tca_buffer[cudp+2] << 8) | self.tca_buffer[cudp+3]
            print("    Length = %.4x" % length)
            print("    Flags = %.4x" % flags)

        if cufrv == Function_Requests.WDBD.value:
            print("    File Identifier = %.2x" % self.tca_buffer[TCA_Fields.CUFRP1.value])
            if self.tca_buffer[TCA_Fields.CUFRP2.value] == 0x00:
                print("    File retrieved from Disk")
            elif self.tca_buffer[TCA_Fields.CUFRP2.value] == 0x80:
                print("    File retrieved from CU Memory")
            else:
                print("    File retrieved unknown value %.1x" % self.tca_buffer[TCA_Fields.CUFRP2.value])
            print("    Address of Data Area: %.4x" % (cudp))
            length = (self.tca_buffer[cudp] << 8) | self.tca_buffer[cudp+1]
            flags = (self.tca_buffer[cudp+2] << 8) | self.tca_buffer[cudp+3]
            print("    Length: %.4x" % length)
            print("    Flags: %.4x" % flags)

        if cufrv == Function_Requests.RDAT.value:
            self.last_read_dp = cudp
            self.da_length_read = False
            self.dirty_flags[TCA_Fields.DPSSTAT.value] = 1
            self.dirty_flags[cudp:cudp+4] = [1, 1, 1, 1]

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
            cufrp1 = self.tca_buffer[TCA_Fields.CUFRP1.value]
            if cufrp1 in WCUS_C_MAP.keys():
                print("    WCUS Condition = %s" % WCUS_C_MAP[cufrp1])
            else:
                print("    WCUS Condition %.2x unknown" % cufrp1)

            if cufrp1 == WCUS_Conditions.DEVICE_IDENTIFICATION.value:
                print("    Controller Identification Characters:", 
                    e2a(self.tca_buffer[0x82:0x84]))
                print("    Device Type of Controller:", e2a(self.tca_buffer[0x84:0x88]))
                
                high, low = self.tca_buffer[0x88] >> 4, self.tca_buffer[0x88] & 0x0f
                if low == 0x01:
                    print("    Hardware or Microcode")
                elif low == 0x0e:
                    print("    Customer Programmable Machine")
                else:
                    print("    Unknown value %.2x in low nibble of 0x88" % low)
                if high == 0x01:
                    print("    IBM Machine")
                elif high == 0x09:
                    print("    Non-IBM Machine")
                else:
                    print("    Unknown value %.2x in high nibble of 0x88" %
                          high)

                print("    Model Number:", e2a(self.tca_buffer[0x89:0x8c]))
                
                plant = (self.tca_buffer[0x8c] << 8) | self.tca_buffer[0x8d]
                print("    Plant of Manufacture: %.4x" % plant)
                print("    Sequence Number:", e2a(self.tca_buffer[0x8e:0x95]))
                print("    Release Level of Program:", e2a(self.tca_buffer[0x95:0x98]))
                print("    Device Specific Information:", e2a(self.tca_buffer[0x98:0xa8]))

            if cufrp1 == WCUS_Conditions.CU_READY.value:
                cufrp2 = self.tca_buffer[TCA_Fields.CUFRP2.value]
                if cufrp2 == 0x00:
                    print("    DSL Allowed")
                elif cufrp2 == 0x02:
                    print("    DSL Not Allowed")
                else:
                    print("    Unknown value %.2x in CU_READY CUFRP2" % cufrp2)


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
    print("Length of data: 0x%x" % len(data))
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
