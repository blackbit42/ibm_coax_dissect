
import sys
from enum import Enum
from signal import signal, SIGPIPE, SIG_DFL

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
    '\\', ' ', 'S', 'T', 'U', 'V', 'W', 'X', 'Y', 'Z', ' ', ' ', ' ', ' ', ' ', ' ',
    '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', ' ', ' ', ' ', ' ', ' ', ' '
]


def e2a(ebcdic_bytes):
    ascii_ = ""
    for x in ebcdic_bytes:
        ascii_ += ebcdic2ascii[x]
    return ascii_


class TCAFields(Enum):
    """Terminal Control Area Fields"""

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
        **{field.value: field for field in TCAFields},
        **{x: f"TCAFields.Reserved{x:02x}" for x in range(0x12, 0x20)},
        **{x: f"TCAFields.Reserved{x:02x}" for x in range(0x27, 0x40)},
        **{x: f"TCAFields.Reserved{x:02x}" for x in range(0x43, 0x43)},
        **{x: f"TCAFields.Reserved{x:02x}" for x in range(0x4a, 0x50)},
        **{x: f"TCAFields.Reserved{x:02x}" for x in range(0x59, 0x5c)},
        **{x: f"TCAFields.Reserved{x:02x}" for x in range(0x62, 0x7e)},
        **{x: f"TCAFields.CUDATA{x:04x}" for x in range(0x81, 0x1001)},
}


class WCUSConditions(Enum):
    """Write Control Unit Status Conditions"""
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
        **{field.value: field for field in WCUSConditions}
}


class ExpeditedStatusFunctionRequests(Enum):
    """Expedited Status Function Requests"""
    DEVICE_BUSY_TIMER_INTERVAL = 0x02
    START_RTM_TIMER = 0x04
    STOP_RTM_TIMER = 0x06


ES_MAP = {
    **{es.value: es for es in ExpeditedStatusFunctionRequests}
}


class AsynchronousEvents(Enum):
    """Asyncronous Events"""
    AEER = 0x20    # Asynchronous Error
    AEEP = 0x22    # Inbound Event Pending
    AEDBA = 0x24   # Data Base Access Needed
    AEEB = 0x26    # End IR/Busy
    AEDV = 0x28    # Device-CU local Status
    AEFREE = 0x2A  # Release Printer
    AEPID = 0x2C   # Request Printer Assignment
    AECOPY = 0x2E  # Copy Request
    AECAN = 0x30   # Cancel Copy Request
    AEDBS = 0x32   # Request Data Base Store
    AESTAT = 0x34  # Asynchronous Response to Start Operation


AE_MAP = {
    **{ae.value: ae for ae in AsynchronousEvents}
}


class SyncronousEvents(Enum):
    FCSE = 0x02   # Function Complete with Syncronous Error
    FC = 0x04     # Function Complete
    FCIR = 0x06   # Function Complete with Input Required
    ERFR = 0x08   # Error in Function Request
    FRA = 0x0a    # Function Request Aborted
    FCDEF = 0x0c  # Function Complete / Status Deferred


SE_MAP = {
    **{se.value: se for se in SyncronousEvents}
}


class FunctionRequests(Enum):
    """Function Requests"""

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
    **{fr.value: fr for fr in FunctionRequests}
}


class CommandNames(Enum):
    """Command Names"""
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
    **{cn.value: cn for cn in CommandNames}
}


class TerminalState():
    """Terminal State"""

    def __init__(self):
        self.tca_buffer = [0] * 4096
        self.dirty_flags = [0] * 4096
        self.address_counter = 0
        self.secondary_control_register = 0
        self.prev_cmd = None
        self.last_read_dp = None
        self.da_length_read = False
        self.exp_event = False
        self.sync_event = False
        self.async_event = False

    def update_tca_buffer(self, data):
        if not isinstance(data, bytes):
            raise TypeError("data must be bytes")

        for x in data:
            self.tca_buffer[self.address_counter] = x
            if self.address_counter in TCA_MAP.keys():
                print(f"    TCA: {TCA_MAP[self.address_counter]} -> 0x{x:02x}")
            else:
                print(f"    TCA: 0x{self.address_counter:04x} -> 0x{x:02x}")
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

            if not self.exp_event and self.tca_buffer[TCAFields.EXFAK.value] == 1:
                self.exp_event = True
                self.dirty_flags[TCAFields.EXFRQ.value] = 1

            if not self.sync_event and self.tca_buffer[TCAFields.DPSSTAT.value] == 1:
                self.sync_event = True
                self.dirty_flags[TCAFields.DSSV.value] = 1

            if not self.async_event and self.tca_buffer[TCAFields.DPASTAT.value] == 1:
                self.async_event = True
                self.dirty_flags[TCAFields.DAEV.value] = 1

        # Check to see if the data portion of the data area is now clean
        if self.last_read_dp is not None and (sum(self.dirty_flags) == 0):
            actual_length = (self.tca_buffer[self.last_read_dp] >> 16) | self.tca_buffer[self.last_read_dp+1] - 4
            print("RDAT Completed:")
            print(f"    Actual length returned = 0x{actual_length:x}")
            pretty_print(self.tca_buffer[self.last_read_dp+4:self.last_read_dp+4+actual_length])
            self.last_read_dp = None

        if self.exp_event and (sum(self.dirty_flags) == 0):
            self.exp_event = False
            print("Expedited Status Available received from terminal:")
            print("    Event:", ES_MAP[self.tca_buffer[TCAFields.EXFRQ.value]].name)

        if self.sync_event and (sum(self.dirty_flags) == 0):
            self.sync_event = False
            print("Synchronous Status Available received from terminal:")
            print("    Event:", SE_MAP[self.tca_buffer[TCAFields.DSSV.value]].name)

        if self.async_event and (sum(self.dirty_flags) == 0):
            self.async_event = False
            print("Asynchronous Status Available received from terminal:")
            print("    Event:", AE_MAP[self.tca_buffer[TCAFields.DAEV.value]].name)

            if self.tca_buffer[TCAFields.DAEV.value] == AsynchronousEvents.AEDBA.value:
                print(f"    Data Base File: {self.tca_buffer[TCAFields.DAEP.value]:02x}")
                print(f'    Access: {"R/O" if self.tca_buffer[TCAFields.DAEP2.value] == 0x0 else "R/W"}')
                print(f"    Diskette Type: 0x{self.tca_buffer[TCAFields.DAEP3.value]:02x}")

            if self.tca_buffer[TCAFields.DAEV.value] == AsynchronousEvents.AEDV.value:
                if self.tca_buffer[TCAFields.DAEP.value] == 0x01:
                    print("    AEDV(Online)")
                    # TODO Should this be inverted?
                    print(f"    DAEP2 bitmap: {bin(self.tca_buffer[TCAFields.DAEP2.value])}")
                    # Check if controller supports "Extended DAEV"
                    cuslvl = (self.tca_buffer[TCAFields.CUSLVL.value] << 8) | \
                        self.tca_buffer[TCAFields.CUSLVL.value+1]
                    if cuslvl & 0x1:
                        print(f"    DAEP3 bitmap: {bin(self.tca_buffer[TCAFields.DAEP3.value])}")

                if self.tca_buffer[TCAFields.DAEP.value] == 0x02:
                    print("    AEDV(Offline)")

                if self.tca_buffer[TCAFields.DAEP.value] == 0x03:
                    print("    AEDV(Dump Complete)")

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
        if packet[0] & 0x002:
            # This is a new command

            # addr = (packet[0] & 0x700) >> 8
            cmd = (packet[0] & 0x0F8) >> 3

            self.prev_cmd = cmd

            if cmd == CommandNames.POLL.value:
                return

            if cmd not in CN_MAP.keys():
                print(f"###UNKNOWN### command 0x{cmd:02x}")
            else:
                print(f"{CN_MAP[cmd]}", end='')

            payload = None
            response_payload = None

            if len(packet) > 1:
                payload = extract_bytes(packet[1:])
                print(f" Length of data: 0x{len(payload):02x}")
                pretty_print(payload)
            else:
                print()
            # Read commands excluding the polls
            if cmd in [
                    CommandNames.READ_DATA.value,
                    CommandNames.READ_TERMINAL_ID.value,
                    CommandNames.READ_MULTIPLE.value,
                    ]:

                response_payload = extract_bytes(response)
                pretty_print(response_payload)

            if cmd == CommandNames.LOAD_ADDRESS_COUNTER_HIGH.value:
                self.set_address_counter_high(payload)

            if cmd == CommandNames.LOAD_ADDRESS_COUNTER_LOW.value:
                self.set_address_counter_low(payload)

            if cmd in [
                    CommandNames.READ_DATA.value,
                    CommandNames.READ_MULTIPLE.value,
                    ]:
                self.update_tca_buffer(response_payload)

            if cmd == CommandNames.WRITE_DATA.value and payload is not None:
                self.update_tca_buffer(payload)

            if cmd == CommandNames.START_OPERATION.value:
                self.print_function_request()

        else:
            print(f"Continuing {CN_MAP[self.prev_cmd]}")
            payload = extract_bytes(packet)
            pretty_print(payload)
            if self.prev_cmd == 0x0c:
                self.update_tca_buffer(payload)

    def print_function_request(self):
        cufrv = self.tca_buffer[0x44]
        if cufrv not in FR_MAP.keys():
            print(f"CU Function Request: Unknown 0x{cufrv:02x}")
            return

        print(f"CU Function Request: {FR_MAP[cufrv]}")

        cudp = (self.tca_buffer[TCAFields.CUDP.value] << 8) | self.tca_buffer[TCAFields.CUDP.value + 1]

        if cufrv == FunctionRequests.WDAT.value:
            print(f"    Logical Terminal = 0x{self.tca_buffer[TCAFields.CULTAD.value]:02x}")
            print(f"    Data Pointer = 0x{cudp:04x}")
            length = (self.tca_buffer[cudp] << 8) | self.tca_buffer[cudp+1]
            flags = (self.tca_buffer[cudp+2] << 8) | self.tca_buffer[cudp+3]
            print(f"    Length = 0x{length:04x}")
            print(f"    Flags = 0x{flags:04x}")

        if cufrv == FunctionRequests.WDBD.value:
            print(f"    File Identifier = 0x{self.tca_buffer[TCAFields.CUFRP1.value]:02x}")
            if self.tca_buffer[TCAFields.CUFRP2.value] == 0x00:
                print("    File retrieved from Disk")
            elif self.tca_buffer[TCAFields.CUFRP2.value] == 0x80:
                print("    File retrieved from CU Memory")
            else:
                print(f"    File retrieved unknown value 0x{self.tca_buffer[TCAFields.CUFRP2.value]}")
            print(f"    Address of Data Area: 0x{cudp:04x}")
            length = (self.tca_buffer[cudp] << 8) | self.tca_buffer[cudp+1]
            flags = (self.tca_buffer[cudp+2] << 8) | self.tca_buffer[cudp+3]
            print(f"    Length: 0x{length:04x}")
            print(f"    Flags: 0x{flags:04x}")

        if cufrv == FunctionRequests.RDAT.value:
            self.last_read_dp = cudp
            self.da_length_read = False
            self.dirty_flags[TCAFields.DPSSTAT.value] = 1
            self.dirty_flags[cudp:cudp+4] = [1, 1, 1, 1]

            cufrp12 = (self.tca_buffer[TCAFields.CUFRP1.value] << 8) | \
                self.tca_buffer[TCAFields.CUFRP2.value]
            print(f"    Number of Data segments = 0x{cufrp12:04x}")
            cufrp34 = (self.tca_buffer[TCAFields.CUFRP3.value] << 8) | \
                self.tca_buffer[TCAFields.CUFRP4.value]
            print(f"    Maximum Segment Length = 0x{cufrp34:04x}")
            print(f"    Logical Terminal Address = 0x{self.tca_buffer[TCAFields.CULTAD.value]:02x}")
            cudp = (self.tca_buffer[TCAFields.CUDP.value] << 8) | \
                self.tca_buffer[TCAFields.CUDP.value + 1]
            print(f"    Address of Data Area = 0x{cudp:04x}")

        if cufrv == FunctionRequests.WCUS.value:
            cufrp1 = self.tca_buffer[TCAFields.CUFRP1.value]
            if cufrp1 in WCUS_C_MAP.keys():
                print(f"    WCUS Condition = {WCUS_C_MAP[cufrp1]}")
            else:
                print(f"    WCUS Condition 0x{cufrp1:02x}")

            if cufrp1 == WCUSConditions.DEVICE_IDENTIFICATION.value:
                print("    Controller Identification Characters:",
                      e2a(self.tca_buffer[0x82:0x84]))
                print(f"    Device Type of Controller: {e2a(self.tca_buffer[0x84:0x88])}")

                high, low = self.tca_buffer[0x88] >> 4, self.tca_buffer[0x88] & 0x0f
                if low == 0x01:
                    print("    Hardware or Microcode")
                elif low == 0x0e:
                    print("    Customer Programmable Machine")
                else:
                    print(f"    Unknown value 0x{low:02x} in low nibble of 0x88")
                if high == 0x01:
                    print("    IBM Machine")
                elif high == 0x09:
                    print("    Non-IBM Machine")
                else:
                    print(f"    Unknown value 0x{high:02x} in high nibble of 0x88")

                print(f"    Model Number: {e2a(self.tca_buffer[0x89:0x8c])}")

                plant = (self.tca_buffer[0x8c] << 8) | self.tca_buffer[0x8d]
                print(f"    Plant of Manufacture: 0x{plant:04x}")
                print(f"    Sequence Number {e2a(self.tca_buffer[0x8e:0x95])}")
                print(f"    Release Level of Program: {e2a(self.tca_buffer[0x95:0x98])}")
                print(f"    Device Specific Information: {e2a(self.tca_buffer[0x98:0xa8])}")

            if cufrp1 == WCUSConditions.CU_READY.value:
                cufrp2 = self.tca_buffer[TCAFields.CUFRP2.value]
                if cufrp2 == 0x00:
                    print("    DSL Allowed")
                elif cufrp2 == 0x02:
                    print("    DSL Not Allowed")
                else:
                    print(f"    Unknown value 0x{cufrp2:02x} in CU_READY CUFRP2")


def main():

    # Prevent error message if output if piped into e.g. `less`
    signal(SIGPIPE, SIG_DFL)

    if len(sys.argv) != 2:
        print("Usage: python parse.py [ila_file]")

    with open(sys.argv[1], "r", encoding="ascii") as f:

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

                is_response = tdata & 0x8000

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
    line = ">"
    count = 0
    for (i, x) in enumerate(data):
        print(f"{x:02x} ", end='')
        line += ebcdic2ascii[x]
        if i % 16 == 15:
            print(" " + line + "<")
            line = ">"
        elif i % 8 == 7:
            print("  ", end='')
        count += 1

    if count % 16:
        print("   " * (16 - (count % 16)), end='')
        print(" " + line + "<")
    else:
        print("\n", end='')


if __name__ == "__main__":
    main()
