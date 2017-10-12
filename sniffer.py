import sys
import logging
# logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
from scapy.all import *

class UrgExfilSniffer:
    def version():
        return '0.0.1'

    def __init__(self, opts):
        filemode = 'wa' if opts.append else 'wb'
        self.outfile = open(opts.outfile, "wb")
        self.port = opts.port
        self.verbose = opts.verbose

    def process(packet):
        print('AAA')

    def listen(self):
        fil = "tcp port 31337"# + str(self.port)
        sniff(filter=fil, prn=UrgExfilSniffer.process)

    def bytes_for(self, integer):
        tup = ((integer >> 8), integer & 0x00FF)
        return byte



if __name__ == "__main__":
    import argparse;
    parser = argparse.ArgumentParser(
               description="Exfiltrate data using TCP urg pointer",
               add_help=True
             )
    parser.add_argument('-p', '--port', required=True, action='store', help='Destination port', type=int)
    parser.add_argument('-f', '--outfile', action='store', help='Location to save received data', default="woofer")
    parser.add_argument('-v', '--verbose', action='store_true', dest='verbose', help='Enable verbose output')
    parser.add_argument('--truncate', action='store_false', dest='append', help='Truncate outfile', default=True)
    parser.add_argument('--version', action='version', version=('%(prog)s ' + UrgExfilSniffer.version()), help="Show version information")
    opts = parser.parse_args()
    exfil = UrgExfilSniffer(opts)
    exfil.listen()
    sys.exit(0)

