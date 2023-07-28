from colorama import Fore
import scapy.all as scapy
from subprocess import call
from modules.interface_settings import check_default_ip_route

def ip_check(ip):
        checking_IP = ip.split('.')
        if checking_IP[-1].endswith('/24') and checking_IP[-1][:-3].isnumeric():
            if len(checking_IP) != 4 or not all(ip.isnumeric() for ip in checking_IP[:-1]) or not all(0 <= int(ip) < 255 for ip in checking_IP[:-1]):
                print(Fore.LIGHTYELLOW_EX + '\n[INFO] Invalid IP address' + Fore.RESET)
                return False
        elif len(checking_IP) != 4 or not all(ip.isnumeric() for ip in checking_IP) or not all(0 <= int(ip) < 255 for ip in checking_IP):
            print(Fore.LIGHTYELLOW_EX + '\n[INFO] Invalid IP address' + Fore.RESET)
            return False

        return True
def arp_scan(ip,retry=3):
    arp_request = scapy.ARP(pdst=ip)
    broadcast = scapy.Ether(dst='ff:ff:ff:ff:ff:ff')
    arp_request_broadcast = broadcast/arp_request 
    ip = scapy.srp(arp_request_broadcast, timeout=0.035, verbose=False, retry=retry)[0]
    if ip:
        info_ip = {'ip': ip[0][1].psrc, 'mac': ip[0][1].hwsrc}
        return info_ip
    return False

    
def scan(ip_net,retry=4,comments=True):
    if not ip_check(ip_net): return 
    scan_list = [] 
    ip_route = arp_scan(check_default_ip_route())
    if not ip_route: ip_route = {'ip': 'UNKNOWN', 'mac': 'UNKNOWN'}
    try:
        call('clear')
        my_ip_mac = scapy.ARP()

        if comments: 
            print(Fore.LIGHTCYAN_EX + f'\nYour IP: {my_ip_mac.psrc} and MAC address: {my_ip_mac.hwsrc}' + Fore.RESET)
            print(Fore.LIGHTCYAN_EX + f'\nRoute IP: {ip_route["ip"]} and MAC address: {ip_route["mac"]}\n' + Fore.RESET)

        if ip_net.endswith('/24'):
            flag, _ = True, True
            ip_net = ip_net.split('.')
       
            for i in range(255):
                ip = '.'.join(ip_net[:3]) + '.' + str(i)
                if _ and ip == ip_route['ip']:
                    _ = False
                    continue
                info_ip = arp_scan(ip, retry)
    
                if comments and flag and info_ip:
                    flag = False
                    print(Fore.LIGHTCYAN_EX + ' ' + '-' * 39 + Fore.RESET)
                    print(Fore.LIGHTCYAN_EX + ' | {:^15} | {:^17} |'.format('IP', 'MAC') + Fore.RESET)
                    print(Fore.LIGHTCYAN_EX + ' ' + '-' * 39 + Fore.RESET)
                
                if info_ip:
                    scan_list.append(info_ip)
                    ip_address = info_ip['ip']
                    mac_address = info_ip['mac']
                    if comments:
                        print(Fore.LIGHTCYAN_EX + ' | {:^15} | {:^17} |'.format(ip_address, mac_address) + Fore.RESET)
                        print(Fore.LIGHTCYAN_EX + ' ' + '-' * 39 + Fore.RESET)
            if scan_list:
                return scan_list
            else: print(Fore.LIGHTYELLOW_EX + '\n[INFO] IP address not found\n' + Fore.RESET) 
    
            return scan_list
        else:
            if ip_net == ip_route['ip']:
                return
            info_ip = arp_scan(ip_net, retry)
    
            if info_ip:
                print(Fore.LIGHTCYAN_EX + f'\n[INFO] IP {info_ip["ip"]} has the following MAC address: {info_ip["mac"]}\n' + Fore.RESET)
                return [info_ip]
            else:
                print(Fore.LIGHTYELLOW_EX + '\n[INFO] IP address not found\n' + Fore.RESET) 
    except KeyboardInterrupt:
        return scan_list


            
       

if __name__ == '__main__':
   scan(input('[!] Введите ip адрес для сканирования: '))
