import ipaddress
import requests
import scapy.all as scapy
from colorama import Fore
from modules.interface_settings import check_default_ip_route
from os.path import exists
from subprocess import call

def ip_check(ip):
        checking_IP = ip.split('.')
        if checking_IP[-1].endswith('/24') and checking_IP[-1][:-3].isnumeric():
            if len(checking_IP) != 4 or not all(ip.isnumeric() for ip in checking_IP[:-1]) or not all(0 <= int(ip) < 256 for ip in checking_IP[:-1]):
                print(Fore.LIGHTYELLOW_EX + '\n[INFO] Invalid IP address' + Fore.RESET)
                return False
        elif len(checking_IP) != 4 or not all(ip.isnumeric() for ip in checking_IP) or not all(0 <= int(ip) < 256 for ip in checking_IP):
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


    def comment(info_ip, flag):
        if flag:
            print(Fore.LIGHTCYAN_EX + ' ' + '-' * 57 + Fore.RESET)
            print(Fore.LIGHTCYAN_EX + ' | {:^15} | {:^17} | {:^15} |'.format('IP', 'MAC', 'INFO') + Fore.RESET)
            print(Fore.LIGHTCYAN_EX + ' ' + '-' * 57 + Fore.RESET)
    
        ip_address = info_ip['ip']
        mac_address = info_ip['mac']
     
    
        for _ in range(2):
            request = requests.get('https://api.macvendors.com/' + mac_address)
            if request.status_code == 200:
                device_model = request.text.split()[0]
                break
            else: device_model = 'No info'
       
        print(Fore.LIGHTCYAN_EX + ' | {:^15} | {:^17} | {:^15} |'.format(ip_address, mac_address, device_model) + Fore.RESET)
        print(Fore.LIGHTCYAN_EX + ' ' + '-' * 57 + Fore.RESET)
    


    scan_list = [] 
    ip_route = arp_scan(check_default_ip_route())
    if not ip_route: ip_route = {'ip': 'UNKNOWN', 'mac': 'UNKNOWN'}
    else: 
        if ip_net == '&': ip_net =  '.'.join(ip_route['ip'].split('.')[:-1])+'.0/24'
    try:
        my_ip_mac = scapy.ARP()

        if ip_net.endswith('/24'):
            if not ip_check(ip_net): return
            call('clear')
            if comments: 
                print(Fore.LIGHTCYAN_EX + f'\nYour IP: {my_ip_mac.psrc} and MAC address: {my_ip_mac.hwsrc}' + Fore.RESET)
                print(Fore.LIGHTCYAN_EX + f'\nRoute IP: {ip_route["ip"]} and MAC address: {ip_route["mac"]}\n' + Fore.RESET)
            flag, _ = True, True
            ip_net = ip_net.split('.')
       
            for i in range(255):
                ip = '.'.join(ip_net[:3]) + '.' + str(i)
                if _ and ip == ip_route['ip']:
                    _ = False
                    continue
                info_ip = arp_scan(ip, retry)
    
                if info_ip:
                    if comments:
                        comment(info_ip,flag)
                        flag = False
                    scan_list.append(info_ip)

            if scan_list:
                return scan_list
            else: print(Fore.LIGHTYELLOW_EX + '\n[INFO] IP address not found\n' + Fore.RESET) 
    
            return scan_list

        elif exists(ip_net):
            with open(ip_net, 'r') as file:
                call('clear')
                if comments: 
                    print(Fore.LIGHTCYAN_EX + f'\nYour IP: {my_ip_mac.psrc} and MAC address: {my_ip_mac.hwsrc}' + Fore.RESET)
                    print(Fore.LIGHTCYAN_EX + f'\nRoute IP: {ip_route["ip"]} and MAC address: {ip_route["mac"]}\n' + Fore.RESET)
                flag, _ = True, True
                for ip in file:
                    ip.strip()
                    if _ and ip == ip_route['ip']:
                        _ = False
                        continue
                    info_ip = arp_scan(ip, retry)
        
                    if info_ip:
                        if comments:
                            comment(info_ip,flag)
                            flag = False
                        scan_list.append(info_ip)


                if scan_list:
                    return scan_list
                else: print(Fore.LIGHTYELLOW_EX + '\n[INFO] IP address not found\n' + Fore.RESET) 
        
                return scan_list

        elif len(ip_net.split('-')) == 2:
            call('clear')
            if comments: 
                print(Fore.LIGHTCYAN_EX + f'\nYour IP: {my_ip_mac.psrc} and MAC address: {my_ip_mac.hwsrc}' + Fore.RESET)
                print(Fore.LIGHTCYAN_EX + f'\nRoute IP: {ip_route["ip"]} and MAC address: {ip_route["mac"]}\n' + Fore.RESET)
            flag, _ = True, True
            
            ip = ip_net.split('-')
            if not ip_check(ip[0]) or not ip_check(ip[1]): return
            start = ipaddress.IPv4Address(ip[0])
            end = ipaddress.IPv4Address(ip[1])
            
            ip = start
            
            while ip <= end:
                if _ and ip == ip_route['ip']:
                    _ = False
                    continue
                info_ip = arp_scan(str(ip), retry)
    
                if info_ip:
                    if comments:
                        comment(info_ip,flag)
                        flag = False
                    scan_list.append(info_ip)

                ip = ipaddress.IPv4Address(int(ip) + 1) 
            
            if scan_list:
                return scan_list

            else: print(Fore.LIGHTYELLOW_EX + '\n[INFO] IP address not found\n' + Fore.RESET)
        else:
            if not ip_check(ip_net): return
            if ip_net == ip_route['ip']:
                return
            info_ip = arp_scan(ip_net, retry)
    
            if info_ip:
                if comments: 
                    for _ in range(2):
                        request = requests.get('https://api.macvendors.com/' + info_ip['mac'])
                        device_model = ''
                        if request.status_code == 200:
                            device_model = f' (device: {request.text.split()[0]})'
                            break 
                        
                        
                    print(Fore.LIGHTCYAN_EX + f'\n[INFO] IP {info_ip["ip"]} has the following MAC address: {info_ip["mac"]}{device_model}\n' + Fore.RESET)
                return [info_ip]
            else:
                print(Fore.LIGHTYELLOW_EX + '\n[INFO] IP address not found\n' + Fore.RESET) 
    except KeyboardInterrupt:
        return scan_list


            
       

if __name__ == '__main__':
   scan(input('[!] Введите ip адрес для сканирования: '))
