import subprocess
import re
from random import randint
from colorama import Fore

def check_default_ip_route():
    def_ip_route = re.search(r'(?:default via) (\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})', subprocess.check_output(['ip','route']).decode())
    if def_ip_route:
        return def_ip_route.group(1)
    else: 
        print(Fore.LIGHTYELLOW_EX + '[INFO] Not found IP route' + Fore.RESET)


def get_current_mac(interface) -> str:
    ip_result = subprocess.check_output(['ip', 'link', 'show', interface])
    mac_address = re.search(rb'\w\w:\w\w:\w\w:\w\w:\w\w:\w\w', ip_result).group(0).decode()
    return mac_address


def random_mac() -> str:
    mac = [randint(0x00,0xff) for _ in range(6)]
    mac_adress = ':'.join(f'{x:02x}' for x in mac)
    return mac_adress


def get_all_interface_and_mac(comment=False) -> dict:
    all_info = subprocess.check_output("ip link show | awk '{print $2, $9, $11, $17}'", shell=True, text=True).split()
    interfaces = {}
    if comment:
        print(Fore.LIGHTCYAN_EX + '','-' * 68)
        print(' | {:^16} | {:^19} | {:^10} | {:^10} |'.format('INTERFACE', 'MAC', 'STATE', 'MODE'))
        print('','-' * 68)
    for i in range(int(len(all_info)) // 4):
        interface, state, mode, mac = all_info[4 * i][:-1], all_info[4 * i + 1], all_info[4 * i + 2], all_info[4 * i + 3]
        if comment:
            print(' | {:^16} | {:^19} | {:^10} | {:^10} |'.format(interface, mac, state, mode))
            print('','-' * 68)
        interfaces[interface] = mac 
    if comment: print(Fore.RESET)
    return interfaces

def change_mac(interface, new_mac) -> None:
    interfaces = get_all_interface_and_mac()
    if interface not in interfaces:
        print(Fore.LIGHTYELLOW_EX + '[INFO] Incorrect interface' + Fore.RESET)
    elif interfaces[interface] == '00:00:00:00:00:00':
        print(Fore.LIGHTYELLOW_EX + '[INFO] Cannot change MAC address of this interface' + Fore.RESET)
    else:
        subprocess.call(['ip', 'link', 'set', interface, 'down'])
    
        try:
            subprocess.check_output(['ip', 'link', 'set', 'dev', interface, 'address', new_mac], stderr=subprocess.DEVNULL) 
        except KeyboardInterrupt: pass    
        except:
            y = 'y'
            if new_mac != '&':
                print(Fore.LIGHTRED_EX + '\n[WARNING] This address is unsafe or incorrect\n' + Fore.RESET)
                y = input('\tUse a random MAC address? (y/n): ')
    
            old_address = get_current_mac(interface)
            if y == 'y':
                while get_current_mac(interface) == old_address:
                    subprocess.call(['ip', 'link', 'set', 'dev', interface, 'address', random_mac()], stderr=subprocess.DEVNULL) 
                print(Fore.GREEN + f'\n[+] MAC adress was successfully changed to {get_current_mac(interface)}\n' + Fore.RESET)
            else: print(Fore.LIGHTYELLOW_EX + f'\n[INFO] MAC address wasn`t changed\n' + Fore.RESET)
        finally: subprocess.call(['ip', 'link', 'set', interface, 'up'])


def change_interface_name(interface, new_name) -> None:
    try:
        if interface in get_all_interface_and_mac():
            subprocess.call(['ip', 'link', 'set', interface, 'down'], stderr=subprocess.DEVNULL)
            subprocess.call(['ip', 'link', 'set', 'dev', interface, 'name', new_name], stderr=subprocess.DEVNULL)
            subprocess.call(['ip', 'link', 'set', interface, 'up'], stderr=subprocess.DEVNULL)
            print(Fore.GREEN + f'\n[+] Interface {interface} has been renamed to {new_name}' + Fore.RESET)
        else: print(Fore.LIGHTYELLOW_EX + '[INFO] Incorrect interface' + Fore.RESET)
    except KeyboardInterrupt: pass    
    except Exception as ERROR: print(Fore.RED + f'\n[ERROR] {type(ERROR).__name__}\n' + Fore.RESET)

                    
    

if __name__ == '__main__': 
    interfaces = get_all_interface_and_mac(comment=True)
    num = input('\nСмена имени интерфейса(1) или Смена mac адреса(2): ')
    
    if num =='1':
        interface = input('Введите название интерфейса, которую хотите поменять: ')
        name = input('Введите новое имя интерфейса: ')
        change_interface_name(interface,name)

    elif num == '2':
        interface = input('Введите название интерфейса, которую хотите поменять: ')
        mac = input("Введите новый mac адрес (& для установки случайного mac адреса): ")
        change_mac(interface,mac)
