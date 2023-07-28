import argparse


def argsumentparse():
    parser = argparse.ArgumentParser(description='Version - 0.1', usage='%(prog)s [-h] | [-s SCAN [-r RETRY]] | [-B BLOCK] | [-I [INTERFACE] [-nm [NEW_MAC] | -nn NEW_NAME]] | [-p SPOOF] | [-cs SOURCE [-ct TARGET]] | [-m [SNIFF]]')
    parser.add_argument('-s', '--scan', dest='scan', help='IP address for scanning')
    parser.add_argument('-r', '--retry', dest='retry', help='Maximum packets sent to IP address')


    parser.add_argument('-B', '--block', dest='block', help='Blocking access to Wi-Fi')


    parser.add_argument('-I', '--interface', nargs='?', const='&', default=False, dest='interface', help='Your interfaces')
    parser.add_argument('-nm', '--new_mac',nargs='?', const='&', dest='new_mac', help='New MAC address')
    parser.add_argument('-nn', '--new_name', dest='new_name', help='New name')

    
    parser.add_argument('-p', '--spoof', dest='spoof', help='Spoofing ARP packets')

 
    parser.add_argument('-cs', '--source', dest='source', help='Victim`s source site') 
    parser.add_argument('-ct', '--target', dest='target', help='Victim`s target site')

    
    parser.add_argument('-m', '--sniff', dest='sniff', nargs='?', const=True, default=False, help='Sniff packet. Data search')


    return  parser.parse_args()


