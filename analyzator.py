from binascii import hexlify
from scapy.all import *
import sys


class Stream:
    close = False
    ip_dest = []
    ip_src = []
    port_dest = []
    port_src = []
    frames = []

    def __init__(self):
        self.ip_dest = []
        self.ip_src = []
        self.port_dest = []
        self.port_src = []
        self.frames = []


# extrahuje data zo suboru
def extract_data():
    return rdpcap("vzorky/trace-12.pcap")
    filename = input("Zadaj meno súboru pre analýzu: ")
    while not os.path.exists(filename):
        print("Súbor neexistuje.")
        filename = input("Zadaj meno súboru pre analýzu: ")
    return rdpcap(filename)


# nacita zname protokoly a typy ramcov zo suboru
def load_from_file(filename, dictionary):
    for line in open(filename, "r"):
        processed = line.split(' ', 1)
        dictionary[int(processed[0], 16)] = processed[1].replace("\n", "")


# vrati bytes s udajmi bud ako hexadecimalne alebo decimalne cislo
def get_data_from_frame(frame, start, end, result_in_integer=False):
    if result_in_integer:
        return int(hexlify(frame[start:(end + 1)]), 16)
    else:
        return frame[start:(end + 1)]


# vypise data v danom formate
def print_data(seq_data, connection=' ', to_int=False):
    count = 0
    for i in seq_data:
        count += 1
        if to_int:
            if count == len(seq_data):
                print(str(i), end='')
            else:
                print(str(i) + connection, end='')
        else:
            if count == len(seq_data):
                print('{:02x}'.format(i), end='')
            else:
                print('{:02x}'.format(i) + connection, end='')


# vypis ramca bajt po bajte
def show_frame(frame_data):
    count = 0
    for i in frame_data:
        print('{:02x} '.format(i), end='')
        count += 1
        if count % 16 == 0:
            print()
            continue
        if count % 8 == 0:
            print('  ', end='')
    print()
    print()


# vypise ipv4 uzly a najvacsi z nich
def print_ipv4_nodes(nodes):
    if len(nodes) != 0:
        print("Zoznam IP adries všetkých prijímajúcich uzlov:")
        for ip in nodes:
            print_data(ip, '.', True)
            print()

        print()
        print("Adresa uzla s najväčším počtom prijatých paketov: ", end='')
        print_data(max(nodes, key=lambda k: nodes[k]), ".", True)
        print()
        print("Množstvo paketov: ", nodes.get(max(nodes, key=lambda k: nodes[k])), "paketov")


# zisti typ icmp
def process_icmp(frame, head_len):
    icmp_types = {}
    load_from_file("icmp_types.txt", icmp_types)
    if get_data_from_frame(frame, 14 + head_len * 4, 14 + head_len * 4, True) in icmp_types:
        print(icmp_types.get(get_data_from_frame(frame, 14 + head_len * 4, 14 + head_len * 4, True)))


# vytiahne bud udp alebo tcp data
def get_protocol_in_ipv4(frame):
    head_len = (get_data_from_frame(frame, 14, 14, True) - int(get_data_from_frame(frame, 14, 14, True) / 16) * 16) * 4
    return frame[14 + head_len:len(frame)]


# zisti typ ramca
def print_frame_type(ethertype_value, ieeetype_value):
    print("Typ rámca: ", end='')
    if ethertype_value >= 1500:
        print("Ethernet II")
    elif ieeetype_value == 43690:
        print("IEEE 802.3 LLC + SNAP")
    elif ieeetype_value == 65535:
        print("IEEE 802.3 raw")
    else:
        print("IEEE 802.3 LLC")


# zisti vnutorny protokol
def choose_and_print_inside_protocol(frame, ethertype_value, ieeetype_value, force_udp):
    ether_types = {}
    load_from_file("ether_types.txt", ether_types)

    llc_types = {}
    load_from_file("llc_saps.txt", llc_types)

    ip_header_protocol = {}
    load_from_file("ip_protocols.txt", ip_header_protocol)
    ip_header_num = get_data_from_frame(frame, 23, 23, True)

    ports = {}
    if ip_header_num == 17:
        load_from_file("udp_ports.txt", ports)
    elif ip_header_num == 6:
        load_from_file("tcp_ports.txt", ports)

    print("Typ vnoreného protokolu: ", end='')
    if ethertype_value >= 1500:
        load_from_file("ether_types.txt", ether_types)
        if ethertype_value not in ether_types:
            print("Neznámy Ethertype")
        else:
            print(ether_types.get(ethertype_value))

        # ARP
        if ethertype_value == 2054:
            print("Zdrojová IP adresa: ", end='')
            print_data(get_data_from_frame(frame, 28, 31), '.', True)
            print()
            print("Cieľová IP adresa: ", end='')
            print_data(get_data_from_frame(frame, 38, 41), '.', True)
            print()

        # IPv4
        if ethertype_value == 2048:
            print("Zdrojová IP adresa: ", end='')
            print_data(get_data_from_frame(frame, 26, 29), '.', True)
            print()

            print("Cieľová IP adresa: ", end='')
            print_data(get_data_from_frame(frame, 30, 33), '.', True)
            print()

            if ip_header_num in ip_header_protocol:
                print(ip_header_protocol.get(ip_header_num))

                if get_data_from_frame(frame, 23, 23, True == 17):
                    load_from_file("udp_ports.txt", ports)
                else:
                    load_from_file("tcp_ports.txt", ports)

                if force_udp == '':
                    if get_data_from_frame(get_protocol_in_ipv4(frame), 0, 1, True) in ports:
                        print(ports.get(get_data_from_frame(get_protocol_in_ipv4(frame), 0, 1, True)))
                    if get_data_from_frame(get_protocol_in_ipv4(frame), 2, 3, True) in ports:
                        print(ports.get(get_data_from_frame(get_protocol_in_ipv4(frame), 2, 3, True)))
                else:
                    print(force_udp)

                print("Zdrojový port: ", end='')
                print(get_data_from_frame(get_protocol_in_ipv4(frame), 0, 1, True))
                print("Cieľový port: ", end='')
                print(get_data_from_frame(get_protocol_in_ipv4(frame), 2, 3, True))

                if ip_header_num == 1:
                    process_icmp(frame, get_data_from_frame(frame, 14, 14, True) - int(
                        get_data_from_frame(frame, 14, 14, True) / 16) * 16)

    elif ieeetype_value == 43690:
        if get_data_from_frame(frame, 20, 21, True) == 267:
            print("PVSTP+")
        elif ethertype_value in ether_types:
            print(ether_types.get(ethertype_value))
        else:
            print("Neznámy Ethertype v SNAP-e")
    elif ieeetype_value == 65535:
        print("IPX")
    elif get_data_from_frame(frame, 21, 21, True) in llc_types:
        print(llc_types.get(get_data_from_frame(frame, 14, 14, True)))


# vypis vlastnosi ramca na obrazovku
def out_to_terminal(frame, num, force_udp=''):
    ether_type = get_data_from_frame(frame, 12, 13, True)
    ieee_type = get_data_from_frame(frame, 14, 15, True)

    print("Rámec č.", num)
    print("Dĺžka rámca poskytnutá pcap API –", len(frame), "B")
    if len(frame) + 4 > 64:
        print("Dĺžka rámca prenášaného po médiu –", len(frame) + 4, "B")
    else:
        print("Dĺžka rámca prenášaného po médiu – 64 B")

    print_frame_type(ether_type, ieee_type)

    print("Zdrojová MAC adresa: ", end='')
    print_data(get_data_from_frame(frame, 6, 11))
    print()
    print("Cieľová  MAC adresa: ", end='')
    print_data(get_data_from_frame(frame, 0, 5))
    print()
    choose_and_print_inside_protocol(frame, ether_type, ieee_type, force_udp)

    # show_frame(frame)
    print()


# prida ip prichadzajuce uzly do dictionary
def insert_ipv4_to_dict(frame, dictionary):
    dest_ip_add = get_data_from_frame(frame, 30, 33)
    if dest_ip_add in dictionary:
        dictionary[dest_ip_add] += 1
    else:
        dictionary[dest_ip_add] = 1


def is_in_replies(array, answers, item_to_test):
    reply_num = 0
    while reply_num < len(array):
        if (get_data_from_frame(item_to_test, 28, 31) == get_data_from_frame(bytes(data[array[reply_num] - 1]), 38, 41)) \
                and (
                get_data_from_frame(item_to_test, 28, 31) == get_data_from_frame(bytes(data[array[reply_num] - 1]), 38,
                                                                                 41)):
            answers.append(array[reply_num])
        reply_num += 1

    for x in answers:
        array.remove(x)


def print_arp_header(item, request=True):
    if request:
        print("ARP-Request, IP adresa: ", end='')
    else:
        print("ARP-Reply, IP adresa: ", end='')
    print_data(get_data_from_frame(item, 38, 41), '.', True)
    if request:
        print(", MAC adresa: ???")
    else:
        print(", MAC adresa: ", end='')
        print_data(get_data_from_frame(item, 22, 27))
        print()

    print("Zdrojová IP: ", end='')
    print_data(get_data_from_frame(item, 28, 31), '.', True)
    print(" Cieľová IP: ", end='')
    print_data(get_data_from_frame(item, 38, 41), '.', True)
    print()
    print()


def is_ip_dest_in_stream(streams, ip_dest, ip_src, prt_src=0, prt_dest=0):
    for x in range(0, len(streams)):
        if streams[x].close == True:
            continue
        if ((streams[x].ip_src == ip_dest) and (streams[x].ip_dest == ip_src) and (
                streams[x].port_dest == prt_dest) and (streams[x].port_src == prt_src)) \
                or ((streams[x].ip_src == ip_src) and (streams[x].ip_dest == ip_dest) and (
                streams[x].port_dest == prt_src) and (streams[x].port_src == prt_dest)):
            return x
    return -1


def insert_to_streams(arr_of_streams, frame_id, ip_src, ip_dest, port_src, port_dest):
    act_str = is_ip_dest_in_stream(arr_of_streams, ip_src, ip_dest, port_src, port_dest)
    if act_str >= 0:
        arr_of_streams[act_str].frames.append(frame_id + 1)
    elif act_str == -1:
        arr_of_streams.append(Stream())
        arr_of_streams[len(arr_of_streams) - 1].ip_src = get_data_from_frame(frame, 26, 29)
        arr_of_streams[len(arr_of_streams) - 1].ip_dest = get_data_from_frame(frame, 30, 33)
        arr_of_streams[len(arr_of_streams) - 1].port_src = get_data_from_frame(tcp, 0, 1)
        arr_of_streams[len(arr_of_streams) - 1].port_dest = get_data_from_frame(tcp, 2, 3)
        arr_of_streams[len(arr_of_streams) - 1].frames.append(frame_id + 1)

def process_data(data, menu):
    ip_dest_nodes = {}

    if menu == 'all':
        for frame_id in range(0, len(data)):
            frame = bytes(data[frame_id])
            out_to_terminal(frame, frame_id + 1)

            if get_data_from_frame(frame, 12, 13, True) == 2048:
                insert_ipv4_to_dict(frame, ip_dest_nodes)

        print_ipv4_nodes(ip_dest_nodes)
    elif (menu == 'h') or (menu == 'hs') or (menu == 'te') or (menu == 's') or (menu == 'fd') or (menu == 'fr'):
        if menu == 'h':
            menu = 'HTTP'
        if menu == 'hs':
            menu = 'HTTPS'
        if menu == 'te':
            menu = 'TELNET'
        if menu == 's':
            menu = 'SSH'
        if menu == 'fd':
            menu = 'FTP datove'
        if menu == 'fr':
            menu = 'FTP riadiace'
        tcp_streams = []
        tcp_ports = {}
        load_from_file("tcp_ports.txt", tcp_ports)

        for frame_id in range(0, len(data)):
            frame = bytes(data[frame_id])

            if (get_data_from_frame(frame, 12, 13, True) == 2048) and (get_data_from_frame(frame, 23, 23, True) == 6):
                tcp = get_protocol_in_ipv4(frame)

                if get_data_from_frame(get_protocol_in_ipv4(frame), 0, 1, True) in tcp_ports:
                    if tcp_ports.get(get_data_from_frame(get_protocol_in_ipv4(frame), 0, 1, True)) != menu:
                        continue
                if get_data_from_frame(get_protocol_in_ipv4(frame), 2, 3, True) in tcp_ports:
                    if tcp_ports.get(get_data_from_frame(get_protocol_in_ipv4(frame), 2, 3, True)) != menu:
                        continue

                act_str = is_ip_dest_in_stream(tcp_streams, get_data_from_frame(frame, 26, 29),
                                               get_data_from_frame(frame, 30, 33),
                                               get_data_from_frame(tcp, 0, 1), get_data_from_frame(tcp, 2, 3))
                if act_str >= 0:
                    tcp_streams[act_str].frames.append(frame_id + 1)
                elif act_str == -1:
                    tcp_streams.append(Stream())
                    tcp_streams[len(tcp_streams) - 1].ip_src = get_data_from_frame(frame, 26, 29)
                    tcp_streams[len(tcp_streams) - 1].ip_dest = get_data_from_frame(frame, 30, 33)
                    tcp_streams[len(tcp_streams) - 1].port_src = get_data_from_frame(tcp, 0, 1)
                    tcp_streams[len(tcp_streams) - 1].port_dest = get_data_from_frame(tcp, 2, 3)
                    tcp_streams[len(tcp_streams) - 1].frames.append(frame_id + 1)
        print()

        good = 0
        semi_good = 0
        for x in tcp_streams:
            begin = 0
            end = 0
            if (get_data_from_frame(get_protocol_in_ipv4(bytes(data[x.frames[0] - 1])), 13, 13, True) == 0x2) \
                    and (get_data_from_frame(get_protocol_in_ipv4(bytes(data[x.frames[1] - 1])), 13, 13, True) == 0x12) \
                    and (get_data_from_frame(get_protocol_in_ipv4(bytes(data[x.frames[2] - 1])), 13, 13, True) == 0x10):
                begin = 1

            # skontrolovat
            if (get_data_from_frame(get_protocol_in_ipv4(bytes(data[x.frames[len(x.frames) - 1] - 1])), 13, 13,
                                    True) == 0x14) \
                    or (get_data_from_frame(get_protocol_in_ipv4(bytes(data[x.frames[len(x.frames) - 1] - 1])), 13, 13,
                                            True) == 0x4):
                end = 1
            else:
                if (get_data_from_frame(get_protocol_in_ipv4(bytes(data[x.frames[len(x.frames) - 1] - 1])), 13, 13,
                                        True) == 0x10) \
                        and (
                        get_data_from_frame(get_protocol_in_ipv4(bytes(data[x.frames[len(x.frames) - 2] - 1])), 13, 13,
                                            True) == 0x11) \
                        and (
                        get_data_from_frame(get_protocol_in_ipv4(bytes(data[x.frames[len(x.frames) - 3] - 1])), 13, 13,
                                            True) == 0x11):
                    end = 1
                else:
                    if (get_data_from_frame(get_protocol_in_ipv4(bytes(data[x.frames[len(x.frames) - 1] - 1])), 13, 13,
                                            True) == 0x10) \
                            and (
                            get_data_from_frame(get_protocol_in_ipv4(bytes(data[x.frames[len(x.frames) - 2] - 1])), 13,
                                                13, True) == 0x11) \
                            and (
                            get_data_from_frame(get_protocol_in_ipv4(bytes(data[x.frames[len(x.frames) - 3] - 1])), 13,
                                                13, True) == 0x10) \
                            and (
                            get_data_from_frame(get_protocol_in_ipv4(bytes(data[x.frames[len(x.frames) - 4] - 1])), 13,
                                                13, True) == 0x11):
                        end = 1
            if good == 0:
                if begin and end:
                    print("----------------------------------------------------------------------------------")
                    print("Komunikácia začatá aj ukončená správne")
                    for y in x.frames:
                        out_to_terminal(bytes(data[y - 1]), y)
                    good = 1
            if semi_good == 0:
                if begin and not end:
                    print("----------------------------------------------------------------------------------")
                    print("Komunikácia začatá ale neukončená správne")
                    for y in x.frames:
                        out_to_terminal(bytes(data[y - 1]), y)
                    semi_good = 1
    elif (menu == 'tf'):
        if menu == 'tf':
            menu = 'TFTP'
        udp_streams = []
        frame_id = 0
        while frame_id < len(data):
            frame = bytes(data[frame_id])
            if (get_data_from_frame(frame, 12, 13, True) == 2048) and (get_data_from_frame(frame, 23, 23, True) == 17):
                udp = get_protocol_in_ipv4(frame)

                act_str = is_ip_dest_in_stream(udp_streams, get_data_from_frame(frame, 26, 29),
                                               get_data_from_frame(frame, 30, 33),
                                               get_data_from_frame(udp, 0, 1), get_data_from_frame(udp, 2, 3))
                if act_str >= 0:
                    udp_streams[act_str].frames.append(frame_id + 1)
                elif act_str == -1:
                    udp_streams.append(Stream())
                    udp_streams[len(udp_streams) - 1].ip_src = get_data_from_frame(frame, 26, 29)
                    udp_streams[len(udp_streams) - 1].ip_dest = get_data_from_frame(frame, 30, 33)
                    udp_streams[len(udp_streams) - 1].port_src = get_data_from_frame(udp, 0, 1)
                    udp_streams[len(udp_streams) - 1].port_dest = get_data_from_frame(udp, 2, 3)
                    udp_streams[len(udp_streams) - 1].frames.append(frame_id + 1)

            frame_id += 1

        x = 0
        while x < len(udp_streams):
            if (len(udp_streams[x].frames) == 1) and (get_data_from_frame(udp_streams[x].port_dest, 0, 1, True) == 69):
                udp_streams[x+1].frames.insert(0, udp_streams[x].frames[0])
                udp_streams.pop(x)
                x += 1
            else:
                udp_streams.pop(x)
        com_count = 1
        for x in udp_streams:
            print("----------------------------------------------------------------------------------")
            print("Komunikácia č.", com_count)
            com_count += 1
            for y in x.frames:
                out_to_terminal(bytes(data[y - 1]), y, menu)
    elif (menu == 'i'):
        if menu == 'i':
            menu = 'ICMP'

        icmp_streams = []
        frame_id = 0
        while frame_id < len(data):
            frame = bytes(data[frame_id])
            if (get_data_from_frame(frame, 12, 13, True) == 2048) and (get_data_from_frame(frame, 23, 23, True) == 1):
                act_str = is_ip_dest_in_stream(icmp_streams, get_data_from_frame(frame, 26, 29),
                                               get_data_from_frame(frame, 30, 33),)
                if act_str >= 0:
                    icmp_streams[act_str].frames.append(frame_id + 1)
                elif act_str == -1:
                    icmp_streams.append(Stream())
                    icmp_streams[len(icmp_streams) - 1].ip_src = get_data_from_frame(frame, 26, 29)
                    icmp_streams[len(icmp_streams) - 1].ip_dest = get_data_from_frame(frame, 30, 33)
                    icmp_streams[len(icmp_streams) - 1].frames.append(frame_id + 1)
                    icmp_streams[len(icmp_streams) - 1].port_src = 0
                    icmp_streams[len(icmp_streams) - 1].port_dest = 0

            frame_id += 1

        com_count = 1
        for x in icmp_streams:
            print("----------------------------------------------------------------------------------")
            print("Komunikácia č.", com_count)
            com_count += 1
            for y in x.frames:
                out_to_terminal(bytes(data[y - 1]), y)
    elif menu == 'a':
        arp_streams = []
        frame_id = 0
        while frame_id < len(data):
            frame = bytes(data[frame_id])
            if (get_data_from_frame(frame, 12, 13, True) == 2054):
                act_str = is_ip_dest_in_stream(arp_streams, get_data_from_frame(frame, 28, 31),
                                               get_data_from_frame(frame, 38, 41), )
                if act_str >= 0:
                    arp_streams[act_str].frames.append(frame_id + 1)
                    if get_data_from_frame(frame, 20, 21, True) == 2:
                        arp_streams[act_str].close = True
                elif act_str == -1:
                    arp_streams.append(Stream())
                    arp_streams[len(arp_streams) - 1].ip_src = get_data_from_frame(frame, 38, 41)
                    arp_streams[len(arp_streams) - 1].ip_dest = get_data_from_frame(frame, 28, 31)
                    arp_streams[len(arp_streams) - 1].frames.append(frame_id + 1)
                    arp_streams[len(arp_streams) - 1].port_src = 0
                    arp_streams[len(arp_streams) - 1].port_dest = 0

            frame_id += 1

        com_count = 1
        if len(arp_streams) > 0:
            temp = False
            for x in arp_streams:
                if x.close and (len(x.frames) > 1):
                    print("----------------------------------------------------------------------------------")
                    print("Komunikácia č.", com_count)
                    com_count += 1
                    print_arp_header(bytes(data[x.frames[0] - 1]))
                    for y in x.frames:
                        if get_data_from_frame(bytes(data[y-1]), 20, 21, True) == 2:
                            print_arp_header(bytes(data[y-1]), False)
                        out_to_terminal(bytes(data[y - 1]), y)
                else:
                    temp = True

            if temp:
                print("----------------------------------------------------------------------------------")
                print("Zbytok ARP rámcov")
                for x in arp_streams:
                    if x.close == False or (len(x.frames) == 1):
                        for y in x.frames:
                            out_to_terminal(bytes(data[y - 1]), y)

        print_ipv4_nodes(ip_dest_nodes)
    else:
        out_to_terminal(bytes(data[int(menu) - 1]), int(menu))


print()
print("*****************************************************************************")
print("                     Analyzátor sieťovej komunikácie                         ")
print("                           Autor: Matej Delinčák                             ")
print("*****************************************************************************")
print()

data = extract_data()
print("Zadaj moznost:")
print("     all - pre výpis všetkých rámcov")
print("     h - pre výpis HTTP rámcov")
print("     hs - pre výpis HTTPS rámcov")
print("     te - pre výpis TELNET rámcov")
print("     s - pre výpis SSH rámcov")
print("     fr - pre výpis FTP riadiace rámcov")
print("     fd - pre výpis FTP dátové rámcov")
print("     tf - pre výpis TFTP rámcov")
print("     i - pre výpis ICMP rámcov")
print("     a - pre výpis ARP rámcov")
print("     číslo rámca - pre výpis požadovaného rámca")
print("Zadaj možnosť: ", end='')
frame = input().lower()
print("Vypísať výstup do konzoly? y/n: ", end='')
menu = 'y'  # input().lower()
print()
file = ""
if menu == 'n':
    print("Zadaj výstupný súbor: ", end='')
    file = "vystup.txt"  # input()
    sys.stdout = file = open(file, "w", encoding="utf-8")
process_data(data, frame)
if menu == 'n':
    file.close()
