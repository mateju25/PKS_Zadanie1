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

    def __init__(self, p_ip_src, p_ip_dest, p_port_src, p_port_dest, p_frame_id):
        self.ip_src = p_ip_src
        self.ip_dest = p_ip_dest
        self.port_dest = p_port_src
        self.port_src = p_port_dest
        self.frames = []
        self.frames.append(p_frame_id + 1)


# extrahuje data zo suboru
def extract_data():
    filename = input("Zadaj meno súboru pre analýzu: ")
    while not os.path.exists(filename):
        print("Súbor neexistuje.")
        filename = input("Zadaj meno súboru pre analýzu: ")
    return rdpcap(filename)


# nacita zname protokoly a typy ramcov zo suboru
def load_from_file(p_filename, p_dictionary):
    for line in open(p_filename, "r"):
        processed = line.split(' ', 1)
        p_dictionary[int(processed[0], 16)] = processed[1].replace("\n", "")


# vrati bytes s udajmi bud ako hexadecimalne alebo decimalne cislo
def get_data_from_frame(p_frame, p_start, p_end, p_result_in_integer=False):
    if p_result_in_integer:
        return int(hexlify(p_frame[p_start:(p_end + 1)]), 16)
    else:
        return p_frame[p_start:(p_end + 1)]


# vypise data v danom formate
def print_data(p_seq_data, p_connection=' ', p_to_int=False):
    count = 0
    for i in p_seq_data:
        count += 1
        if p_to_int:
            if count == len(p_seq_data):
                print(str(i), end='')
            else:
                print(str(i) + p_connection, end='')
        else:
            if count == len(p_seq_data):
                print('{:02x}'.format(i), end='')
            else:
                print('{:02x}'.format(i) + p_connection, end='')


# vypis ramca bajt po bajte
def show_frame(p_frame_data):
    count = 0
    for i in p_frame_data:
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
def print_ipv4_nodes(p_nodes):
    if len(p_nodes) != 0:
        print("Zoznam IP adries všetkých prijímajúcich uzlov:")
        for ip in p_nodes:
            print_data(ip, '.', True)
            print()

        print()
        print("Adresa uzla s najväčším počtom prijatých paketov: ", end='')
        print_data(max(p_nodes, key=lambda k: p_nodes[k]), ".", True)
        print()
        print("Množstvo paketov: ", p_nodes.get(max(p_nodes, key=lambda k: p_nodes[k])), "paketov")


# vytiahne transportny protokol
def get_transport_protocol(p_frame):
    head_len = (get_data_from_frame(p_frame, 14, 14, True) - int(
        get_data_from_frame(p_frame, 14, 14, True) / 16) * 16) * 4
    return p_frame[14 + head_len:len(p_frame)]


# vypise typ ramca
def print_frame_type(p_ethertype_value, p_ieeetype_value):
    print("Typ rámca: ", end='')
    if p_ethertype_value >= 1500:
        print("Ethernet II")
    elif p_ieeetype_value == 43690:
        print("IEEE 802.3 LLC + SNAP")
    elif p_ieeetype_value == 65535:
        print("IEEE 802.3 raw")
    else:
        print("IEEE 802.3 LLC")


# zisti a vypise vnutorny protokol
def choose_and_print_inside_protocol(p_frame, p_ethertype_value, p_ieeetype_value, p_force_udp):
    ether_types = {}
    load_from_file("ether_types.txt", ether_types)

    llc_types = {}
    load_from_file("llc_saps.txt", llc_types)

    ip_header_protocol = {}
    load_from_file("ip_protocols.txt", ip_header_protocol)
    ip_header_num = get_data_from_frame(p_frame, 23, 23, True)

    ports = {}
    if ip_header_num == 17:
        load_from_file("udp_ports.txt", ports)
    elif ip_header_num == 6:
        load_from_file("tcp_ports.txt", ports)

    print("Typ vnoreného protokolu: ", end='')
    if p_ethertype_value >= 1500:
        load_from_file("ether_types.txt", ether_types)
        if p_ethertype_value not in ether_types:
            print("Neznámy Ethertype")
        else:
            print(ether_types.get(p_ethertype_value))

        # ARP
        if p_ethertype_value == 2054:
            print("Zdrojová IP adresa: ", end='')
            print_data(get_data_from_frame(p_frame, 28, 31), '.', True)
            print()
            print("Cieľová IP adresa: ", end='')
            print_data(get_data_from_frame(p_frame, 38, 41), '.', True)
            print()

        # IPv4
        if p_ethertype_value == 2048:
            print("Zdrojová IP adresa: ", end='')
            print_data(get_data_from_frame(p_frame, 26, 29), '.', True)
            print()

            print("Cieľová IP adresa: ", end='')
            print_data(get_data_from_frame(p_frame, 30, 33), '.', True)
            print()

            if ip_header_num in ip_header_protocol:
                print(ip_header_protocol.get(ip_header_num))

                if get_data_from_frame(p_frame, 23, 23, True) == 17:
                    load_from_file("udp_ports.txt", ports)
                else:
                    load_from_file("tcp_ports.txt", ports)

                if p_force_udp == '':
                    if get_data_from_frame(get_transport_protocol(p_frame), 0, 1, True) in ports:
                        print(ports.get(get_data_from_frame(get_transport_protocol(p_frame), 0, 1, True)))
                    if get_data_from_frame(get_transport_protocol(p_frame), 2, 3, True) in ports:
                        print(ports.get(get_data_from_frame(get_transport_protocol(p_frame), 2, 3, True)))
                else:
                    print(p_force_udp)

                print("Zdrojový port: ", end='')
                print(get_data_from_frame(get_transport_protocol(p_frame), 0, 1, True))
                print("Cieľový port: ", end='')
                print(get_data_from_frame(get_transport_protocol(p_frame), 2, 3, True))

                if ip_header_num == 1:
                    icmp_types = {}
                    load_from_file("icmp_types.txt", icmp_types)

                    if get_data_from_frame(get_transport_protocol(p_frame), 0, 0, True) in icmp_types:
                        print(icmp_types.get(get_data_from_frame(get_transport_protocol(p_frame), 0, 0, True)))

    elif p_ieeetype_value == 43690:
        if get_data_from_frame(p_frame, 20, 21, True) == 267:
            print("PVSTP+")
        elif p_ethertype_value in ether_types:
            print(ether_types.get(p_ethertype_value))
        else:
            print("Neznámy Ethertype v SNAP-e")
    elif p_ieeetype_value == 65535:
        print("IPX")
    elif get_data_from_frame(p_frame, 21, 21, True) in llc_types:
        print(llc_types.get(get_data_from_frame(p_frame, 14, 14, True)))


# vypis vlastnosi ramca na obrazovku
def out_to_terminal(p_frame, p_num, p_force_udp=''):
    ether_type = get_data_from_frame(p_frame, 12, 13, True)
    ieee_type = get_data_from_frame(p_frame, 14, 15, True)

    print("Rámec č.", p_num)
    print("Dĺžka rámca poskytnutá pcap API –", len(p_frame), "B")
    if len(p_frame) + 4 > 64:
        print("Dĺžka rámca prenášaného po médiu –", len(p_frame) + 4, "B")
    else:
        print("Dĺžka rámca prenášaného po médiu – 64 B")

    print_frame_type(ether_type, ieee_type)

    print("Zdrojová MAC adresa: ", end='')
    print_data(get_data_from_frame(p_frame, 6, 11))
    print()
    print("Cieľová  MAC adresa: ", end='')
    print_data(get_data_from_frame(p_frame, 0, 5))
    print()
    choose_and_print_inside_protocol(p_frame, ether_type, ieee_type, p_force_udp)

    show_frame(p_frame)


# prida ip prichadzajuce uzly do dictionary
def insert_ipv4_to_dict(p_frame, p_dictionary):
    dest_ip_add = get_data_from_frame(p_frame, 30, 33)
    if dest_ip_add in p_dictionary:
        p_dictionary[dest_ip_add] += 1
    else:
        p_dictionary[dest_ip_add] = 1


# vypise arp hlavicku
def print_arp_header(p_item, p_request=True):
    if p_request:
        print("ARP-Request, IP adresa: ", end='')
    else:
        print("ARP-Reply, IP adresa: ", end='')
    print_data(get_data_from_frame(p_item, 38, 41), '.', True)
    if p_request:
        print(", MAC adresa: ???")
    else:
        print(", MAC adresa: ", end='')
        print_data(get_data_from_frame(p_item, 22, 27))
        print()

    print("Zdrojová IP: ", end='')
    print_data(get_data_from_frame(p_item, 28, 31), '.', True)
    print(" Cieľová IP: ", end='')
    print_data(get_data_from_frame(p_item, 38, 41), '.', True)
    print()
    print()


def is_ip_dest_in_stream(p_streams, p_ip_dest, p_ip_src, p_prt_src=0, p_prt_dest=0):
    for x in range(0, len(p_streams)):
        if p_streams[x].close:
            continue
        if ((p_streams[x].ip_src == p_ip_dest) and (p_streams[x].ip_dest == p_ip_src) and (
                p_streams[x].port_dest == p_prt_src) and (p_streams[x].port_src == p_prt_dest)) \
                or ((p_streams[x].ip_src == p_ip_src) and (p_streams[x].ip_dest == p_ip_dest) and (
                p_streams[x].port_dest == p_prt_dest) and (p_streams[x].port_src == p_prt_src)):
            return x
    return -1


def insert_to_streams(p_arr_of_streams, p_frame_id, p_ip_src, p_ip_dest, p_port_src=0, p_port_dest=0):
    act_str = is_ip_dest_in_stream(p_arr_of_streams, p_ip_src, p_ip_dest, p_port_src, p_port_dest)
    if act_str >= 0:
        p_arr_of_streams[act_str].frames.append(p_frame_id + 1)
    elif act_str == -1:
        p_arr_of_streams.append(Stream(p_ip_src, p_ip_dest, p_port_src, p_port_dest, p_frame_id))


def process_data(p_data, p_menu):
    ip_dest_nodes = {}

    if p_menu == 'all':
        for frame_id in range(0, len(p_data)):
            frame = bytes(p_data[frame_id])
            out_to_terminal(frame, frame_id + 1)

            if get_data_from_frame(frame, 12, 13, True) == 2048:
                insert_ipv4_to_dict(frame, ip_dest_nodes)

    elif (p_menu == 'h') or (p_menu == 'hs') or (p_menu == 'te') or (p_menu == 's') or (p_menu == 'fd') or (
            p_menu == 'fr'):

        if p_menu == 'h':
            p_menu = 'HTTP'
        if p_menu == 'hs':
            p_menu = 'HTTPS'
        if p_menu == 'te':
            p_menu = 'TELNET'
        if p_menu == 's':
            p_menu = 'SSH'
        if p_menu == 'fd':
            p_menu = 'FTP datove'
        if p_menu == 'fr':
            p_menu = 'FTP riadiace'
        tcp_streams = []
        tcp_ports = {}
        load_from_file("tcp_ports.txt", tcp_ports)

        for frame_id in range(0, len(p_data)):
            frame = bytes(p_data[frame_id])
            if get_data_from_frame(frame, 12, 13, True) == 2048:
                insert_ipv4_to_dict(frame, ip_dest_nodes)
                if get_data_from_frame(frame, 23, 23, True) == 6:
                    tcp = get_transport_protocol(frame)

                    if get_data_from_frame(get_transport_protocol(frame), 0, 1, True) in tcp_ports:
                        if tcp_ports.get(get_data_from_frame(get_transport_protocol(frame), 0, 1, True)) != p_menu:
                            continue
                    else:
                        if get_data_from_frame(get_transport_protocol(frame), 2, 3, True) in tcp_ports:
                            if tcp_ports.get(get_data_from_frame(get_transport_protocol(frame), 2, 3, True)) != p_menu:
                                continue
                        else:
                            continue

                    insert_to_streams(tcp_streams, frame_id, get_data_from_frame(frame, 26, 29),
                                      get_data_from_frame(frame, 30, 33), get_data_from_frame(tcp, 0, 1),
                                      get_data_from_frame(tcp, 2, 3))

        good = 0
        semi_good = 0
        for x in tcp_streams:
            begin = 0
            end = 0
            if (get_data_from_frame(get_transport_protocol(bytes(p_data[x.frames[0] - 1])), 13, 13, True) == 0x2) \
                    and (
                    get_data_from_frame(get_transport_protocol(bytes(p_data[x.frames[1] - 1])), 13, 13, True) == 0x12) \
                    and (
                    get_data_from_frame(get_transport_protocol(bytes(p_data[x.frames[2] - 1])), 13, 13, True) == 0x10):
                begin = 1

            # skontrolovat
            if (get_data_from_frame(get_transport_protocol(bytes(p_data[x.frames[len(x.frames) - 1] - 1])), 13, 13,
                                    True) == 0x14) \
                    or (
                    get_data_from_frame(get_transport_protocol(bytes(p_data[x.frames[len(x.frames) - 1] - 1])), 13, 13,
                                        True) == 0x4):
                end = 1
            else:
                if (get_data_from_frame(get_transport_protocol(bytes(p_data[x.frames[len(x.frames) - 1] - 1])), 13, 13,
                                        True) == 0x10) \
                        and (
                        get_data_from_frame(get_transport_protocol(bytes(p_data[x.frames[len(x.frames) - 2] - 1])), 13,
                                            13,
                                            True) == 0x11) \
                        and (
                        get_data_from_frame(get_transport_protocol(bytes(p_data[x.frames[len(x.frames) - 3] - 1])), 13,
                                            13,
                                            True) == 0x11):
                    end = 1
                else:
                    if (get_data_from_frame(get_transport_protocol(bytes(p_data[x.frames[len(x.frames) - 1] - 1])), 13,
                                            13,
                                            True) == 0x10) \
                            and (
                            get_data_from_frame(get_transport_protocol(bytes(p_data[x.frames[len(x.frames) - 2] - 1])),
                                                13,
                                                13, True) == 0x11) \
                            and (
                            get_data_from_frame(get_transport_protocol(bytes(p_data[x.frames[len(x.frames) - 3] - 1])),
                                                13,
                                                13, True) == 0x10) \
                            and (
                            get_data_from_frame(get_transport_protocol(bytes(p_data[x.frames[len(x.frames) - 4] - 1])),
                                                13,
                                                13, True) == 0x11):
                        end = 1
            if good == 0:
                if begin and end:
                    print("----------------------------------------------------------------------------------")
                    print("Komunikácia začatá aj ukončená správne")
                    for y in x.frames:
                        out_to_terminal(bytes(p_data[y - 1]), y)
                    good = 1

            if semi_good == 0:
                if begin and not end:
                    print("----------------------------------------------------------------------------------")
                    print("Komunikácia začatá správne ale neukončená správne")
                    for y in x.frames:
                        out_to_terminal(bytes(p_data[y - 1]), y)
                    semi_good = 1

        if good == 0:
            print("Komunikácia začatá aj ukončená správne v tejto vzorke neexistuje.")
        if semi_good == 0:
            print("Komunikácia začatá správne ale neukončená správne v tejto vzorke neexistuje.")

    elif p_menu == 'tf':
        if p_menu == 'tf':
            p_menu = 'TFTP'
        udp_streams = []
        for frame_id in range(0, len(p_data)):
            frame = bytes(p_data[frame_id])
            if get_data_from_frame(frame, 12, 13, True) == 2048:
                insert_ipv4_to_dict(frame, ip_dest_nodes)
                if get_data_from_frame(frame, 23, 23, True) == 17:
                    udp = get_transport_protocol(frame)
                    insert_to_streams(udp_streams, frame_id, get_data_from_frame(frame, 26, 29),
                                      get_data_from_frame(frame, 30, 33), get_data_from_frame(udp, 0, 1),
                                      get_data_from_frame(udp, 2, 3))


        x = 0
        while x < len(udp_streams):
            if (len(udp_streams[x].frames) == 1) and (get_data_from_frame(udp_streams[x].port_dest, 0, 1, True) == 69):
                udp_streams[x + 1].frames.insert(0, udp_streams[x].frames[0])
                udp_streams.pop(x)
                x += 1
            else:
                udp_streams.pop(x)
        com_count = 1
        if len(udp_streams) == 0:
            print("Žiadna komunikácia sa nenašla.")
        for x in udp_streams:
            print("----------------------------------------------------------------------------------")
            print("Komunikácia č.", com_count)
            com_count += 1
            for y in x.frames:
                out_to_terminal(bytes(p_data[y - 1]), y, p_menu)

    elif p_menu == 'i':
        if p_menu == 'i':
            p_menu = 'ICMP'

        icmp_streams = []
        for frame_id in range(0, len(p_data)):
            frame = bytes(p_data[frame_id])
            if get_data_from_frame(frame, 12, 13, True) == 2048:
                insert_ipv4_to_dict(frame, ip_dest_nodes)
                if get_data_from_frame(frame, 23, 23, True) == 1:
                    insert_to_streams(icmp_streams, frame_id, get_data_from_frame(frame, 26, 29),
                                    get_data_from_frame(frame, 30, 33))


        com_count = 1
        if len(icmp_streams) == 0:
            print("Žiadna komunikácia sa nenašla.")
        for x in icmp_streams:
            print("----------------------------------------------------------------------------------")
            print("Komunikácia č.", com_count)
            com_count += 1
            for y in x.frames:
                out_to_terminal(bytes(p_data[y - 1]), y)

    elif p_menu == 'a':
        arp_streams = []
        for frame_id in range(0, len(p_data)):
            frame = bytes(p_data[frame_id])
            if get_data_from_frame(frame, 12, 13, True) == 2054:
                insert_to_streams(arp_streams, frame_id, get_data_from_frame(frame, 28, 31),
                                  get_data_from_frame(frame, 38, 41))

        com_count = 1
        if len(arp_streams) > 0:
            temp = False
            for x in arp_streams:
                if x.close and (len(x.frames) > 1):
                    print("----------------------------------------------------------------------------------")
                    print("Komunikácia č.", com_count)
                    com_count += 1
                    print_arp_header(bytes(p_data[x.frames[0] - 1]))
                    for y in x.frames:
                        if get_data_from_frame(bytes(p_data[y - 1]), 20, 21, True) == 2:
                            print_arp_header(bytes(p_data[y - 1]), False)
                        out_to_terminal(bytes(p_data[y - 1]), y)
                else:
                    temp = True

            if temp:
                print("----------------------------------------------------------------------------------")
                print("Zbytok ARP rámcov")
                for x in arp_streams:
                    if x.close is False or (len(x.frames) == 1):
                        for y in x.frames:
                            out_to_terminal(bytes(p_data[y - 1]), y)

    else:
        if type(p_menu) is int:
            out_to_terminal(bytes(p_data[int(p_menu) - 1]), int(p_menu))
        else:
            print("Chybný vstup.")

    print_ipv4_nodes(ip_dest_nodes)


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
menu_filter = input().lower()
print("Vypísať výstup do konzoly? y/n: ", end='')
menu = input().lower()
print()
file = ""
if menu == 'n':
    print("Zadaj výstupný súbor: ", end='')
    file = "vystup.txt"  # input()
    sys.stdout = file = open(file, "w", encoding="utf-8")
process_data(data, menu_filter)
if menu == 'n':
    file.close()
