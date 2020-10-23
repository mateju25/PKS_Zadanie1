from binascii import hexlify
from scapy.all import *
import sys


# objekt pre jeden ipv4 stream komunikacie
class IPv4Stream:
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


# objekt pre jeden ARP stream komunikacie
class ARPStream:
    close = False
    ip_dest = []
    ip_src = []
    mac_src = []
    frames = []

    def __init__(self, p_ip_src, p_ip_dest, p_mac_src, p_frame_id, p_close=False):
        self.ip_src = p_ip_src
        self.ip_dest = p_ip_dest
        self.mac_src = p_mac_src
        self.frames = []
        self.close = p_close
        self.frames.append(p_frame_id + 1)


# extrahuje data zo suboru pcap
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


# vypise hocijake data typu bytes v danom formate
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
def print_frame(p_frame_data):
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


# vypise ipv4 uzly a najvacsi z nich (bod 3)
def print_ipv4_nodes(p_nodes):
    if len(p_nodes) != 0:
        print("Zoznam IP adries všetkých prijímajúcich uzlov:")
        for ip in p_nodes:
            print_data(ip, '.', True)
            print()

        print()
        print("Adresa uzla s najväčším počtom prijatých paketov: ")
        # vytiahne adresu
        print_data(max(p_nodes, key=lambda k: p_nodes[k]), ".", True)
        # vytiahne mnozstvo
        print("        ", p_nodes.get(max(p_nodes, key=lambda k: p_nodes[k])), "paketov")


# vytiahne transportny protokol z frame-u
def get_transport_protocol(p_frame):
    head_len = (get_data_from_frame(p_frame, 14, 14, True) - int(
        get_data_from_frame(p_frame, 14, 14, True) / 16) * 16) * 4
    return p_frame[14 + head_len:len(p_frame)]


# vypise typ ramca
def print_frame_type(p_ethertype_value, p_ieeetype_value):
    print("Typ rámca: ", end='')
    if p_ethertype_value >= 1500:
        print("Ethernet II")
    elif p_ieeetype_value == 0xAAAA:
        print("IEEE 802.3 LLC + SNAP")
    elif p_ieeetype_value == 0xFFFF:
        print("IEEE 802.3 raw")
    else:
        print("IEEE 802.3 LLC")


# vypise zdrojovu a cielovu ip adresu
def print_ipv4_adr(src, dst):
    print("Zdrojová IP adresa: ", end='')
    print_data(src, '.', True)
    print()
    print("Cieľová IP adresa: ", end='')
    print_data(dst, '.', True)
    print()


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

        # vypise ethertype
        if p_ethertype_value in ether_types:
            print(ether_types.get(p_ethertype_value))
        else:
            print("Neznámy Ethertype")

        # ARP
        if p_ethertype_value == 2054:
            print_ipv4_adr(get_data_from_frame(p_frame, 28, 31), get_data_from_frame(p_frame, 38, 41))
            if get_data_from_frame(p_frame, 20, 21, True) == 2:
                print("ARP Reply")
            else:
                print("ARP Request")

        # IPv4
        if p_ethertype_value == 2048:
            print_ipv4_adr(get_data_from_frame(p_frame, 26, 29), get_data_from_frame(p_frame, 30, 33))

            if ip_header_num in ip_header_protocol:
                print(ip_header_protocol.get(ip_header_num))

                # nacita udp alebo tcp porty
                if get_data_from_frame(p_frame, 23, 23, True) == 17:
                    load_from_file("udp_ports.txt", ports)
                elif get_data_from_frame(p_frame, 23, 23, True) == 6:
                    load_from_file("tcp_ports.txt", ports)

                # ICMP
                if ip_header_num == 1:
                    icmp_types = {}
                    load_from_file("icmp_types.txt", icmp_types)
                    print("Správa: ", end='')
                    if get_data_from_frame(get_transport_protocol(p_frame), 0, 0, True) in icmp_types:
                        print(icmp_types.get(get_data_from_frame(get_transport_protocol(p_frame), 0, 0, True)))
                    return

                # vypise nazov portu
                if p_force_udp == '':
                    if get_data_from_frame(get_transport_protocol(p_frame), 0, 1, True) in ports:
                        print(ports.get(get_data_from_frame(get_transport_protocol(p_frame), 0, 1, True)))
                    else:
                        if get_data_from_frame(get_transport_protocol(p_frame), 2, 3, True) in ports:
                            print(ports.get(get_data_from_frame(get_transport_protocol(p_frame), 2, 3, True)))
                        else:
                            print("Neznámy port.")
                else:
                    print(p_force_udp)

                # vypise cisla portov
                if len(ports) != 0:
                    print("Zdrojový port: ", end='')
                    print(get_data_from_frame(get_transport_protocol(p_frame), 0, 1, True))
                    print("Cieľový port: ", end='')
                    print(get_data_from_frame(get_transport_protocol(p_frame), 2, 3, True))
            else:
                print("Neznamy")

    # IEEE + SNAP
    elif p_ieeetype_value == 43690:
        if get_data_from_frame(p_frame, 20, 21, True) == 267:
            print("PVSTP+")
        elif p_ethertype_value in ether_types:
            print(ether_types.get(p_ethertype_value))
        else:
            print("Neznámy Ethertype v SNAP-e")
    # IEEE + raw
    elif p_ieeetype_value == 65535:
        print("IPX")
    # IEEE
    elif get_data_from_frame(p_frame, 14, 14, True) in llc_types:
        print(llc_types.get(get_data_from_frame(p_frame, 14, 14, True)))


# vypise dlzku ramca (bod 1)
def print_len_of_frame(p_frame):
    print("Dĺžka rámca poskytnutá pcap API –", len(p_frame), "B")
    if len(p_frame) + 4 > 64:
        print("Dĺžka rámca prenášaného po médiu –", len(p_frame) + 4, "B")
    else:
        print("Dĺžka rámca prenášaného po médiu – 64 B")


# vypise mac adresy (bod 1)
def print_mac_adr(p_frame):
    print("Zdrojová MAC adresa: ", end='')
    print_data(get_data_from_frame(p_frame, 6, 11))
    print()
    print("Cieľová  MAC adresa: ", end='')
    print_data(get_data_from_frame(p_frame, 0, 5))
    print()


# vypis vlastnosi ramca na obrazovku
def out_to_terminal(p_frame, p_num, p_force_udp='', ports=False):
    ether_type = get_data_from_frame(p_frame, 12, 13, True)
    ieee_type = get_data_from_frame(p_frame, 14, 15, True)

    print("Rámec č.", p_num)
    print_len_of_frame(p_frame)
    print_frame_type(ether_type, ieee_type)
    print_mac_adr(p_frame)
    choose_and_print_inside_protocol(p_frame, ether_type, ieee_type, p_force_udp)
    print_frame(p_frame)


# prida ip prichadzajuce uzly do dictionary (bod 3)
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


# zisti ci sa dana kombinacia ip_dst, ip_src, port_dst, port_src nachadza uz v nejakom streame
def is_ip_dest_in_stream(p_streams, p_ip_dest, p_ip_src, p_prt_src=0, p_prt_dest=0):
    for x in range(0, len(p_streams)):
        if ((p_streams[x].ip_src == p_ip_dest) and (p_streams[x].ip_dest == p_ip_src) and (
                p_streams[x].port_dest == p_prt_src) and (p_streams[x].port_src == p_prt_dest)) \
                or ((p_streams[x].ip_src == p_ip_src) and (p_streams[x].ip_dest == p_ip_dest) and (
                p_streams[x].port_dest == p_prt_dest) and (p_streams[x].port_src == p_prt_src)):
            return x
    return -1


# vlozi stream komunikacie do pola
def insert_to_streams(p_arr_of_streams, p_frame_id, p_ip_src, p_ip_dest, p_port_src=0, p_port_dest=0):
    act_str = is_ip_dest_in_stream(p_arr_of_streams, p_ip_src, p_ip_dest, p_port_src, p_port_dest)
    if act_str >= 0:
        # ak existuje vlozi cislo ramca k ostatnym
        p_arr_of_streams[act_str].frames.append(p_frame_id + 1)
    elif act_str == -1:
        # vytvori novy stream
        p_arr_of_streams.append(IPv4Stream(p_ip_src, p_ip_dest, p_port_src, p_port_dest, p_frame_id))


# zisti ci sa dana kombinacia ip_dst, ip_src, mac_adrr nachadza uz v nejakom arp streame
def is_arp_in_stream(p_streams, p_ip_dest, p_ip_src, p_mac_src):
    for x in range(0, len(p_streams)):
        # je stream uzavrety? (nachadza sa v nom reply?)
        if p_streams[x].close:
            continue
        if ((p_streams[x].ip_src == p_ip_dest) and (p_streams[x].ip_dest == p_ip_src) and (p_streams[x].mac_src == p_mac_src)) \
                or ((p_streams[x].ip_src == p_ip_src) and (p_streams[x].ip_dest == p_ip_dest) and (p_streams[x].mac_src == p_mac_src)):
            return x
    return -1


# vlozi arp stream komunikacie do pola
def insert_to_arpstreams(p_arr_of_streams, p_frame_id, p_ip_src, p_ip_dest, p_mac_src, arp_reply=1):
    act_str = is_arp_in_stream(p_arr_of_streams, p_ip_src, p_ip_dest, p_mac_src)
    if act_str >= 0:
        # ak existuje vlozi cislo ramca k ostatnym
        p_arr_of_streams[act_str].frames.append(p_frame_id + 1)
        if arp_reply == 2:
            p_arr_of_streams[act_str].close = True
    elif act_str == -1:
        # vytvori novy stream
        if arp_reply == 2:
            p_arr_of_streams.append(ARPStream(p_ip_src, p_ip_dest, p_mac_src, p_frame_id, True))
        else:
            p_arr_of_streams.append(ARPStream(p_ip_src, p_ip_dest, p_mac_src, p_frame_id))


# vypise komunikaciu (prvych 10 a poslednych 10 framov)
def print_communication(p_data, frames, force_udp='', flags=True):
    one = True
    for y in range(0, len(frames)):
        if (y < 10) or (y >= len(frames) - 10):
            if flags:
                print("Flagy: ", end='')
                flags = bin(get_data_from_frame(get_transport_protocol(bytes(p_data[frames[y] - 1])), 13, 13, True))
                flags = list(flags[2:len(flags)])
                while len(flags) < 8:
                    flags.insert(0, '0')
                if flags[7] == '1':
                    print("[FIN]", end='')
                if flags[6] == '1':
                    print("[SYN]", end='')
                if flags[5] == '1':
                    print("[RST]", end='')
                if flags[4] == '1':
                    print("[PSH]", end='')
                if flags[3] == '1':
                    print("[ACK]", end='')
                print()
            out_to_terminal(bytes(p_data[frames[y] - 1]), frames[y], force_udp)
        else:
            if one:
                print("...")
                print()
                one = False


# spracuje data na zaklade volby uzivatela
def process_data(p_data, p_menu):
    ip_dest_nodes = {}

    # vypise vsetky ramce komunikacie
    if p_menu == 'all':
        for frame_id in range(0, len(p_data)):
            frame = bytes(p_data[frame_id])
            out_to_terminal(frame, frame_id + 1)

            if get_data_from_frame(frame, 12, 13, True) == 2048:
                insert_ipv4_to_dict(frame, ip_dest_nodes)

    # miesto kde sa spracuje TCP protokol
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
            # vytvorim streamy
            if get_data_from_frame(frame, 12, 13, True) == 2048:
                if get_data_from_frame(frame, 23, 23, True) == 6:
                    tcp = get_transport_protocol(frame)

                    # filtre ramcov (chcem len tie, ktore chce uzivatel)
                    if get_data_from_frame(tcp, 0, 1, True) in tcp_ports:
                        if tcp_ports.get(get_data_from_frame(tcp, 0, 1, True)) != p_menu:
                            continue
                    else:
                        if get_data_from_frame(tcp, 2, 3, True) in tcp_ports:
                            if tcp_ports.get(get_data_from_frame(tcp, 2, 3, True)) != p_menu:
                                continue
                        else:
                            continue

                    insert_to_streams(tcp_streams, frame_id, get_data_from_frame(frame, 26, 29),
                                      get_data_from_frame(frame, 30, 33), get_data_from_frame(tcp, 0, 1),
                                      get_data_from_frame(tcp, 2, 3))

        good = 0
        semi_good = 0
        # zisti ci je komunikacia dobre zacata dobre skoncena
        for x in tcp_streams:
            begin = 0
            end = 0
            # SYN, SYN ACK, ACK - zaciatok
            if (get_data_from_frame(get_transport_protocol(bytes(p_data[x.frames[0] - 1])), 13, 13, True) == 0x2) and (
                    get_data_from_frame(get_transport_protocol(bytes(p_data[x.frames[1] - 1])), 13, 13,
                                        True) == 0x12) and (
                    get_data_from_frame(get_transport_protocol(bytes(p_data[x.frames[2] - 1])), 13, 13, True) == 0x10):
                begin = 1

            to_end0 = get_data_from_frame(get_transport_protocol(bytes(p_data[x.frames[len(x.frames) - 1] - 1])), 13,
                                          13, True)
            to_end1 = get_data_from_frame(get_transport_protocol(bytes(p_data[x.frames[len(x.frames) - 2] - 1])), 13,
                                          13, True)
            if len(x.frames) - 3 < 0:
                to_end2 = -1
            else:
                to_end2 = get_data_from_frame(get_transport_protocol(bytes(p_data[x.frames[len(x.frames) - 3] - 1])), 13,
                                          13, True)
            if len(x.frames) - 4 < 0:
                to_end3 = -1
            else:
                to_end3 = get_data_from_frame(get_transport_protocol(bytes(p_data[x.frames[len(x.frames) - 4] - 1])), 13,
                                          13, True)

            # rst
            if (to_end0 == 0x14) or (to_end0 == 0x4):
                end = 1
            else:
                # 3 way fin
                if (to_end0 == 0x10) and ((to_end1 == 0x11) or (to_end1 == 0x19)) \
                        and ((to_end2 == 0x11) or (to_end2 == 0x19)):
                    end = 1
                else:
                    # 4 way fin
                    if (to_end0 == 0x10) and ((to_end1 == 0x11) or (to_end1 == 0x19)) \
                            and (to_end2 == 0x10) and ((to_end3 == 0x11) or (to_end3 == 0x19)):
                        end = 1

            if good == 0:
                if begin and end:
                    print("----------------------------------------------------------------------------------")
                    print("Komunikácia začatá aj ukončená správne")
                    print_communication(data, x.frames)
                    good = 1

            if semi_good == 0:
                if begin and not end:
                    print("----------------------------------------------------------------------------------")
                    print("Komunikácia začatá správne ale neukončená správne")
                    print_communication(data, x.frames)
                    semi_good = 1

        if good == 0:
            print("Komunikácia začatá aj ukončená správne v tejto vzorke neexistuje.")
        if semi_good == 0:
            print("Komunikácia začatá správne ale neukončená správne v tejto vzorke neexistuje.")

    # tu sa spracuje UDP (ak bude treba doimplementaciu, bude treba doplnit filtre ako pri TCP, riadok 373)
    elif p_menu == 'tf':
        udp_streams = []
        # vytvorim streamy
        for frame_id in range(0, len(p_data)):
            frame = bytes(p_data[frame_id])
            if get_data_from_frame(frame, 12, 13, True) == 2048:
                if get_data_from_frame(frame, 23, 23, True) == 17:
                    udp = get_transport_protocol(frame)
                    insert_to_streams(udp_streams, frame_id, get_data_from_frame(frame, 26, 29),
                                      get_data_from_frame(frame, 30, 33), get_data_from_frame(udp, 0, 1),
                                      get_data_from_frame(udp, 2, 3))

        x = 0
        # spracovavam TFTP komunikaciu - spajam streamy, ktore patria k sebe
        while x < len(udp_streams):
            if (len(udp_streams[x].frames) == 1) and ((get_data_from_frame(udp_streams[x].port_dest, 0, 1, True) == 69)
                                                      or (get_data_from_frame(udp_streams[x].port_src, 0, 1, True) == 69)):
                if (get_data_from_frame(udp_streams[x].port_dest, 0, 1, True) == get_data_from_frame(udp_streams[x+1].port_src, 0, 1, True)) or  (
                        get_data_from_frame(udp_streams[x].port_src, 0, 1, True) == get_data_from_frame(udp_streams[x+1].port_dest, 0, 1, True)):
                    udp_streams[x + 1].frames.insert(0, udp_streams[x].frames[0])
                    udp_streams.pop(x)
                    x += 1
                else:
                    udp_streams.pop(x+1)
            else:
                udp_streams.pop(x)
        #vypisem komunikacie
        com_count = 1
        if len(udp_streams) == 0:
            print("Žiadna komunikácia sa nenašla.")
        for x in udp_streams:
            print("----------------------------------------------------------------------------------")
            print("Komunikácia č.", com_count)
            com_count += 1
            print_communication(p_data, x.frames, "TFTP", False)

    # nlok pre spracovanie ICMP protokolu
    elif p_menu == 'i':
        icmp_streams = []
        # vytvorim streamy
        for frame_id in range(0, len(p_data)):
            frame = bytes(p_data[frame_id])
            if get_data_from_frame(frame, 12, 13, True) == 2048:
                if get_data_from_frame(frame, 23, 23, True) == 1:
                    out_to_terminal(frame, frame_id + 1)
    # blok pre spracovanie RIP protokolu
    elif p_menu == 'r':
        sum = 0
        p_menu = "RIP"
        udp_ports = {}
        load_from_file("udp_ports.txt", udp_ports)
        for frame_id in range(0, len(p_data)):
            frame = bytes(p_data[frame_id])
            #ipv4
            if get_data_from_frame(frame, 12, 13, True) == 2048:
                #UDP
                if get_data_from_frame(frame, 23, 23, True) == 17:

                    #RIP - nacitavam a pozeram z file ci je RIP
                    transport = get_transport_protocol(frame)
                    if get_data_from_frame(transport, 0, 1, True) in udp_ports:
                        if udp_ports.get(get_data_from_frame(transport, 0, 1, True)) != p_menu:
                            continue
                    else:
                        if get_data_from_frame(transport, 2, 3, True) in udp_ports:
                            if udp_ports.get(get_data_from_frame(transport, 2, 3, True)) != p_menu:
                                continue
                        else:
                            continue

                    out_to_terminal(frame, frame_id + 1)
                    sum += 1
        print("Počet RIP rámcov: ", sum)

    # blok pre ARP komunikaciu
    elif p_menu == 'a':
        arp_streams = []
        # vytvorim streamy
        for frame_id in range(0, len(p_data)):
            frame = bytes(p_data[frame_id])
            if get_data_from_frame(frame, 12, 13, True) == 2054:
                if get_data_from_frame(frame, 20, 21, True) == 1:
                    insert_to_arpstreams(arp_streams, frame_id, get_data_from_frame(frame, 28, 31),
                                  get_data_from_frame(frame, 38, 41), get_data_from_frame(frame, 22, 27), 1)
                else:
                    insert_to_arpstreams(arp_streams, frame_id, get_data_from_frame(frame, 28, 31),
                                         get_data_from_frame(frame, 38, 41), get_data_from_frame(frame, 32, 37), 2)
        com_count = 1
        if len(arp_streams) > 0:
            temp = False
            # vypisujem len dvojice
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

            # vypisem zbytok arp komunikacie bez parov
            if temp:
                print("----------------------------------------------------------------------------------")
                print("Zbytok ARP rámcov")
                for x in arp_streams:
                    if x.close is False or (len(x.frames) == 1):
                        for y in x.frames:
                            if get_data_from_frame(bytes(p_data[y - 1]), 20, 21, True) == 2:
                                print_arp_header(bytes(p_data[y - 1]), False)
                            else:
                                print_arp_header(bytes(p_data[y - 1]))
                            out_to_terminal(bytes(p_data[y - 1]), y)
    # vypise konkretny ramec
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
print("     r - pre výpis RIP rámcov")
print("Zadaj možnosť: ", end='')
menu_filter = input().lower()
print()
print("Vypísať výstup do konzoly? y/n: ", end='')
menu = input().lower()
file = ""
if menu == 'n':
    print("Zadaj výstupný súbor: ", end='')
    file = input()
    sys.stdout = file = open(file, "w", encoding="utf-8")
process_data(data, menu_filter)
if menu == 'n':
    file.close()
