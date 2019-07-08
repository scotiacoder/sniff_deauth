from scapy.all import sniff




def pkt_handler(packet):
    print(packet.summary())
    try:
        print(packet.addr1, packet.addr2, packet.addr3)
    except:
        pass

    return True

def main():
    sniff(iface='wlan1mon', filter='wlan type data or wlan type mgt and (subtype deauth or subtype disassoc)', prn=pkt_handler)
    return True
main()


