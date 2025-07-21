from scapy.all import *
from scapy.layers.dhcp import DHCP, BOOTP
from scapy.layers.inet import IP, UDP
from scapy.layers.l2 import Ether

# ===== CONFIGURATION =====
server_ip = "10.0.0.1"           # Must be assigned to your local interface
interface = "Ethernet"           # Change to your Windows network interface name
subnet_mask = "255.255.255.0"
router_ip = server_ip

# ===== IP POOL (Skip first 10 usable IPs) =====
ip_pool = [f"10.0.0.{i}" for i in range(11, 255)]
leased_ips = {}

# ===== Fetch server MAC address from interface =====
server_mac = get_if_hwaddr(interface)

def get_next_ip(mac):
    if mac in leased_ips:
        return leased_ips[mac]
    if not ip_pool:
        return None
    ip = ip_pool.pop(0)
    leased_ips[mac] = ip
    return ip

def handle_dhcp(pkt):
    if DHCP in pkt and pkt[DHCP].options[0][1] == 1:  # DHCP Discover
        mac = pkt[Ether].src
        offered_ip = get_next_ip(mac)
        if not offered_ip:
            print("No IPs available to lease")
            return

        print(f"[OFFER] {offered_ip} -> {mac}")
        ether = Ether(dst="ff:ff:ff:ff:ff:ff", src=server_mac)
        ip = IP(src=server_ip, dst="255.255.255.255")
        udp = UDP(sport=67, dport=68)
        bootp = BOOTP(op=2, yiaddr=offered_ip, siaddr=server_ip,
                      chaddr=pkt[BOOTP].chaddr, xid=pkt[BOOTP].xid, flags=0x8000)
        dhcp = DHCP(options=[("message-type", "offer"),
                             ("server_id", server_ip),
                             ("lease_time", 600),
                             ("subnet_mask", subnet_mask),
                             ("router", router_ip),
                             "end"])
        offer = ether / ip / udp / bootp / dhcp
        sendp(offer, iface=interface, verbose=0)

    elif DHCP in pkt and pkt[DHCP].options[0][1] == 3:  # DHCP Request
        mac = pkt[Ether].src
        requested_ip = get_next_ip(mac)
        leased_ips[mac] = requested_ip

        print(f"[ACK] {requested_ip} -> {mac}")
        ether = Ether(dst="ff:ff:ff:ff:ff:ff", src=server_mac)
        ip = IP(src=server_ip, dst="255.255.255.255")
        udp = UDP(sport=67, dport=68)
        bootp = BOOTP(op=2, yiaddr=requested_ip, siaddr=server_ip,
                      chaddr=pkt[BOOTP].chaddr, xid=pkt[BOOTP].xid, flags=0x8000)
        dhcp = DHCP(options=[("message-type", "ack"),
                             ("server_id", server_ip),
                             ("lease_time", 600),
                             ("subnet_mask", subnet_mask),
                             ("router", router_ip),
                             "end"])
        ack = ether / ip / udp / bootp / dhcp
        sendp(ack, iface=interface, verbose=0)

# ===== Start sniffing =====
print(f"Starting DHCP server on Windows using interface: {interface}")
sniff(filter="udp and (port 67 or 68)", prn=handle_dhcp, store=0, iface=interface)
