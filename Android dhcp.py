from scapy.all import *
from scapy.layers.dhcp import DHCP, BOOTP
from scapy.layers.inet import IP, UDP
from scapy.layers.l2 import Ether

# === CONFIGURATION ===
interface = "wlan0"  # Update with your actual AP interface (e.g., 'ap0')
server_ip = "10.0.0.1"
subnet_mask = "255.255.255.0"
router_ip = server_ip

# === IP POOL: 10.0.0.10 to 10.0.0.254 ===
ip_pool = [f"10.0.0.{i}" for i in range(10, 255)]
leased_ips = {}

# === Server MAC ===
server_mac = get_if_hwaddr(interface)

def get_next_ip(mac):
    if mac in leased_ips:
        return leased_ips[mac]
    if ip_pool:
        ip = ip_pool.pop(0)
        leased_ips[mac] = ip
        return ip
    return None

def handle_dhcp(pkt):
    if DHCP in pkt and pkt[DHCP].options[0][1] == 1:  # DHCP Discover
        mac = pkt[Ether].src
        offered_ip = get_next_ip(mac)
        if not offered_ip:
            print("No available IPs to offer.")
            return

        print(f"[OFFER] {offered_ip} -> {mac}")
        ether = Ether(dst="ff:ff:ff:ff:ff:ff", src=server_mac)
        ip = IP(src=server_ip, dst="255.255.255.255")
        udp = UDP(sport=67, dport=68)
        bootp = BOOTP(op=2, yiaddr=offered_ip, siaddr=server_ip,
                      chaddr=pkt[BOOTP].chaddr, xid=pkt[BOOTP].xid, flags=0x8000)
        dhcp = DHCP(options=[("message-type", "offer"),("server_id", server_ip),("lease_time", 600),("subnet_mask", subnet_mask),("router", router_ip),"end"])
        sendp(ether/ip/udp/bootp/dhcp, iface=interface, verbose=0)

    elif DHCP in pkt and pkt[DHCP].options[0][1] == 3:  # DHCP Request
        mac = pkt[Ether].src
        requested_ip = get_next_ip(mac)
        if not requested_ip:
            print("No available IPs for ACK.")
            return

        print(f"[ACK] {requested_ip} -> {mac}")
        ether = Ether(dst="ff:ff:ff:ff:ff:ff", src=server_mac)
        ip = IP(src=server_ip, dst="255.255.255.255")
        udp = UDP(sport=67, dport=68)
        bootp = BOOTP(op=2, yiaddr=requested_ip, siaddr=server_ip,
                      chaddr=pkt[BOOTP].chaddr, xid=pkt[BOOTP].xid, flags=0x8000)
        dhcp = DHCP(options=[("message-type", "ack"),("server_id", server_ip),("lease_time", 600),("subnet_mask", subnet_mask),("router", router_ip),"end"])
        sendp(ether/ip/udp/bootp/dhcp, iface=interface, verbose=0)

print(f"[*] Starting DHCP server on {interface} using 10.0.0.0/24 pool")
sniff(filter="udp and (port 67 or 68)", iface=interface, prn=handle_dhcp, store=0)
