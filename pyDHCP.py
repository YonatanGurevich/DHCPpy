import socket
from time import strftime
from binascii import hexlify, unhexlify
from getmac import get_mac_address as gma
from netifaces import interfaces, ifaddresses  # AF_LINK


HOST = ('', 67)  # Any interface, port 67 - DHCP server protocol port
MAGIC_COOKIE = b'63825363'
BROADCAST_MAC = b'f' * 12
FIRST_IP = 11  # Value of the last octet of the first IP address assigned (unless 10 is requested by NETBIOS udhcp)
DEFAULT_TTL = b'40'  # 64 dec
DEFAULT_LEASE_TIME = 3600  # 3600 seconds = 1 hour
DEFAULT_RENEWAL_TIME = 1800  # 30 minutes
DEFAULT_REBINDING_TIME = 3150  # 52:30 minutes
LEASE_TIME_LEN = 8
DNS_SERVERS = ['1.1.1.1', '8.8.8.8']


# DHCP Options
OPTION_SUBNET_MASK = b'01'
OPTION_TIME_OFFSET = b'02'
OPTION_ROUTER = b'03'
OPTION_DNS = b'06'
OPTION_HOST_NAME = b'0c'
OPTION_TTL = b'17'
OPTION_BROADCAST = b'1c'
OPTION_REQUESTED_IP = b'32'
OPTION_LEASE_TIME = b'33'
OPTION_MESSAGE_TYPE = b'35'
OPTION_SERVER_ID = b'36'
OPTION_PARAMETER_LIST = b'37'  # Ignored
OPTION_MAX_SIZE = b'39'  # Ignored
OPTION_RENEWAL = b'3a'
OPTION_REBIND = b'3b'
OPTION_VENDOR_CID = b'3c'  # Ignored
OPTION_CLIENT_ID = b'3d'  # Ignored
OPTION_CFQDN = b'51'
OPTION_END = b'ff'

# Message Types
DHCP_DISCOVER = b'01'
DHCP_OFFER = b'02'
DHCP_REQUEST = b'03'
DHCP_ACK = b'05'
DHCP_NAK = b'06'


class DHCPPayload:  # application layer data
    def __init__(self):
        self.op = b'01'                # Message op code: 1 = BOOTREQUEST, 2 = BOOTREPLY
        self.htype = b'01'             # Hardware address type
        self.hlen = b'06'              # Hardware address length
        self.xid = b''                 # Transaction ID
        self.b_flag = b''              # Broadcast: b'8000', Unicast: b'0000'
        self.ciaddr = b''              # Client IP address
        self.yiaddr = b''              # Your (client) IP address
        self.siaddr = b''              # IP address of next server to use
        self.giaddr = b''              # Gateway IP address
        self.chaddr = b''              # Client hardware address
        self.message_type = b''
        self.requested_ip = b''
        self.abort = False

    def to_bytes(self):
        """
        :return: byte string formatted for DHCP protocol
        """
        payload = b''
        payload += self.op
        payload += self.htype
        payload += self.hlen
        payload += b'00'               # hops
        payload += self.xid
        payload += b'0000'             # seconds
        payload += self.b_flag
        payload += self.ciaddr
        payload += self.yiaddr
        payload += self.siaddr
        payload += self.giaddr
        payload += self.chaddr
        payload += b'0' * 404
        payload += MAGIC_COOKIE
        payload += OPTION_MESSAGE_TYPE
        payload += b'01'               # option length
        payload += self.message_type
        return payload


def log(string):
    """
    :type string: str
    """
    print(strftime('{%Y-%m-%d %H:%M:%S}\t') + string)


def get_my_ip():
    """
    :return: Server IP address (string)
    """
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        # doesn't even have to be reachable
        s.connect(('10.255.255.255', 1))
        ip = s.getsockname()[0]
    except Exception:
        ip = '127.0.0.1'
    finally:
        s.close()
    return ip


def get_my_netmask(ip):
    """
    :param ip: IP address for which you want to know the netmask
    :return:
    """
    for interface in (i for i in interfaces() if i != 'lo'):
        for family in ifaddresses(interface):
            if socket.AF_INET not in ifaddresses(interface):
                continue
            if family == socket.AF_INET:
                if ifaddresses(interface)[family][0]['addr'] == ip:
                    return ifaddresses(interface)[family][0]['netmask']


def get_my_interface():
    """
    :return: Your public network interface
    """
    for interface in (i for i in interfaces() if i != 'lo'):
        for family in ifaddresses(interface):
            if socket.AF_INET not in ifaddresses(interface):
                continue
            if family == socket.AF_INET:
                if ifaddresses(interface)[family][0]['addr'] == '127.0.0.1':
                    continue
                inter = interface
                return inter


def to_hex_ip(ip):
    """
    :param ip: IP address (string)
    :return: hex representation of IP address (bytes)
    """
    return hexlify(socket.inet_aton(ip))


def from_hex_ip(ip):
    """
    Converts an IP address, which is in 32-bit packed format to the popular human readable dotted-quad string format.
    :param ip: hexadecimal IP address
    :return: IP address in string format
    """
    return socket.inet_ntoa(unhexlify(ip))


def from_bytes_mac(mac):
    """
    Converts bytes-like MAC address to regular string format
    :type mac: bytes
    """
    return ':'.join(str(mac)[2:-1][i:i+2] for i in range(0, 12, 2))


def parse_packet(data):
    """
    Parce received DHCP packet to packet class format
    :param data: Data received (application layer)
    :return: DHCPPayload object
    """
    data = hexlify(data)
    if data[:6] != b'010106':
        log("Received a bad DHCP packet")
        '''
        op code 01 (bootrequest) since its either discover or request packet
        htype 01: ethernet
        hlen 06: (hardware length (MAC address) 6 bytes long
        '''
        return None
    packet = DHCPPayload()
    packet.op = data[0:2]
    packet.htype = data[2:4]
    packet.hlen = data[4:6]
    packet.xid = data[8:16]
    packet.b_flag = data[20:24]
    packet.ciaddr = data[24:32]
    packet.yiaddr = data[32:40]
    packet.siaddr = data[40:48]
    packet.giaddr = data[48:56]
    packet.chaddr = data[56:68]
    packet_options = data[480:]
    while True:
        option = packet_options[:2]
        if option == OPTION_END:
            break

        option_length = int(packet_options[2:4], 16)
        option_data = packet_options[4:4+option_length*2]

        if option == OPTION_MESSAGE_TYPE:
            packet.message_type = option_data
        elif option == OPTION_REQUESTED_IP:
            packet.requested_ip = option_data
        elif option == OPTION_SERVER_ID:  # In Request packets only
            if option_data != to_hex_ip(my_ip):
                log("Packet is directed to another DHCP server")
                packet.abort = True
                break

        packet_options = packet_options[4 + option_length * 2:]

    return packet


def arp(ip) -> bytes:
    """
    Sends an ARP for the requested IP and returns the answer if there was any.
    (False negative is common for Android clients)
    :type ip: str
    """
    global my_mac, my_ip
    bytes_mac = my_mac.replace(':', '').encode()
    bytes_ip = to_hex_ip(my_ip)
    bytes_target_ip = to_hex_ip(ip)

    with socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(3)) as rs:  # AF_LINK, , htons(3) , IPPROTO_RAW
        rs.settimeout(10.1)
        rs.bind((my_interface, 0))
        arp_packet = BROADCAST_MAC
        arp_packet += bytes_mac
        arp_packet += b'0806'  # ARP packet type
        arp_packet += b'0001080006040001'  # HW type, Protocol type, HW size, Protocol size, OpCode (request)
        arp_packet += bytes_mac
        arp_packet += bytes_ip
        arp_packet += b'0' * 12
        arp_packet += bytes_target_ip
        rs.sendall(unhexlify(arp_packet))
        try:
            a_data, a_address = rs.recvfrom(60)
        except TimeoutError:
            return b''
        a_data = hexlify(a_data)
        if (
            len(a_data) >= 84 and                   # Minimal ARP packet length
            a_data[24:28] == b'0806' and            # ARP packet type
            a_data[40:44] == b'0002' and            # OpCode (reply)
            a_data[44:56] != b'0' * 12 and          # Sender MAC
            a_data[56:64] == bytes_target_ip and    # Sender IP
            a_data[64:76] == bytes_mac and          # Target MAC (me)
            a_data[76:84] == bytes_ip               # Target IP (me)
        ):
            log("ARP reply: IP {} is at {}".format(ip, from_bytes_mac(a_data[44:56])))
            return a_data[44:56]
        return b''


def network_prefix():
    """
    Combines the server's IP with the netmask to generate the 0 IP of the network
    """
    prefix = my_ip.split('.')
    temp_nm = my_netmask.split('.')
    for i in range(len(prefix)):
        if temp_nm[i] == '0':
            prefix[i] = '0'
    return prefix


def assign_ip():
    """
    Assign free IP address to reply_packet.yiaddr
    """
    global next_ip
    prefix = network_prefix()
    if received_packet.ciaddr == next_ip == '0.0.0.0':
        next_ip = '.'.join([*prefix[:-1], str(FIRST_IP)])
    octet = 40
    for i in range(int(next_ip.split('.')[-1]), 254):
        check_ip = '.'.join([*prefix[:-1], str(octet)])
        if arp(check_ip) == b'':
            next_ip = check_ip
            octet = i
            break

    reply_packet.yiaddr = next_ip
    next_ip = '.'.join([*prefix[:-1], str(octet + 1)])


def option_len_hex(option_data):
    """
    :param option_data: DHCP option data
    :return: len value for the option
    """
    return format(int(len(option_data) / 2), '0{}x'.format(2)).encode()


def hex_dns(dns_servers):
    """
    :param dns_servers: list of servers IP addresses in string format
    :return: dns servers addresses in hex format
    """
    total_data = b''
    for srv in dns_servers:
        total_data += to_hex_ip(srv)
    return total_data


def add_options(payload):
    """
    :param payload: DHCP data converted to bytes
    :return: DHCP packet with necessary options attached
    """
    payload += OPTION_SUBNET_MASK + option_len_hex(to_hex_ip(my_netmask)) + to_hex_ip(my_netmask)
    payload += OPTION_ROUTER + option_len_hex(to_hex_ip(my_router)) + to_hex_ip(my_router)
    payload += OPTION_TTL + option_len_hex(DEFAULT_TTL) + DEFAULT_TTL
    payload += OPTION_LEASE_TIME + option_len_hex(hex_lease) + hex_lease
    payload += OPTION_SERVER_ID + option_len_hex(to_hex_ip(my_ip)) + to_hex_ip(my_ip)
    payload += OPTION_DNS + option_len_hex(hex_dns(DNS_SERVERS)) + hex_dns(DNS_SERVERS)
    payload += OPTION_RENEWAL + option_len_hex(hex_renewal) + hex_renewal
    payload += OPTION_REBIND + option_len_hex(hex_rebind) + hex_rebind
    payload += OPTION_END
    return payload


def add_udp(payload):
    """
    Adds UDP layer to DHCP packet
    :param payload: DHCP packet
    :return: DHCP packet with UDP header
    """
    udp_header = format(HOST[1], '04x').encode()                     # Source port
    udp_header += format(68, '04x').encode()                         # Destination port
    udp_header += format(int(len(payload) / 2) + 8, '04x').encode()  # Total length of UDP segment
    udp_header += b'0000'                                            # Checksum (Disabled)
    return udp_header + payload


def add_ip(payload, destination_ip):
    """
    Add IP layer to DHCP packet
    :param payload: DHCP packet with UDP header
    :param destination_ip: destination IP in string format
    :return: DHCP packet with UDP and IP headers
    """
    ip_header = b'4500'                                     # IP version (4), Header length (5 nibbles), DSCP(0), ECN(0)
    ip_header += format(int(len(payload) / 2) + 20, '04x').encode()  # Total IP packet length
    ip_header += b'00004000'                                # ID (disabled), Flags (don't fragment)
    ip_header += b'80'                                      # TTL = 128
    ip_header += b'11'                                      # Protocol = UDP
    ip_header += b'0000'                                    # Checksum Disabled
    ip_header += to_hex_ip(my_ip)                           # Source IP
    ip_header += to_hex_ip(destination_ip)
    return ip_header + payload


def add_ethernet(payload, destination_mac):
    """
    Add "data link" (Ethernet) layer to packet
    :param payload: DHCP packet with UDP and IP headers
    :param destination_mac: Destination MAC address in bytes format
    :return: Ethernet frame with IP and UDP headers and DHCP packet
    """
    eth_header = destination_mac
    eth_header += my_mac.replace(':', '').encode()
    eth_header += b'0800'  # IPv4
    return eth_header + payload


with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as rx_socket:  # rx_socket - Receiving socket, IPv4 UDP
    try:
        rx_socket.bind(HOST)
    except PermissionError as e:
        log("Permission denied")
        print(e)
        quit()
    except OSError as err:
        log("Port already in use")
        print(err)
        quit()

    my_ip = get_my_ip()
    my_netmask = get_my_netmask(my_ip)
    my_mac = gma()
    my_interface = get_my_interface()
    my_router = '.'.join([*network_prefix()[:-1], '1'])  # My network prefix with computer address 1
    if arp(my_router) == b'':
        my_router = ''

    next_ip = '0.0.0.0'
    hex_lease = format(DEFAULT_LEASE_TIME, '0{}x'.format(LEASE_TIME_LEN)).encode()       # Lease time in hex format
    hex_renewal = format(DEFAULT_RENEWAL_TIME, '0{}x'.format(LEASE_TIME_LEN)).encode()   # Lease renewal time
                                                                                         # in hex format
    hex_rebind = format(DEFAULT_REBINDING_TIME, '0{}x'.format(LEASE_TIME_LEN)).encode()  # Rebinding time in hex format

    while True:
        log("Listening on {}:{}".format(*HOST))
        try:
            data, address = rx_socket.recvfrom(1500)
        except KeyboardInterrupt:
            print(" Quitting")
            quit(0)
        if address[1] == 68:  # DHCP client discover/request messages come from port 68
            received_packet = parse_packet(data)
            if not received_packet:
                continue
            if received_packet.abort:  # True if packet is directed to other DHCP server
                continue
            log("Packet Received")

            # Reply
            reply_packet = DHCPPayload()
            reply_packet.op = b'02'
            reply_packet.htype = b'01'
            reply_packet.hlen = b'06'
            reply_packet.xid = received_packet.xid
            reply_packet.b_flag = received_packet.b_flag
            reply_packet.ciaddr = received_packet.ciaddr
            assign_ip()
            log("Reserved IP {}".format(reply_packet.yiaddr))
            reply_packet.yiaddr = to_hex_ip(reply_packet.yiaddr)

            reply_packet.siaddr = to_hex_ip(my_ip)
            reply_packet.giaddr = to_hex_ip('0.0.0.0')
            reply_packet.chaddr = received_packet.chaddr

            if received_packet.message_type == DHCP_DISCOVER:
                reply_packet.message_type = DHCP_OFFER
                payload = reply_packet.to_bytes()
                dhcp_payload = add_options(payload)

            elif received_packet.message_type == DHCP_REQUEST:
                if arp(from_hex_ip(received_packet.requested_ip)) != b'':
                    reply_packet.message_type = DHCP_NAK
                    payload = reply_packet.to_bytes()
                    dhcp_payload = add_options(payload)

                else:
                    reply_packet.message_type = DHCP_ACK
                    payload = reply_packet.to_bytes()
                    dhcp_payload = add_options(payload)

            # Encapsulation

            udp_segment = add_udp(dhcp_payload)
            if received_packet.b_flag == b'0000':  # If broadcast flag is 0000 (false) we have client address
                destination = [received_packet.ciaddr.decode(), received_packet.chaddr]
            else:
                destination = ['255.255.255.255', b'f' * 12]  # If broadcast flag was true we send a broadcast message
            ip_packet = add_ip(udp_segment, (destination[0]))
            ethernet_frame = add_ethernet(ip_packet, destination[1])

            with socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(3)) as tx_socket:
                '''
                tx_socket = Transmit socket
                Since I encountered permission challenges transmitting UDP broadcast messages from the "rx_socket"
                I bypassed those by using this raw socket
                '''
                tx_socket.bind((my_interface, 0))
                log("Sending Reply...")
                tx_socket.send(unhexlify(ethernet_frame))
