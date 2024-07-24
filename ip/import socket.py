import socket
import struct
import random

DHCP_SERVER_IP = '192.168.1.3'
DHCP_SERVER_PORT = 67  # Using different port for testing
DHCP_CLIENT_PORT = 68  # Using different port for testing

# DHCP Message Types
DHCP_DISCOVER = 1
DHCP_REQUEST = 3
DHCP_OFFER = 2

def build_discover_packet(transaction_id, mac):
    packet = struct.pack('!BBBBIHHI16s16s64s128s',
                         1, 1, 6, 0, transaction_id, 0, 0, 0, b'', b'', b'', b'')
    packet += b'\x00' * 192  # bootp legacy
    packet += struct.pack('!I', 0x63825363)  # Magic cookie
    packet += struct.pack('!BBB', 53, 1, DHCP_DISCOVER)  # Option 53 (DHCP Message Type)
    packet += struct.pack('!BB6s', 61, 6, mac)  # Option 61 (Client Identifier)
    packet += struct.pack('!B', 255)  # End Option
    return packet

def send_discover(sock, mac):
    transaction_id = random.randint(0, 0xFFFFFFFF)
    packet = build_discover_packet(transaction_id, mac)
    print(f'Sending DHCP Discover with transaction ID: {transaction_id}')
    sock.sendto(packet, ('<broadcast>', DHCP_SERVER_PORT))
    return transaction_id

def listen_for_offer(sock):
    while True:
        print('Listening for DHCP Offer...')
        data, addr = sock.recvfrom(1024)
        print(f'Received data from {addr}')
        if data[242] == DHCP_OFFER:  # DHCP Offer
            offered_ip = socket.inet_ntoa(data[16:20])
            print(f'Received DHCP OFFER: {offered_ip}')
            return data, addr

def build_request_packet(transaction_id, mac, offered_ip):
    packet = struct.pack('!BBBBIHHI16s16s64s128s',
                         1, 1, 6, 0, transaction_id, 0, 0, 0, b'', b'', b'', b'')
    packet += b'\x00' * 192  # bootp legacy
    packet += struct.pack('!I', 0x63825363)  # Magic cookie
    packet += struct.pack('!BBB', 53, 1, DHCP_REQUEST)  # Option 53 (DHCP Message Type)
    packet += struct.pack('!BB4s', 50, 4, socket.inet_aton(offered_ip))  # Option 50 (Requested IP Address)
    packet += struct.pack('!BB4s', 54, 4, socket.inet_aton(DHCP_SERVER_IP))  # Option 54 (Server Identifier)
    packet += struct.pack('!B', 255)  # End Option
    return packet

def send_request(sock, transaction_id, mac, offered_ip):
    packet = build_request_packet(transaction_id, mac, offered_ip)
    print(f'Sending DHCP Request for IP: {offered_ip}')
    sock.sendto(packet, ('<broadcast>', DHCP_SERVER_PORT))

def main():
    mac = b'\xaa\xbb\xcc\xdd\xee\xff'  # Replace with the client's MAC address
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
    sock.bind(('', DHCP_CLIENT_PORT))  # Bind to client port

    try:
        transaction_id = send_discover(sock, mac)
        print(f'DHCP Discover sent with transaction ID: {transaction_id}')
        data, addr = listen_for_offer(sock)
        offered_ip = socket.inet_ntoa(data[16:20])
        print(f'DHCP Offer received with IP: {offered_ip}')
        send_request(sock, transaction_id, mac, offered_ip)
        print('DHCP Request sent')
    except Exception as e:
        print(f'Error: {e}')
    finally:
        sock.close()

if _name_ == '_main_':
    main()