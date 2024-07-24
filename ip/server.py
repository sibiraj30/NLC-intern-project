import sys
import threading

import select

from GUI_server import GUIServer
from Packet import *


class Server:

    def __init__(self, gui: GUIServer, lease_time: int, name, ip_address, mask_size: int, source_port=67, destination_port=68,
                 destination_ip='127.0.0.1'):

        self.gui = gui
        self.lease_time = lease_time
        self.server_name = name
        self.ip_address = ip_address
        self.mask = (((1 << mask_size) - 1) << (32 - mask_size)).to_bytes(4, 'big')
        self.destination_port = destination_port
        self.destination_ip = destination_ip
        self.source_port = source_port

        # variabila pentru a stoca ce parametri a cerut un client
        self.request_lists = {}

        # Creare socket UDP
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
        # Activare optiune transmitere pachete de difuzie
        self.socket.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
        # Activare optiune refolosire port
        self.socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.socket.bind(('', self.source_port))

        self.socket.setblocking(False)

        self.address_pool = ['12.30.0.1', '12.30.0.2', '12.30.0.3']
        self.client_address_mapping = {}

        self.running = True

        try:
            self.receive_thread = threading.Thread(target=self.receive_fct)
            self.receive_thread.start()
        except:
            print("Eroare la pornirea thread‐ului")
            sys.exit()

    def receive_fct(self):
        contor = 0
        while self.running:
            # Apelam la functia sistem IO -select- pentru a verifca daca socket-ul are date in bufferul de receptie
            # Stabilim un timeout de 1 secunda
            r, _, _ = select.select([self.socket], [], [], 1)
            if not r:
                contor = contor + 1
            else:
                self.gui.write_to_terminal("[SERVER] Waiting for message from client")
                data, address = self.socket.recvfrom(1024)
                packet_receive = Packet()
                print("Received a packet!")
                packet_receive.unpack(data)
                print(packet_receive.message_type)
                if packet_receive.message_type == Packet.DHCPDISCOVER:
                    self.gui.write_to_terminal("[SERVER] Received DHCPDISCOVER message")
                    threading.Thread(target=self.process_discover, args=(packet_receive, address)).start()
                elif packet_receive.message_type == Packet.DHCPREQUEST:
                    self.gui.write_to_terminal("[SERVER] Receive REQUEST")
                    threading.Thread(target=self.process_request, args=(packet_receive, address)).start()

    def cleanup(self):
        self.running = False
        print("Waiting for the thread to close...")
        self.receive_thread.join()
        print("Closing socket...")
        self.socket.close()
        print("Cleanup done!")

    def process_discover(self, discover: Packet, address):
        offer_packet = get_offer()

        offer_packet.xid = discover.xid
        offer_packet.client_ip = b'\x00\x00\x00\x00'
        offer_packet.your_ip = socket.inet_aton(self.choose_address())
        offer_packet.server_ip = socket.inet_aton(self.ip_address)
        offer_packet.client_hardware_address = discover.client_hardware_address

        offer_packet.add_option(Packet.SERVER_IDENTIFIER_OPTION, socket.inet_aton(self.ip_address))
        offer_packet.add_option(Packet.IP_ADDRESS_LEASE_TIME_ADDRESS_OPTION, self.lease_time.to_bytes(4, 'big'))

        # process options
        if int.from_bytes(Packet.REQUESTED_IP_ADDRESS_OPTION, 'big') in discover.opt_dict:
            requested_ip = socket.inet_ntoa(discover.opt_dict[int.from_bytes(Packet.REQUESTED_IP_ADDRESS_OPTION, 'big')])
            if self.is_address_available(client_mac=discover.client_hardware_address, address=requested_ip):
                offer_packet.your_ip = requested_ip

        if int.from_bytes(Packet.PARAMETER_REQUESTED_LIST_OPTION, 'big') in discover.opt_dict:
            request_list = discover.opt_dict[int.from_bytes(Packet.PARAMETER_REQUESTED_LIST_OPTION, 'big')]
            self.request_lists[discover.xid] = request_list
            if int.from_bytes(Packet.SUBNET_MASK_OPTION, 'big') in request_list:
                offer_packet.add_option(Packet.SUBNET_MASK_OPTION, self.mask)
            if int.from_bytes(Packet.ROUTER_OPTION, 'big') in request_list:
                offer_packet.add_option(Packet.ROUTER_OPTION, socket.inet_aton(self.ip_address))
            if int.from_bytes(Packet.DOMAIN_NAME_SERVER_OPTION, 'big') in request_list:
                dummy_dns_servers = [socket.inet_aton('9.7.10.15'),
                                     socket.inet_aton('9.7.10.16'),
                                     socket.inet_aton('9.7.10.18')]
                offer_packet.add_option(Packet.DOMAIN_NAME_SERVER_OPTION, *dummy_dns_servers)
            if int.from_bytes(Packet.RENEWAL_TIME_VALUE_OPTION, 'big') in request_list:
                t1 = int(self.lease_time*(0.5 + (random.random() - 0.5) / 10.0))
                offer_packet.add_option(Packet.RENEWAL_TIME_VALUE_OPTION, t1.to_bytes(4, 'big'))
            if int.from_bytes(Packet.REBINDING_TIME_VALUE_OPTION, 'big') in request_list:
                t2 = int(self.lease_time*(0.875 + (random.random() - 0.5) / 20.0))
                offer_packet.add_option(Packet.RENEWAL_TIME_VALUE_OPTION, t2.to_bytes(4, 'big'))

        self.socket.sendto(offer_packet.pack(), address)
        self.gui.write_to_terminal("[SERVER] Sent DHCPOFFER message")

    def process_request(self, packet_receive: Packet, address):
        # let's ignore this for now
        # if packet_receive.server_ip != self.ip_address:
        #     print("Wrong server address in request!")
        #     return
        self.gui.write_to_terminal('[SERVER] Process REQUEST')
        assert int.from_bytes(Packet.REQUESTED_IP_ADDRESS_OPTION, 'big') in packet_receive.opt_dict
        requested_ip = socket.inet_ntoa(packet_receive.opt_dict[int.from_bytes(Packet.REQUESTED_IP_ADDRESS_OPTION, 'big')])
        client_mac = packet_receive.mac
        if self.is_address_available(client_mac, requested_ip):
            self.assign_address(client_mac, requested_ip)
            self.send_ack(packet_receive, address)
        else:
            self.send_nak(packet_receive, address)

    def send_nak(self, packet_receive, address):

        nak_packet = get_nak()
        nak_packet.xid = packet_receive.xid
        nak_packet.server_ip = packet_receive.server_ip
        nak_packet.client_ip = b'\x00\x00\x00\x00'
        nak_packet.client_hardware_address = packet_receive.client_hardware_address
        self.socket.sendto(nak_packet.pack(), address)
        self.gui.write_to_terminal('[SERVER] Send NAK')

    def send_ack(self, packet_receive, address):

        ack_packet = get_ack()
        ack_packet.xid = packet_receive.xid
        ack_packet.client_hardware_address = packet_receive.client_hardware_address
        ack_packet.server_ip = socket.inet_aton(self.ip_address)
        ack_packet.your_ip = packet_receive.your_ip
        ack_packet.add_option(Packet.IP_ADDRESS_LEASE_TIME_ADDRESS_OPTION, self.lease_time.to_bytes(4, 'big'))
        ack_packet.add_option(Packet.SERVER_IDENTIFIER_OPTION, socket.inet_aton(self.ip_address))

        # ar trebui ca in ack sa apara aceeasi paramatri ceruti si in discover, dar nu prea imi iese cu dictionarul
        # if int.from_bytes(Packet.SUBNET_MASK_OPTION, 'big') in self.request_lists[int.from_bytes(ack_packet.xid, 'big')]:
        #     ack_packet.add_option(Packet.SUBNET_MASK_OPTION, self.mask)
        # if int.from_bytes(Packet.ROUTER_OPTION, 'big') in self.request_lists[int.from_bytes(ack_packet.xid, 'big')]:
        #     ack_packet.add_option(Packet.ROUTER_OPTION, socket.inet_aton(self.ip_address))
        # if int.from_bytes(Packet.DOMAIN_NAME_SERVER_OPTION, 'big') in self.request_lists[int.from_bytes(ack_packet.xid, 'big')]:
        #     dummy_dns_servers = [socket.inet_aton('9.7.10.15'),
        #                          socket.inet_aton('9.7.10.16'),
        #                          socket.inet_aton('9.7.10.18')]
        #     ack_packet.add_option(Packet.DOMAIN_NAME_SERVER_OPTION, *dummy_dns_servers)
        # if int.from_bytes(Packet.RENEWAL_TIME_VALUE_OPTION, 'big') in self.request_lists[int.from_bytes(ack_packet.xid, 'big')]:
        #     t1 = int(self.lease_time * (0.5 + (random.random() - 0.5) / 10.0))
        #     ack_packet.add_option(Packet.RENEWAL_TIME_VALUE_OPTION, t1.to_bytes(4, 'big'))
        # if int.from_bytes(Packet.REBINDING_TIME_VALUE_OPTION, 'big') in self.request_lists[int.from_bytes(ack_packet.xid, 'big')]:
        #     t2 = int(self.lease_time * (0.875 + (random.random() - 0.5) / 20.0))
        #     ack_packet.add_option(Packet.RENEWAL_TIME_VALUE_OPTION, t2.to_bytes(4, 'big'))

        self.socket.sendto(ack_packet.pack(), address)
        self.gui.write_to_terminal("[SERVER] Send ACK")
        print(self.address_pool)

    # choose address from addresss pool - maybe need another way to choose?:))
    def choose_address(self):
        return self.address_pool[0]

    # verificari adresa - daca e disponibila
    def is_address_available(self, client_mac, address):
        if address in self.address_pool or \
                (client_mac in self.client_address_mapping and self.client_address_mapping[client_mac] == address):
            return True
        else:
            return False

    # asignare adresa
    def assign_address(self, mac, address):
        if address in self.address_pool:
            # scoatem adresa din pool
            self.address_pool.remove(address)
            self.client_address_mapping[mac] = address

            return address
        return None

    # eliberare adresa
    def release_address(self, mac):
        if mac in self.client_address_mapping:
            address = self.client_address_mapping[mac]
            self.address_pool.append(address)

            del self.client_address_mapping[mac]
