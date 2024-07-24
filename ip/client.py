import queue
import sys
import threading
import time
import socket
import select
import subprocess
import random

from GUI_client import GuiClient
from Packet import *

MAX_COUNT = 2 

class Client:

    def _init_(self, gui: GuiClient, source_port=68, destination_port=67, destination_ip='<server_laptop_ip>'):
        self.gui = gui
        self.destination_port = destination_port
        self.destination_ip = destination_ip

        self.received_offer_event = threading.Event()
        self.renew_timer = None
        self.rebind_timer = None

        self.storage = queue.Queue(16)
        self.prepared_discover = None
        self.discover_timeout = 1  
        self.max_discover_timeout = 30

        self.xid = b''
        self.mac = b''
        self.your_ip = b''
        self.server_identifier = b''
        self.server_ip = b''
        self.lease_time = 0
        self.t1 = 0
        self.t2 = 0

        self.socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
        self.socket.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
        self.socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.socket.bind(("", source_port))
        self.running = True

        self.receive_thread = threading.Thread(target=self.receive_fct)
        self.receive_thread.start()

    def cleanup(self):
        self.running = False
        self.receive_thread.join()
        self.socket.close()

    def receive_fct(self):
        contor = 0
        while self.running:
            r, _, _ = select.select([self.socket], [], [], 1)
            if not r:
                contor += 1
            else:
                self.gui.write_to_terminal("[CLIENT] Receive thread listening...")
                try:
                    data, address = self.socket.recvfrom(1024)
                except:
                    print("Eroare la citirea din socket")
                    sys.exit()

                received_packet = Packet()
                received_packet.unpack(data)
                print("client")
                print(received_packet.message_type)

                if received_packet.message_type == Packet.DHCPDISCOVER:
                    self.gui.write_to_terminal("[CLIENT] Received DISCOVER???")
                    print("[CLIENT] Received DISCOVER???")
                elif received_packet.message_type == Packet.DHCPOFFER:
                    self.gui.write_to_terminal("[CLIENT] Received DHCPOFFER")
                    self.received_offer_event.set()
                    try:
                        self.storage.put(received_packet)
                    except TimeoutError:
                        print("Fatal error: Storage is full!") 
                    threading.Thread(target=self.process_offer).start()
                elif received_packet.message_type == Packet.DHCPACK:
                    self.gui.write_to_terminal("[CLIENT] Received DHCPACK")
                    threading.Thread(target=self.process_ack, args=[received_packet]).start()
                elif received_packet.message_type == Packet.DHCPNAK:
                    self.gui.write_to_terminal("[CLIENT] Received DHCPNAK")

    def prepare_discover(self, discover: Packet):
        self.prepared_discover = discover

    def discover(self):
        if self.prepared_discover is None:
            pack_discover = get_discover()
        else:
            pack_discover = self.prepared_discover
        self.xid = pack_discover.xid
        self.mac = pack_discover.client_hardware_address
        self.received_offer_event.clear()
        self.gui.write_text(pack_discover.to_string())
        self.socket.sendto(pack_discover.pack(), ("<broadcast>", self.destination_port))


    def send_request(self, packet_offer_receive):
        packet_request = get_request()
        packet_request.client_hardware_address = packet_offer_receive.client_hardware_address
        packet_request.xid = packet_offer_receive.xid
        packet_request.add_option(Packet.REQUESTED_IP_ADDRESS_OPTION, packet_offer_receive.your_ip)
        packet_request.add_option(Packet.SERVER_IDENTIFIER_OPTION, packet_offer_receive.server_ip)

        self.socket.sendto(packet_request.pack(), ("<broadcast>", 67))
        self.gui.write_to_terminal('[CLIENT] Sent REQUEST')

    def process_ack(self, received_ack: Packet):
        assert int.from_bytes(Packet.IP_ADDRESS_LEASE_TIME_ADDRESS_OPTION, 'big') in received_ack.opt_dict
        self.lease_time = received_ack.opt_dict[int.from_bytes(Packet.IP_ADDRESS_LEASE_TIME_ADDRESS_OPTION, 'big')]
        lease = int.from_bytes(self.lease_time, byteorder='big')
        print(lease)
        if int.from_bytes(Packet.RENEWAL_TIME_VALUE_OPTION, 'big') in received_ack.opt_dict:
            self.t1 = received_ack.opt_dict[int.from_bytes(Packet.RENEWAL_TIME_VALUE_OPTION, 'big')]
        else:
            self.t1 = int(lease / 2)
        if int.from_bytes(Packet.REBINDING_TIME_VALUE_OPTION, 'big') in received_ack.opt_dict:
            self.t2 = received_ack.opt_dict[int.from_bytes(Packet.REBINDING_TIME_VALUE_OPTION, 'big')]
        else:
            self.t2 = int(lease * 7 / 8)
        
        try:
            your_ip = socket.inet_ntoa(received_ack.your_ip)
            server_ip = socket.inet_ntoa(received_ack.server_ip)
            netmask_bytes = received_ack.opt_dict.get(1, b'') 
            netmask = socket.inet_ntoa(netmask_bytes) if netmask_bytes else "255.255.255.0"

            if sys.platform == "win32":  
                command = f"netsh interface ip set address \"Ethernet\" static {your_ip} {netmask} {server_ip}"
            else:  
                command = f"sudo ip addr add {your_ip}/{netmask} dev eth0" 

            result = subprocess.run(command, shell=True, capture_output=True, text=True)

            if result.returncode == 0:
                self.gui.write_to_terminal(f"[CLIENT] Successfully set IP: {your_ip}, Netmask: {netmask}")
            else:
                self.gui.write_to_terminal(f"[CLIENT] Error setting IP: {result.stderr}")
        except Exception as e:
            self.gui.write_to_terminal(f"[CLIENT] Exception during IP configuration: {e}")

        if self.renew_timer is not None:
            self.renew_timer.cancel()
        if self.rebind_timer is not None:
            self.rebind_timer.cancel()
        self.renew_timer = threading.Timer(self.t1, self.send_renew)
        self.renew_timer.start()
        self.rebind_timer = threading.Timer(self.t2, self.send_rebind)
        self.rebind_timer.start()

    def send_renew(self):
        request = get_request()
        print("renew")
        print(request.message_type)
        request.xid=self.xid
        request.client_hardware_address = self.mac
        request.client_ip = self.your_ip
        request.add_option(Packet.REQUESTED_IP_ADDRESS_OPTION, self.your_ip)
        self.gui.write_to_terminal("[CLIENT] Send renew")
        self.socket.sendto(request.pack(), (socket.inet_ntoa(self.server_ip), 67))

    def send_rebind(self):
        request = get_request()
        request.xid=self.xid
        request.client_hardware_address = self.mac
        request.client_ip = self.your_ip
        request.add_option(Packet.REQUESTED_IP_ADDRESS_OPTION, self.your_ip)
        self.gui.write_to_terminal("[CLIENT] Send rebind")
        self.socket.sendto(request.pack(), ("<broadcast>", 67))