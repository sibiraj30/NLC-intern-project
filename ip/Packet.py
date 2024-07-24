import socket
import random
import struct


TIP_MESAJ = ("", "DHCPDISCOVER",
             "DHCPOFFER",
             "DHCPREQUEST",
             "DHCPDECLINE",
             "DHCPACK",
             "DHCPNAK",
             "DHCPRELEASE",
             "DHCPINFORM")


def generate_mac():
    mac = "".join(random.choice("abcdef0123456789") for _ in range(0, 12))
    return mac


def mac_to_bytes(mac):
    while len(mac) < 12:
        mac = '0' + mac
    mac_bytes = b''
    for i in range(0, 12, 2):
        m = int(mac[i:i + 2], 16)
        mac_bytes += m.to_bytes(1, 'big')
    return mac_bytes


class BOOTPHeader(object):
    REQUEST = b'\x01'
    REPLY = b'\x02'

    def __init__(self, opcode, mac):
 

        self.opcode = opcode
        self.hardware_type = b'\x01'
        self.hardware_address_length = b'\x06'
        self.hops = b'\x00'
        self.xid = self.gen_xid()
        self.seconds = b'\x00\x00'
        self.flags = b'\x80\x00'
        self.client_ip = b'\x00\x00\x00\x00'
        self.your_ip = b'\x00\x00\x00\x00'
        self.server_ip = b'\x00\x00\x00\x00'
        self.gateway_ip = b'\x00\x00\x00\x00'
        self.client_hardware_address = mac + b'\x00' * 10  
        self.server_host_name = b'\x00' * 64
        self.boot_filename = b'\x00' * 128  
        self.options = ''  

    def gen_xid(self):
        return random.getrandbits(32).to_bytes(4, 'big')

    def pack(self):
        return (self.opcode + self.hardware_type + self.hardware_address_length +
                self.hops + self.xid + self.seconds + self.flags + self.client_ip + self.your_ip +
                self.server_ip + self.gateway_ip + self.client_hardware_address + self.server_host_name +
                self.boot_filename + self.options)


class Packet(BOOTPHeader):
    DHCPDISCOVER = b'\x01'
    DHCPOFFER = b'\x02'
    DHCPREQUEST = b'\x03'
    DHCPDECLINE = b'\x04'
    DHCPACK = b'\x05'
    DHCPNAK = b'\x06'
    DHCPRELEASE = b'\x07'
    DHCPINFORM = b'\x08'

    SUBNET_MASK_OPTION = b'\x01'
    ROUTER_OPTION = b'\x03'
    DOMAIN_NAME_SERVER_OPTION = b'\x06'
    REQUESTED_IP_ADDRESS_OPTION = b'\x32'
    IP_ADDRESS_LEASE_TIME_ADDRESS_OPTION = b'\x33'
    DHCP_MESSAGE_TYPE_OPTION = b'\x35'
    SERVER_IDENTIFIER_OPTION = b'\x36'
    PARAMETER_REQUESTED_LIST_OPTION = b'\x37'
    RENEWAL_TIME_VALUE_OPTION = b'\x3a'
    REBINDING_TIME_VALUE_OPTION = b'\x3b'
    END_OPTION = b'\xff'

    def __init__(self, message_type=DHCPDISCOVER):

        self.message_type = message_type
        self.mac = mac_to_bytes(generate_mac())


        if self.message_type == self.DHCPOFFER or self.message_type == self.DHCPACK or \
                self.message_type == self.DHCPNAK:
            self.opcode = BOOTPHeader.REPLY
        else:
            self.opcode = BOOTPHeader.REQUEST

        super(Packet, self).__init__(self.opcode, self.mac)
        self.option_list = []
        self.opt_dict = {}

        self.add_option(self.DHCP_MESSAGE_TYPE_OPTION, self.message_type)

    def add_option(self, option, *args: bytes):
        value = b''
        length = 0
        for i in args:
            length += len(i)
            value += i
        if length > 0:
            length = bytes([length])
        else:
            length = b''
        self.option_list.append(option + length + value)

    def pack(self):
        self.options = b'\x63\x82\x53\x63' 
        self.options += b''.join(self.option_list)

        self.options += Packet.END_OPTION
        return super(Packet, self).pack()

    def unpack(self, data):
        self.opcode, self.hardware_type, self.hardware_address_length, \
            self.hops, self.xid, self.seconds, self.flags, self.client_ip, \
            self.your_ip, self.server_ip, self.gateway_ip, self.client_hardware_address, \
            self.server_host_name, self.boot_filename, self.options \
            = struct.unpack('cccc4s2s2s4s4s4s4s16s64s128s' + str(len(data) - 236) + 's', data)

        idx = 4

        while True:
            try:
            
                op_code = self.options[idx]
                if op_code == 255:
                    self.opt_dict[op_code] = ''
                    break
                op_len = self.options[idx + 1]
                op_data = self.options[idx + 2:idx + 2 + op_len]
                idx = idx + 2 + op_len
                self.opt_dict[op_code] = op_data
            except IndexError:
                break

        if int.from_bytes(self.DHCP_MESSAGE_TYPE_OPTION, 'big') in self.opt_dict:
            self.message_type = self.opt_dict[int.from_bytes(self.DHCP_MESSAGE_TYPE_OPTION, 'big')]
            if self.message_type == self.DHCPOFFER or self.message_type == self.DHCPACK or \
                    self.message_type == self.DHCPNAK:
                self.opcode = BOOTPHeader.REPLY
            else:
                self.opcode = BOOTPHeader.REQUEST
        else:
            print("Failed to get message_type from packet!")

    def to_string(self) -> str:

        string = ""
        int_op = int.from_bytes(self.opcode, "big")
        string += f"Opcode={int_op}" + "\n"

        int_htype = int.from_bytes(self.hardware_type, "big")
        string += f"Hardware type={int_htype}" + "\n"

        int_hlen = int.from_bytes(self.hardware_address_length, "big")
        string += f"Hardware address length={int_hlen}" + "\n"

        int_hops = int.from_bytes(self.hops, "big")
        string += f"Hops={int_hops}" + "\n"

        int_xid = int.from_bytes(self.xid, "big")
        string += f"Xid={int_xid}" + "\n"

        int_secs = int.from_bytes(self.seconds, "big")
        string += f"Xid={int_secs}" + "\n"

        string += f"Flags={self.flags}" + "\n"

        string += f"Ciaddr={socket.inet_ntoa(self.client_ip)}" + "\n"
        string += f"Yiaddr={socket.inet_ntoa(self.your_ip)}" + "\n"
        string += f"Siaddr={socket.inet_ntoa(self.server_ip)}" + "\n"
        string += f"Giaddr={socket.inet_ntoa(self.gateway_ip)}" + "\n"

        string += f"Chaddr={self.client_hardware_address}" + "\n"

        return string




def get_discover() -> Packet:
    discover = Packet(Packet.DHCPDISCOVER)
    return discover


def get_offer() -> Packet:
    offer = Packet(Packet.DHCPOFFER)
    return offer


def get_request() -> Packet:
    request = Packet(Packet.DHCPREQUEST)
    return request


def get_ack() -> Packet:
    ack = Packet(Packet.DHCPACK)
    return ack


def get_nak() -> Packet:
    nak = Packet(Packet.DHCPNAK)
    return nak
