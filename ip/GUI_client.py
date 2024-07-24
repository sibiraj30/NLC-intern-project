import socket
import tkinter as tk
from tkinter import *
from tkinter import messagebox
import re

import client
import Packet


def validate_lease_time(lease_time) -> bool:
    if len(lease_time) == 0:
        messagebox.showerror("Lease time error", "Lease time can't be empty")
        return False
    elif any(ch.isalpha() for ch in lease_time):
        messagebox.showerror("Lease time error", "Lease time can't contain letters")
        return False
    return True


def validate_ip_address(ip_address) -> bool:
    if len(ip_address) == 0:
        messagebox.showerror("IP Address error", "Ip Address can't be empty")
        return False
    elif not re.match(r"\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}", ip_address):
        messagebox.showerror("IP Address error", "Ip Address format error")
        return False
    else:
        for ip_byte in ip_address.split("."):
            if int(ip_byte) < 0 or int(ip_byte) > 255 or any(i.isalpha() for i in ip_byte):
                messagebox.showerror("IP Address error", "Ip Address format error")
                return False
    return True


class GuiClient:

    def __init__(self, window_context):
        super().__init__()
     
        self.backend = client.Client(self)

     
        window_context.title("DHCP Client")
        window_context.geometry("900x600")
        window_context.resizable(False, False)

        self.opt_frame = Frame(window_context)
        self.right_frame = Frame(window_context)

        self.SUBNET_MASK = IntVar()
        self.ROUTER = IntVar()
        self.DNS = IntVar()
        self.REQUESTED_IP_ADDRESS = IntVar()
        self.LEASE_TIME = IntVar()
        self.MESSAGE_TYPE = IntVar()
        self.MESSAGE_TYPE.set(1)
        self.SERVER_IDENTIFIER = IntVar()
        self.PARAMETER_REQUESTED_LIST = IntVar()
        self.RENEWAL_TIME = IntVar()
        self.REBINDING_TIME = IntVar()
        self.END = IntVar()
        self.END.set(1)

        self.button_start = Button(self.opt_frame, command=self.backend.discover, height=2, width=10, text="Start")
        self.button_load_option = Button(self.opt_frame, height=2, width=10, text="Load", command=self.load_options)
        self.ip_entry = Entry(self.opt_frame)
      

        self.text = Text(self.right_frame, width=45, height=16)
        self.text_terminal = Text(self.right_frame, width=45, height=16)

    def load_options(self):

        discover = Packet.get_discover()

        if self.REQUESTED_IP_ADDRESS.get():
            if not validate_ip_address(self.ip_entry.get()):
                raise ValueError
            discover.add_option(Packet.Packet.REQUESTED_IP_ADDRESS_OPTION, socket.inet_aton(self.ip_entry.get()))

        if self.PARAMETER_REQUESTED_LIST.get():
            parameter_list = list()

            if self.SUBNET_MASK.get():
                parameter_list.append(Packet.Packet.SUBNET_MASK_OPTION)
            if self.ROUTER.get():
                parameter_list.append(Packet.Packet.ROUTER_OPTION)
            if self.DNS.get():
                parameter_list.append(Packet.Packet.DOMAIN_NAME_SERVER_OPTION)
            if self.SERVER_IDENTIFIER.get():
                parameter_list.append(Packet.Packet.SERVER_IDENTIFIER_OPTION)
            if self.RENEWAL_TIME.get():
                parameter_list.append(Packet.Packet.RENEWAL_TIME_VALUE_OPTION)
            if self.REBINDING_TIME.get():
                parameter_list.append(Packet.Packet.REBINDING_TIME_VALUE_OPTION)

            if len(parameter_list) == 0:
                messagebox.showerror(title="Parameter request list error!",
                                     message="Something happened when building parameter request list!")
                raise ValueError

            discover.add_option(Packet.Packet.PARAMETER_REQUESTED_LIST_OPTION, *parameter_list)


        self.backend.prepare_discover(discover)

    def disable_entry(self):
        if self.REQUESTED_IP_ADDRESS.get() == 1:
            self.ip_entry.config(state=NORMAL)
        elif self.REQUESTED_IP_ADDRESS.get() == 0:
            self.ip_entry.config(state=DISABLED)

    def toggle_request_list(self):
        if self.SUBNET_MASK.get() == 1 or self.ROUTER.get() == 1 or self.DNS.get() or self.RENEWAL_TIME.get() or \
                self.REBINDING_TIME.get():
            self.PARAMETER_REQUESTED_LIST.set(1)
        else:
            self.PARAMETER_REQUESTED_LIST.set(0)

    def run(self):
        self.opt_frame.grid(row=0, column=0)
        self.right_frame.grid(row=0, column=1, padx=60)

        opt_label = Label(self.opt_frame, text="DHCP Options")
        opt_label.grid(row=1, column=1, padx=50, pady=20)

        par_label = Label(self.right_frame, text="Current Parameters")
        par_label.grid(row=0, column=0)
        self.text.grid(row=1, column=0)

        terminal_label = Label(self.right_frame, text="Operations")
        terminal_label.grid(row=2, column=0)
        self.text_terminal.grid(row=3, column=0)

        opt6_label = Label(self.opt_frame, text="Option 53: DHCP Message Type")
        opt4_label = Label(self.opt_frame, text="Option 50: Requested IP Address")

        opt8_label = Label(self.opt_frame, text="Option 55: Parameter Requested List", state=DISABLED)
        opt1_label = Label(self.opt_frame, text="Option 1: Subnet Mask")
        opt2_label = Label(self.opt_frame, text="Option 3: Router")
        opt3_label = Label(self.opt_frame, text="Option 6: Domain Name Server")

        opt9_label = Label(self.opt_frame, text="Option 58: Renewal Time Value")
        opt10_label = Label(self.opt_frame, text="Option 59: Rebinding Time Value")
        opt11_label = Label(self.opt_frame, text="Option 255: End")

        opt6_ck = Checkbutton(self.opt_frame, variable=self.MESSAGE_TYPE, height=2, width=4)
        opt4_ck = Checkbutton(self.opt_frame, variable=self.REQUESTED_IP_ADDRESS, height=2, width=4,
                              command=self.disable_entry)

        opt8_ck = Checkbutton(self.opt_frame, variable=self.PARAMETER_REQUESTED_LIST, height=2, width=4, state=DISABLED)
        opt1_ck = Checkbutton(self.opt_frame, variable=self.SUBNET_MASK, height=2, width=4,
                              command=self.toggle_request_list)
        opt2_ck = Checkbutton(self.opt_frame, variable=self.ROUTER, height=2, width=4,
                              command=self.toggle_request_list)
        opt3_ck = Checkbutton(self.opt_frame, variable=self.DNS, height=2, width=4,
                              command=self.toggle_request_list)

        opt9_ck = Checkbutton(self.opt_frame, variable=self.RENEWAL_TIME, height=2, width=4,
                              command=self.toggle_request_list)
        opt10_ck = Checkbutton(self.opt_frame, variable=self.REBINDING_TIME, height=2, width=4,
                               command=self.toggle_request_list)
        opt11_ck = Checkbutton(self.opt_frame, variable=self.END, height=2, width=4)

        opt6_label.grid(row=2, column=1, sticky='w')
        opt6_label.config(state="disabled")
        opt4_label.grid(row=3, column=1, sticky='w')
        self.ip_entry.config(state="disabled")
        self.ip_entry.grid(row=3, column=2)

        opt8_label.grid(row=5, column=1, sticky='w')
        opt1_label.grid(row=6, column=1, sticky='w')
        opt2_label.grid(row=7, column=1, sticky='w')
        opt3_label.grid(row=8, column=1, sticky='w')
 
        opt9_label.grid(row=10, column=1, sticky='w')
        opt10_label.grid(row=11, column=1, sticky='w')
        opt11_label.grid(row=12, column=1, sticky='w')
        opt11_label.config(state="disabled")

        opt6_ck.grid(row=2, column=0)
        opt4_ck.grid(row=3, column=0)
 
        opt8_ck.grid(row=5, column=0)
        opt1_ck.grid(row=6, column=0)
        opt2_ck.grid(row=7, column=0)
        opt3_ck.grid(row=8, column=0)
        opt6_ck.config(state="disabled")

        opt9_ck.grid(row=10, column=0)
        opt10_ck.grid(row=11, column=0)
        opt11_ck.grid(row=12, column=0)
        opt11_ck.config(state="disabled")

        self.button_start.grid(row=15, column=0, padx=20, pady=20)
        self.button_load_option.grid(row=15, column=1, padx=20, pady=20)

    def write_text(self, information):

        self.text.insert(END, str(information))

    def delete_text(self):
        self.text.delete(0, END)

    def write_to_terminal(self, msg):
        self.text_terminal['state'] = 'normal'
        self.text_terminal.insert('end', msg)
        self.text_terminal.insert('end', '\n')
        self.text_terminal['state'] = 'disabled'

    def cleanup(self):
        self.backend.cleanup()


if __name__ == "__main__":
    window = tk.Tk()
    gui_client = GuiClient(window)
    gui_client.run()
    window.mainloop()
    gui_client.cleanup()
