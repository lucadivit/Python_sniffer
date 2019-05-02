from builtins import super
from threading import Event
from scapy.layers.inet import IP
from scapy.all import *
import os

class Sniffer(Thread):

    def __init__(self, interface, callback_prn=None, callback_stop=None, stop_escape_raw="stop_sniff", monitor=False, verbose=False):
        super().__init__()
        self.mtu = mtu
        self.interface = interface
        self.stop_escape_raw = stop_escape_raw
        self.callback_stop = callback_stop
        self.callback_prn = callback_prn
        self.is_stopped = False
        self.monitor = monitor
        self.verbose = verbose
        self.stop_sniffer_flag = Event()

    def start(self):
        super().start()

    def run(self):
        print("\n" + "Sniffer Avviato" + "\n")
        try:
            sniff(iface=self.get_interface(), prn=self.sniffing_callback, store=0,  stop_filter=self.stop_callback, monitor=self.get_monitor())#lambda x: self.stop_sniffer_flag.isSet()
        except:
            print("\n" + "Errore! Provare a disabilitare la monitor mode" + "\n")
            return

    def set_stopped_flag(self, bool_stop):
        self.is_stopped = bool_stop

    def get_stopped_flag(self):
        return self.is_stopped

    def set_interface(self, interface):
        self.interface = interface

    def get_interface(self):
        return self.interface

    def set_monitor(self, val):
        self.monitor = val

    def get_monitor(self):
        return self.monitor

    def set_stop_escape_raw(self, stop_escape_raw):
        self.stop_escape_raw = stop_escape_raw

    def get_stop_escape_raw(self):
        return self.stop_escape_raw

    def set_callback_stop(self, callback_stop):
        self.callback_stop = callback_stop

    def set_callback_prn(self, callback_prn):
        self.callback_prn = callback_prn

    def stop(self):
        self.stop_sniffer_flag.set()
        sendp(IP(src="127.0.0.1", dst="127.0.0.1")/self.get_stop_escape_raw(), verbose=0)

    def set_verbose(self, val):
        self.verbose=val

    def get_verbose(self):
        return self.verbose

    def sniffing_callback(self, *args):
        if self.is_last_packet(args[0]) is True:
            pass
        else:
            if self.callback_prn is not None:
                self.callback_prn(args)
            if self.get_verbose() is True:
                print("\n" + "Pkt sniffato" + "\n")


    def is_last_packet(self, pkt):
        if pkt[0].haslayer(Raw) is True and self.stop_sniffer_flag.isSet() is True:
            payload = str(pkt[0].getlayer(Raw).load)
            if self.stop_escape_raw in payload:
                return True
            else:
                return False
        else:
            return False

    def stop_callback(self, *args):
        if self.is_last_packet(args[0]) is True:
            if self.callback_stop is not None:
                self.callback_stop(args)
            self.set_stopped_flag(True)
            print("\n" + "Sniffer Terminato" + "\n")
            return True
        else:
            return False
