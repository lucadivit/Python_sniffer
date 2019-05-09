# Python_sniffer
This simple python class provides a network sniffer. It uses the scapy libraries.

## Description
The scapy's method "sniff" has the characteristic that it locks the execution of the code. With this class you can run the sniffer in a new thread without locking the natural execution of the code.

### Usage
```
from Sniffer import Sniffer
from Iface import Iface

iface = Iface('wlan0')

# This is an optional command
iface.set_mtu(2500)

sniffer = Sniffer(iface)
sniffer.start()
# Some instruction
sniffer.stop()
```
The constructor accepts also callback functions then you can use the scapy methods on sniffed packet:
```
def print_packet(*args, **kwargs):
  print("This message is printed every time that sniffer intercepts a packet.")
  print(kwargs)
  args[0].show()

def finished(*args, **kwargs):
  print("This message is printed when you stop the sniffer.")

iface = Iface('wlan0')
prn_kwargs = {'var': 0}
sniffer = Sniffer(iface, callback_prn=print_packet, callback_stop=finished, callback_prn_kwargs=prn_kwargs)
sniffer.start()
while(sniffer.get_started_flag() is False):
    pass
# Some instruction
sniffer.stop()
```
### Prerequisites
This class is written with Python3. Then you need to install scapy in python3 enviroment and run script with sudo command.
### Other
You can have only one instance of sniffer. At now, if you call .stop method you have to create another instance of sniffer if you want re-run it.
```
iface = Iface('wlan0')
sniffer = Sniffer(iface)
sniffer.start()
sniffer.stop()
sniffer = Sniffer(iface)
sniffer.start()
```
