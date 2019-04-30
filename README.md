# Python_sniffer
This simple python class provides a network sniffer. It uses the scapy libraries.

## Description
The scapy's method "sniff" has the characteristic that it locks the execution of the code. With this class you can run the sniffer in a new thread without locking the natural execution of the code.

### Usage
```
from Sniffer import Sniffer

sniffer = Sniffer('wlan0')
sniffer.start()
# Some instruction
sniffer.stop()
```
The constructor accepts also callback functions then you can use the scapy methods on sniffed packet:
```
from Sniffer import Sniffer

def print_packet(*args):
  print("This message is printed every time that sniffer intercepts a packet.")
  args.show()

def finished(*args):
  print("This message is printed when you stop the sniffer.")

sniffer = Sniffer('wlan0', callback_prn=print_packet, callback_stop=finished)
sniffer.start()
# Some instruction
sniffer.stop()
```
