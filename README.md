# Python_sniffer
This simple python class provides a network sniffer. It uses the scapy libraries.

### Usage
```
from Sniffer import Sniffer

sniffer = Sniffer('wlan0')
sniffer.start()
#Some instruction
sniffer.stop()
```
