# checkIPv1
check if an ip address matches any network
How to run
# python checkIPmod.py --network=192.168.1.0/24 --network=192.170.1.0/24 --ipaddr=192.168.1.1 --ipaddr=192.170.1.1
23/08/2017 19:50:12 - check Ip - INFO:  ----- Import netifaces if not available -----
23/08/2017 19:50:12 - check Ip - INFO:  ----- Import netaddr if not available -----
23/08/2017 19:50:12 - check Ip - INFO:  Network (192.168.1.0/24) is in CIDR presentation format
23/08/2017 19:50:12 - check Ip - INFO:  address (192.168.1.1) is an ip address
23/08/2017 19:50:12 - check Ip - INFO:  Address (192.168.1.1) is in network
192.168.1.1
23/08/2017 19:50:12 - check Ip - INFO:  address (192.170.1.1) is an ip address
23/08/2017 19:50:12 - check Ip - WARNING:  Address (192.170.1.1) is not in network
192.170.1.1
23/08/2017 19:50:12 - check Ip - INFO:  Network (192.170.1.0/24) is in CIDR presentation format
23/08/2017 19:50:12 - check Ip - INFO:  address (192.168.1.1) is an ip address
23/08/2017 19:50:12 - check Ip - WARNING:  Address (192.168.1.1) is not in network
192.168.1.1
23/08/2017 19:50:12 - check Ip - INFO:  address (192.170.1.1) is an ip address
23/08/2017 19:50:12 - check Ip - INFO:  Address (192.170.1.1) is in network
192.170.1.1

