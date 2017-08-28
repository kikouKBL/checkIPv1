# checkIPv1


This is a small python routine to make some checking around IP and Networks/subnetworks

  - running on python 2.x
  - for Ubuntu linux
  - download the py(s) and just run them  !

# How to run it!

  - As sudo (cause some apt packages will be installed if necessary)
  - Launch the followig command to check if an IPv4 belongs to a list of subnets ..


```sh
python checkIPmod.py --network=192.168.1.0/24 --network=192.170.1.0/24 --ipaddr=192.168.1.1 --ipaddr=192.170.1.1
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

```
  - Launch the followig command to check if list of nets (IPv4 network addresses) are subnets of eachother ...


```sh
python checkSubnetInNet.py --network=192.168.2.1/24 --network=192.168.1.1/16 --network=192.170.1.0/24      
27/08/2017 23:38:13 - check Ip - INFO: Check range of IPs in subnet (192.168.2.1/24) against all other subnets 
27/08/2017 23:38:13 - check Ip - INFO: 192.168.2.1/24 Net in Subnet 192.170.1.0/24 ? : False 
27/08/2017 23:38:13 - check Ip - INFO: 192.168.2.1/24 Net in Subnet 192.168.1.1/16 ? : True 
27/08/2017 23:38:13 - check Ip - INFO: Check range of IPs in subnet (192.170.1.0/24) against all other subnets 
27/08/2017 23:38:13 - check Ip - INFO: 192.170.1.0/24 Net in Subnet 192.168.2.1/24 ? : False 
27/08/2017 23:38:13 - check Ip - INFO: 192.170.1.0/24 Net in Subnet 192.168.1.1/16 ? : False 
27/08/2017 23:38:13 - check Ip - INFO: Check range of IPs in subnet (192.168.1.1/16) against all other subnets 
27/08/2017 23:38:13 - check Ip - INFO: 192.168.1.1/16 Net in Subnet 192.168.2.1/24 ? : False 
27/08/2017 23:38:13 - check Ip - INFO: 192.168.1.1/16 Net in Subnet 192.170.1.0/24 ? : False 

