#!/usr/bin/python
# -*-coding:Utf-8 -*

import socket
import copy
import binascii
import subprocess
import os,getopt
import logging
import sys
import six
import errno
import netaddr
import netifaces

from functools import partial


logger = logging.getLogger('check Ip')
logger.setLevel(logging.DEBUG)
logging.addLevelName(logging.WARNING, "\033[1;31m%s" % logging.getLevelName(logging.WARNING))
logging.addLevelName(logging.ERROR, "\033[1;41m%s" % logging.getLevelName(logging.ERROR))
ch = logging.StreamHandler(sys.stdout)
ch.setLevel(logging.DEBUG)
formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s: %(message)s' + "\033[1;0m", datefmt='%d/%m/%Y %T')
ch.setFormatter(formatter)
logger.addHandler(ch)

def do_help(program):
    print "\nUsage: "+program+" --network=192.168.1.0/24 --network=193.168.1.0/24 --ipAddr=192.168.1.1 --ipAddr=193.168.1.1"
    print """ Mandatory arguments 
  -n, --network=CIDR	networks to check the IPs against
  -a, --ipAddr=IP	list of IP to check into the networks
"""
    sys.exit()


def get_IpToInteger(ipAddress):
    """
    """
    try:
        ipAddress_hex = socket.inet_pton(socket.AF_INET,ipAddress)
	ipAddress_dec = int(binascii.hexlify(ipAddress_hex), 16)
	return ipAddress_dec
    except :
	logger.error(" Address (%s) is not valid IP" % ipAddress)
	pass

def get_IpRange(Subnet):
    """
    """
    try:
	cidr_format = Subnet.split('/')
	host_prefix = cidr_format[0]
	route_mask = int(cidr_format[1])

	shiftedMask = (1<< (32-route_mask)) - 1
	netmask = ((1 << 32)-1)-shiftedMask

	lowerRange=get_IpToInteger(host_prefix) & netmask
	upperRange=lowerRange+shiftedMask
	return (lowerRange , upperRange)
    except :
	logger.error("Incorrect subnet (%s) CIDR format" % Subnet)
	pass

def isNetInSubNet(Net,Subnet):
    """
    """
    net_1 = range(list(Net)[0],list(Net)[1])
    net_2 = range(list(Subnet)[0],list(Subnet)[1])
    return set(net_1).issubset(net_2)
    

def checkSubnetsInNets(Subnet_dic):
    """
    """
    ## print Subnet_dic
    for net,netR in Subnet_dic.iteritems():
	logger.info("Check range of IPs in subnet (%s) against all other subnets " % net )
	Subnet_dic_ = copy.deepcopy(Subnet_dic)
	subnet_=Subnet_dic_.pop(net)
    	for net_,netR_ in Subnet_dic_.iteritems():
		## logger.info("%s Net in Subnet %s ? : %s " % (subnet_,netR_,isNetInSubNet(subnet_,netR_)))
		logger.info("%s Net in Subnet %s ? : %s " % (net,net_,isNetInSubNet(subnet_,netR_)))

def main(*args):
        networks = []
        networksRange = []
        networksRange_Dic = {}
        gotNetworks=False
        program=sys.argv[0]

        try:
                opts, args = getopt.gnu_getopt(sys.argv[1:], "?qhnl:", ["help", "network=", "version","logFile=","loglevel="])
        except getopt.GetoptError, err:
                # print help information and exit:
                print str(err)
                do_help(program)
                sys.exit(2)
        else:
                output = None
                verbose = True
                for option, argument in opts:
                        if option in ("-n", "--network"):
                                networks.append(argument)
                                gotNetworks=True
                        elif option in ("-h", "-?", "--help"):
                                do_help(program)
                        elif option in ("-q", "--quiet"):
                                verbose = False
                        else:
                                assert False, "unhandled option"

		if gotNetworks :
			for network in networks:
				IpRange=get_IpRange(network)
				networksRange.append(IpRange)
				networksRange_Dic[network]=IpRange
			checkSubnetsInNets(networksRange_Dic)
		else:
			  logger.error("Incorrect parameters format" )

                if len(sys.argv)==1:
                        do_help(program)

if __name__ == "__main__":
        sys.exit(main(*sys.argv))
