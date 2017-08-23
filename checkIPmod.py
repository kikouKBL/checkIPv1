#!/usr/bin/python
# -*-coding:Utf-8 -*

import subprocess
import os,getopt
import logging
import sys
import six
import errno
import netaddr
import netifaces

from functools import partial

APT_NO_LOCK = 100  # The return code for "couldn't acquire lock" in APT.
APT_NO_LOCK_RETRY_DELAY = 10  # Wait 10 seconds between apt lock checks.
APT_NO_LOCK_RETRY_COUNT = 30  # Retry to acquire the lock X times.


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
    print "\nUsage: "+program+" --networks=192.168.1.0/24,193.168.1.0/24 --ipAddr=192.168.1.1,193.168.1.1"
    print """ Mandatory arguments 
  -n, --networks=CIDR	list of networks
  -a, --ipAddr=IP	list IPs
"""
    sys.exit()


def log(message, level=None):
    """Write a message to the verneGlobal log"""
    command = ['verneGlobal-log']
    if level:
        command += ['-l', level]
    if not isinstance(message, six.string_types):
        message = repr(message)
    command += [message]
    # Missing verneGlobal-log should not cause failures in unit tests
    # Send log output to stderr
    try:
        subprocess.call(command)
    except OSError as e:
        if e.errno == errno.ENOENT:
            if level:
                message = "{}: {}".format(level, message)
            message = "verneGlobal-log: {}".format(message)
	    file=sys.stderr
            print(message, file)
        else:
            raise


def apt_install(packages, options=None, fatal=False):
    """Install one or more packages"""
    if options is None:
        options = ['--option=Dpkg::Options::=--force-confold']

    cmd = ['apt-get', '--assume-yes']
    cmd.extend(options)
    cmd.append('install')
    if isinstance(packages, six.string_types):
        cmd.append(packages)
    else:
        cmd.extend(packages)
    log("Installing {} with options: {}".format(packages,
                                                options))
    _run_apt_command(cmd, fatal)


def apt_upgrade(options=None, fatal=False, dist=False):
    """Upgrade all packages"""
    if options is None:
        options = ['--option=Dpkg::Options::=--force-confold']

    cmd = ['apt-get', '--assume-yes']
    cmd.extend(options)
    if dist:
        cmd.append('dist-upgrade')
    else:
        cmd.append('upgrade')
    log("Upgrading with options: {}".format(options))
    _run_apt_command(cmd, fatal)

def apt_update(fatal=False):
    """Update local apt cache"""
    cmd = ['apt-get', 'update']
    _run_apt_command(cmd, fatal)

def _run_apt_command(cmd, fatal=False):
    """
    Run an APT command, checking output and retrying if the fatal flag is set
    to True.

    :param: cmd: str: The apt command to run.
    :param: fatal: bool: Whether the command's output should be checked and
        retried.
    """
    env = os.environ.copy()

    if 'DEBIAN_FRONTEND' not in env:
        env['DEBIAN_FRONTEND'] = 'noninteractive'

    if fatal:
        retry_count = 0
        result = None

        # If the command is considered "fatal", we need to retry if the apt
        # lock was not acquired.

        while result is None or result == APT_NO_LOCK:
            try:
                result = subprocess.check_call(cmd, env=env)
            except subprocess.CalledProcessError as e:
                retry_count = retry_count + 1
                if retry_count > APT_NO_LOCK_RETRY_COUNT:
                    raise
                result = e.returncode
                log("Couldn't acquire DPKG lock. Will retry in {} seconds."
                    "".format(APT_NO_LOCK_RETRY_DELAY))
                time.sleep(APT_NO_LOCK_RETRY_DELAY)

    else:
        subprocess.call(cmd, env=env)

def _getPackageInstall():
  logger.info(" ----- Import netifaces if not available -----")
  try:
      import netifaces
  except ImportError:
      apt_update(fatal=True)
      apt_install('python-netifaces', fatal=True)
      import netifaces

  logger.info(" ----- Import netaddr if not available -----")
  try:
      import netaddr
  except ImportError:
      apt_update(fatal=True)
      apt_install('python-netaddr', fatal=True)
      import netaddr


def _validate_cidr(network):
    try:
        netaddr.IPNetwork(network)
	logger.info(" Network (%s) is in CIDR presentation format" % network)
    except (netaddr.core.AddrFormatError, ValueError):
	logger.error(" Network (%s) is not in CIDR presentation format" % network)


def no_ip_found_error_out(network):
    errmsg = ("No IP address found in network(s): %s" % network)
    logger.error(errmsg)
    ## raise ValueError(errmsg)

def is_ip(address):
    """
    Returns True if address is a valid IP address.
    """
    try:
        # Test to see if already an IPv4/IPv6 address
        address = netaddr.IPAddress(address)
	logger.info(" address (%s) is an ip address" % address)
        return True
    except netaddr.AddrFormatError:
	logger.error(" address (%s) is not an ip address" % address)
        return False


def get_address_in_network(network, fallback=None, fatal=False):
    """Get an IPv4 or IPv6 address within the network from the host.

    :param network (str): CIDR presentation format. For example,
        '192.168.1.0/24'. Supports multiple networks as a space-delimited list.
    :param fallback (str): If no address is found, return fallback.
    :param fatal (boolean): If no address is found, fallback is not
        set and fatal is True then exit(1).
    """
    if network is None:
        if fallback is not None:
            return fallback

        if fatal:
            no_ip_found_error_out(network)
        else:
            return None

    networks = network.split() or [network]
    for network in networks:
        _validate_cidr(network)
        network = netaddr.IPNetwork(network)
        for iface in netifaces.interfaces():
            addresses = netifaces.ifaddresses(iface)
            if network.version == 4 and netifaces.AF_INET in addresses:
                addr = addresses[netifaces.AF_INET][0]['addr']
                netmask = addresses[netifaces.AF_INET][0]['netmask']
                cidr = netaddr.IPNetwork("%s/%s" % (addr, netmask))
                if cidr in network:
                    return str(cidr.ip)

            if network.version == 6 and netifaces.AF_INET6 in addresses:
                for addr in addresses[netifaces.AF_INET6]:
                    if not addr['addr'].startswith('fe80'):
                        cidr = netaddr.IPNetwork("%s/%s" % (addr['addr'], addr['netmask']))
                        if cidr in network:
                            return str(cidr.ip)

    if fallback is not None:
        return fallback

    if fatal:
        no_ip_found_error_out(network)

    return None


def is_ipv6(address):
    """Determine whether provided address is IPv6 or not."""
    try:
        address = netaddr.IPAddress(address)
    except netaddr.AddrFormatError:
        # probably a hostname - so not an address at all!
        return False

    return address.version == 6


def is_address_in_network(network, address):
    """
    Determine whether the provided address is within a network range.

    :param network (str): CIDR presentation format. For example,
        '192.168.1.0/24'.
    :param address: An individual IPv4 or IPv6 address without a net
        mask or subnet prefix. For example, '192.168.1.1'.
    :returns boolean: Flag indicating whether address is in network.
    """
    try:
        network = netaddr.IPNetwork(network)
    except (netaddr.core.AddrFormatError, ValueError):
	logger.error(" Network (%s) is not in CIDR presentation format" % network)

    try:
        address = netaddr.IPAddress(address)
    except (netaddr.core.AddrFormatError, ValueError):
	logger.info(" Address (%s) is not in correct presentation format" % address)

    if address in network:
	logger.info(" Address (%s) is in network" % address)
        return True
    else:
	logger.warning(" Address (%s) is not in network" % address)
        return False



def _get_for_address(address, key):
    """Retrieve an attribute of or the physical interface that
    the IP address provided could be bound to.

    :param address (str): An individual IPv4 or IPv6 address without a net
        mask or subnet prefix. For example, '192.168.1.1'.
    :param key: 'iface' for the physical interface name or an attribute
        of the configured interface, for example 'netmask'.
    :returns str: Requested attribute or None if address is not bindable.
    """
    address = netaddr.IPAddress(address)
    for iface in netifaces.interfaces():
        addresses = netifaces.ifaddresses(iface)
        if address.version == 4 and netifaces.AF_INET in addresses:
            addr = addresses[netifaces.AF_INET][0]['addr']
            netmask = addresses[netifaces.AF_INET][0]['netmask']
            network = netaddr.IPNetwork("%s/%s" % (addr, netmask))
            cidr = network.cidr
            if address in cidr:
                if key == 'iface':
                    return iface
                else:
                    return addresses[netifaces.AF_INET][0][key]

        if address.version == 6 and netifaces.AF_INET6 in addresses:
            for addr in addresses[netifaces.AF_INET6]:
                if not addr['addr'].startswith('fe80'):
                    network = netaddr.IPNetwork("%s/%s" % (addr['addr'],
                                                           addr['netmask']))
                    cidr = network.cidr
                    if address in cidr:
                        if key == 'iface':
                            return iface
                        elif key == 'netmask' and cidr:
                            return str(cidr).split('/')[1]
                        else:
                            return addr[key]

    return None

### _validate_cidr('192.168.1.0/24')
### get_address_in_network('192.16')
### network='192.168.1.0/24'
### address='192.168.1.0'
### is_ip(address)
### is_address_in_network(network, address)

def main(*args):
        networks = []
        ipAddresses = []
        gotNetworks=False
        gotIPs=False
        program=sys.argv[0]

        try:
                opts, args = getopt.gnu_getopt(sys.argv[1:], "?qhnil:", ["help", "network=", "version","ipaddr=","logFile=","loglevel="])
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
                        elif option in ("-i", "--ipaddr"):
                                ipAddresses.append(argument)
                                gotIPs=True
                        elif option in ("-h", "-?", "--help"):
                                do_help(program)
                        elif option in ("-q", "--quiet"):
                                verbose = False
                        else:
                                assert False, "unhandled option"

		if gotNetworks and gotIPs:
		  _getPackageInstall()
                  for network in networks:
                        if gotNetworks :
			  _validate_cidr(network)
			  for ip_ in ipAddresses:
				is_ip(ip_)
				is_address_in_network(network,ip_)
				print ip_
                          ##do_parsing(filename,OutDir)
                        else:
			  print "KO"
                          ##pids.append(newpid)

                if len(sys.argv)==1:
                        do_help(program)

if __name__ == "__main__":
        sys.exit(main(*sys.argv))

