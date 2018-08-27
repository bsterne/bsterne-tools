#!/usr/bin/python
# Copyright (c) 2007 Brandon Sterne
# Licensed under the MIT license.
# http://brandon.sternefamily.net/files/mit-license.txt
# CIDR Block Converter - Updated 2018-08-27
import re
import sys

# convert an IP address from its dotted-quad format to its
# 32 binary digit representation
def ip2bin(ip):
    b = ""
    inQuads = ip.split(".")
    outQuads = 4
    for q in inQuads:
        if q != "":
            b += dec2bin(int(q),8)
            outQuads -= 1
    while outQuads > 0:
        b += "00000000"
        outQuads -= 1
    return b

# convert a decimal number to binary representation
# if d is specified, left-pad the binary number with 0s to that length
def dec2bin(n,d=None):
    s = ""
    while n>0:
        if n&1:
            s = "1"+s
        else:
            s = "0"+s
        n >>= 1
    if d is not None:
        while len(s)<d:
            s = "0"+s
    if s == "": s = "0"
    return s

# convert a binary string into an IP address
def bin2ip(b):
    ip = ""
    for i in range(0,len(b),8):
        ip += str(int(b[i:i+8],2))+"."
    return ip[:-1]

# print a list of IP addresses based on the CIDR block specified
def printCIDR(c, range_mode):
    parts = c.split("/")
    baseIP = ip2bin(parts[0])
    subnet = int(parts[1])
    # Python string-slicing weirdness:
    # "myString"[:-1] -> "myStrin" but "myString"[:0] -> ""
    # if a subnet of 32 was specified simply print the single IP
    if subnet == 32:
        print bin2ip(baseIP)
    # for any other size subnet, print a list of IP addresses by concatenating
    # the prefix with each of the suffixes in the subnet
    else:
        ipPrefix = baseIP[:-(32-subnet)]
        # print only the IP range, e.g. 10.1.1.0-10.1.1.15
        if range_mode:
            print "%s-%s" % (bin2ip(ipPrefix+dec2bin(0, (32-subnet))),
                             bin2ip(ipPrefix+dec2bin(2**(32-subnet)-1, (32-subnet))))
            return
        for i in range(2**(32-subnet)):
            print bin2ip(ipPrefix+dec2bin(i, (32-subnet)))

# input validation routine for the CIDR block specified
def validateCIDRBlock(b):
    # appropriate format for CIDR block ($prefix/$subnet)
    p = re.compile("^([0-9]{1,3}\.){0,3}[0-9]{1,3}(/[0-9]{1,2}){1}$")
    if not p.match(b):
        print "Error: Invalid CIDR format!"
        return False
    # extract prefix and subnet size
    prefix, subnet = b.split("/")
    # each quad has an appropriate value (1-255)
    quads = prefix.split(".")
    for q in quads:
        if (int(q) < 0) or (int(q) > 255):
            print "Error: quad "+str(q)+" wrong size."
            return False
    # subnet is an appropriate value (1-32)
    if (int(subnet) < 1) or (int(subnet) > 32):
        print "Error: subnet "+str(subnet)+" wrong size."
        return False
    # passed all checks -> return True
    return True

def printUsage():
    print "Usage: ./cidr.py <prefix>/<subnet> [--range]\n" + \
          "  e.g. ./cidr.py 10.1.1.1/28\n" + \
          "       ./cidr.py 192.168.1/24 --range"

def main():
    # get the CIDR block from the command line args
    try:
        cidrBlock = sys.argv[1]
    # if not specified on the CLI -> prompt the user for CIDR block
    except:
        cidrBlock = raw_input("CIDR Block: ")
    # input validation returned an error
    if not validateCIDRBlock(cidrBlock):
        printUsage()
    # print the user-specified CIDR block
    else:
        printCIDR(cidrBlock, sys.argv[-1] == "--range")

if __name__ == "__main__":
    main()
