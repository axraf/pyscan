#-*- coding: utf-8 -*-
import optparse
from socket import *

class bcolors:
    HEADER = '\033[95m'
    OKBLUE = '\033[94m'
    OKGREEN = '\033[92m'
    WARNING = '\033[93m'
    FAIL = '\033[91m'
    ENDC = '\033[0m'

def connScan(tgtHost, tgtPort):
    try:
        connSkt = socket(AF_INET, SOCK_STREAM)
        connSkt.connect((tgtHost, tgtPort))
        connSkt.send('Ehlo \n')
        results = connSkt.recv(100)
        print bcolors.OKGREEN + '[+]%d/tcp open' % tgtPort + bcolors.ENDC
        print bcolors.OKBLUE + '[+] ' + str(results) + bcolors.ENDC
        connSkt.close()
    except:
        print bcolors.FAIL + '[-]%d/tcp closed' % tgtPort + bcolors.ENDC

def portScan(tgtHost ,tgtPorts):
    try:
        tgtIP = gethostbyname(tgtHost)
    except:
        print bcolors.FAIL + "[-] Cannot resolve '%s': Unknown host" % tgtHost + bcolors.ENDC
        return
    try:
        tgtName = gethostbyaddr(tgtIP)
        print bcolors.OKGREEN + "\n[+] Scan Results for: " + tgtName[0] + bcolors.ENDC
    except:
        print bcolors.OKGREEN + '\n[+] Scan Results for: ' + tgtIP + bcolors.ENDC
    setdefaulttimeout(1)
    for tgtPort in tgtPorts:
        print bcolors.HEADER + 'Scanning port ' + tgtPort + bcolors.ENDC
        connScan(tgtHost, int(tgtPort))

def main():
    parser = optparse.OptionParser('usage %prog -H <target host> -p <target port>')
    parser.add_option('-H', dest='tgtHost', type='string', help='specify target host')
    parser.add_option('-p', dest='tgtPort', type='string', help='specify target port')
    (options, args) = parser.parse_args()
    tgtHost = options.tgtHost
    tgtPort = str(options.tgtPort).split(',')
    if(tgtHost == None) | (tgtPort[0] == None):
        print parser.usage
        exit(0)
    portScan(tgtHost, tgtPort)
if __name__ == "__main__":
    main()


