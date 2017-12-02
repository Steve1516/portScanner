import nmap
import optparse

def nmapScan(tgtHost, tgtPort):
    nm = nmap.PortScanner()
    nm.scan(tgtHost, tgtPort)
    print('[*] Port : %s\tstate : %s' % (tgtPort, nm[tgtHost]['tcp'][int(tgtPort)]['state']))

def main():
    parser = optparse.OptionParser('Usage %prog -H <target HOST> -p <target PORT>')
    parser.add_option('-H', dest='tgtHost', type='string', help='specify target host')
    parser.add_option('-p', dest='tgtPort', type='string',
                      help='specify target port[s] separated by \',\'(and 0 for 1-65535) ')

    (options, args) = parser.parse_args()
    tgtHost = options.tgtHost
    tgtPorts = str(options.tgtPort).split(',')

    if (tgtHost == None) | (tgtPorts[0] == None):
        print('[-] You must specify a target host and port[s]!' + ' [*]Help: ' + parser.usage)
        exit(0)

    for tgtPort in tgtPorts:
        nmapScan(tgtHost, tgtPort)

    print('Scan Finish!')

if __name__ == '__main__':
    main()
