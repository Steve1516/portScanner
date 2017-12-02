import optparse

from socket import *

from threading import *

screenLock = Semaphore(value=1)

def connScan(tgtHost, tgtPort):
    try:
        connSkt = socket(AF_INET, SOCK_STREAM)
        connSkt.connect((tgtHost, tgtPort))
        screenLock.acquire()
        print('[+] %d/tcp open'%tgtPort)
    except:
        pass
    finally:
        screenLock.release()
        connSkt.close()

def portScan(tgtHost, tgtPorts):
    try:
        tgtIP = gethostbyname(tgtHost)
    except:
        print('[-] Connot reslove %s : Unknow Host'%tgtHost)
        return
    try:
        tgtName = gethostbyaddr(tgtIP)
        print('\n[+] Scan Results for : ' + tgtName[0])
    except:
        print('\n[+] Scan Results for : ' + tgtIP)

    setdefaulttimeout(1)

    if (tgtPorts[0] == '0'):
        for all_port in range(1, 65536):
            t = Thread(target=connScan, args=(tgtHost, int(all_port)))
            t.start()
    else:
        for tgtPort in tgtPorts:
            t = Thread(target=connScan, args=(tgtHost, int(tgtPort)))
            t.start()


def main():
    parser = optparse.OptionParser('Usage %prog -H <target HOST> -p <target PORT>')
    parser.add_option('-H', dest='tgtHost', type='string', help='specify target host')
    parser.add_option('-p', dest='tgtPort', type='string', help='specify target port[s] separated by \',\'(and 0 for 1-65535) ')

    (options, args) = parser.parse_args()
    tgtHost = options.tgtHost
    tgtPorts = str(options.tgtPort).split(',')

    if (tgtHost == None) | (tgtPorts[0] == None):
        print('[-] You must specify a target host and port[s]!' + ' [*]Help: ' + parser.usage)
        exit(0)

    portScan(tgtHost, tgtPorts)

    print('Scan Finish!')

if __name__ == '__main__':
    main()
