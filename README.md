# port_scan

---------------------------------------
## port_scan based on socket
```Python

import optparse

from socket import *

from threading import *

screenLock = Semaphore(value=1)

def connScan(tgtHost, tgtPort):
    try:
        connSkt = socket(AF_INET, SOCK_STREAM)
        connSkt.connect((tgtHost, tgtPort))
        #connSkt.send('Info Connect\n') #由于系统防护策略，发送此类消息会被提示端口关闭
        #results = connSkt.recv(1024)
        screenLock.acquire()
        print('[+] %d/tcp open'%tgtPort)
        #print('[+] ' + str(results))
    except:
        pass
        #screenLock.acquire()
        #print('[-] %d/tcp closed'%tgtPort)
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


```


```
<运行结果>
E:\CodeProject\PycharmProjects\port_scan>python main.py -H 192.168.0.106 -p 0

[+] Scan Results for : ********  #马赛克
[+] 135/tcp open
[+] 139/tcp open
[+] 443/tcp open
[+] 445/tcp open
[+] 902/tcp open
[+] 912/tcp open
Scan Finish!

```


---------------------------------------
## port_scan based on Python-Nmap

```Python

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

```

```
<运行结果>
E:\CodeProject\PycharmProjects\port_scanNmap>python main.py -H 192.168.0.106 -p 21,22,139,140,339
[*] Port : 21   state : closed
[*] Port : 22   state : closed
[*] Port : 139  state : open
[*] Port : 140  state : closed
[*] Port : 339  state : closed
Scan Finish!

```
