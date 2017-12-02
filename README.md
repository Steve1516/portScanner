# port_scan

---------------------------------------
## port_scan based on socket


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
