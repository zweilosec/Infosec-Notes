Basic Initial Enumeration

## Host Discovery

### Using nmap

```
nmap -sn -v -T4 $ip/$mask
```

### Using netdiscover

```
netdiscover -r $ip/$mask
```

### Using ping

tab - windows
```
for /L %i in (1,1,255) do  @ping.exe -n 1 -w 50 10.10.10.%i | findstr TTL
```

tab - linux

```
for x in (1..255); do ping -c 1 -w 50 10.10.10.x | grep TTL
```

Change the IP `10.10.10.` to match the network you are scanning.  This is set up to scan a /24 network by default, and will require some customization to do other size networks.


## Port Enumeration

```bash
ports=$(nmap -Pn -n -p- --min-rate=1000 -T4 10.10.10.189 | grep ^[0-9] | cut -d '/' -f1 | tr '\n' ',' | sed s/,$//)

nmap -vvv -n -p $ports -sC -sV 
```

if need full details scan:
```bash
nmap -vvv --reason -sCV -Pn -A --osscan-guess --version-all -p $ports -oA host.nmap-full
```
