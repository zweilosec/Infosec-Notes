# Pivoting

{% hint style="success" %}
Hack Responsibly.

Always ensure you have **explicit** permission to access any computer system **before** using any of the techniques contained in these documents. You accept full responsibility for your actions by applying any knowledge gained here.
{% endhint %}

## PORT FORWARDING ("port to port")

### Using Metasploit

Target: Most platforms

If you get a meterpreter session on a dual homed machine, or one with multiple network interfaces.

```bash
portfwd add -l 4445 -p 4443 -r 10.1.1.1
# Use -R to make it reverse
```

### Using PLINK

Target: Windows

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

## Public key Authentication

With OpenSSH, the authorized keys are by default configured in `.ssh/authorized_keys` in the user's home directory. Many OpenSSH versions also look for `ssh/authorized_keys2`.

You are able to [add options to the authorized key file](https://www.ssh.com/academy/ssh/authorized-keys-openssh#format-of-the-authorized-keys-file)

Example `authorized_keys` file to allow only port forwarding with no shell access

```bash
command="echo 'This account is only for port forwarding!'",from="10.10.0.1,10.10.0.2",no-user-rc,no-agent-forwarding,no-X11-forwarding,no-pty ssh-$keyType $publicKey
```

`command="cmd"` - Forces a command to be executed when this key is used for authentication. This is also called command restriction or forced command. The effect is to limit the privileges given to the key, and specifying this options is often important for implementing the principle of least privilege. Without this option, the key grants unlimited access as that user, including obtaining shell access.

It is a common error when configuring SFTP file transfers to accidentally omit this option and permit shell access.

`from="pattern-list"` - Specifies a source restriction or from-stanza, restricting the set of IP addresses or host names from which the reverse-mapped DNS names from which the key can be used.

The patterns may use \* as wildcard, and may specify IP addresses using \* or in CIDR address/masklen notation. Only hosts whose IP address or DNS name matches one of the patterns are allowed to use the key.

More than one pattern may be specified by separating them by commas. An exclamation mark ! can be used in front of a pattern to negate it.

`no-pty` - Prevents allocation of a pseudo-tty for connections using the key.

`no-user-rc` - Disables execution of .ssh/rc when using the key.

`no-x11-forwarding` - Prevents X11 forwarding.

## References

* [https://notes.benheater.com/books/network-pivoting/page/ssh-port-forwarding](https://notes.benheater.com/books/network-pivoting/page/ssh-port-forwarding)
* [https://iximiuz.com/en/posts/ssh-tunnels/](https://iximiuz.com/en/posts/ssh-tunnels/)
* [https://ironhackers.es/en/cheatsheet/port-forwarding-cheatsheet/](https://ironhackers.es/en/cheatsheet/port-forwarding-cheatsheet/)
* [https://github.com/haad/proxychains](https://github.com/haad/proxychains)
* [https://0xdf.gitlab.io/2019/01/28/pwk-notes-tunneling-update1.html](https://0xdf.gitlab.io/2019/01/28/pwk-notes-tunneling-update1.html)
* [https://thegreycorner.com/2021/12/15/hackthebox\_dante-review.html](https://thegreycorner.com/2021/12/15/hackthebox\_dante-review.html)
* [https://github.com/t3l3machus/pentest-pivoting](https://github.com/t3l3machus/pentest-pivoting)
* [https://serverfault.com/questions/361794/with-ssh-only-reverse-tunnel-web-access-via-ssh-socks-proxy](https://serverfault.com/questions/361794/with-ssh-only-reverse-tunnel-web-access-via-ssh-socks-proxy)
* [https://www.offensive-security.com/metasploit-unleashed/proxytunnels/](https://www.offensive-security.com/metasploit-unleashed/proxytunnels/)
* [https://www.cobaltstrike.com/blog/howto-port-forwards-through-a-socks-proxy/](https://www.cobaltstrike.com/blog/howto-port-forwards-through-a-socks-proxy/)
* [https://materials.rangeforce.com/tutorial/2020/03/16/Proxychains/](https://materials.rangeforce.com/tutorial/2020/03/16/Proxychains/)
* [https://medium.com/geekculture/forwarding-burp-suite-traffic-through-socks-proxy-bada1124341c](https://medium.com/geekculture/forwarding-burp-suite-traffic-through-socks-proxy-bada1124341c)
