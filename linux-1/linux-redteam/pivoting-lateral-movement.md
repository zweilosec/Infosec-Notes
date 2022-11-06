# Pivoting/Lateral Movement

{% hint style="success" %}
Hack Responsibly.

Always ensure you have **explicit** permission to access any computer system **before** using any of the techniques contained in these documents. You accept full responsibility for your actions by applying any knowledge gained here.
{% endhint %}

Not much here yet...please feel free to contribute at [https://www.github.com/zweilosec](https://github.com/zweilosec)

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
