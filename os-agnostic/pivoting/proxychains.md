---
description: Pivoting using Proxychains
---

# Proxychains

## Requirements

Requires installing proxychains on the attacker machine.

## Advantages

* advantage 1
  * subnote
* advantage 2

## References

* [https://github.com/haad/proxychains](https://github.com/haad/proxychains)
* [https://materials.rangeforce.com/tutorial/2020/03/16/Proxychains/](https://materials.rangeforce.com/tutorial/2020/03/16/Proxychains/)
* [https://github.com/t3l3machus/pentest-pivoting](https://github.com/t3l3machus/pentest-pivoting)
* [https://www.hackwhackandsmack.com/?p=1021](https://www.hackwhackandsmack.com/?p=1021)

## To Sort

* [https://cyberdefense.orange.com/fr/blog/etat-de-lart-du-pivoting-reseau-en-2019/](https://cyberdefense.orange.com/fr/blog/etat-de-lart-du-pivoting-reseau-en-2019/)

### Proxychains Pivot

```bash
#  When you have access to a machine, you can use it as pivot to target machines

# Getting known machines
arp -a

# Setup SSH Dynamic on the attacking box
ssh -D <local_port> <user>@<ip>

# Setup proxychains in /etc/proxychains.conf
[ProxyList]
socks5 127.0.0.1 <local_port>

# Reduce timeout in /etc/proxychains.conf to gain speed
tcp_read_time_out 800
tcp_connect_time-out 800

# Then
proxychains...
# Scanning (nmap) can be very long through proxychains
# You can speed it up by using xargs and multithreading
# The main goal is to spread ports between different threads (-P 50)

seq 1 1000 | xargs -P 50 -I{} proxychains -q nmap -p {} -sT -Pn --open -n -T4 --min-parallelism 100 --min-rate 1 --oG proxychains_nmap --append-output $IP_Address

# Unfortunately you can't just run -oA but need the --append-output option to get searchable output
# To find out what ports are open: 
cat proxychains_nmap | grep -A1 "Status"

# The same behavior can be used to scan multiple machines
# The base command
proxychains nmap -sT -T4 --top-ports 20  -oG 10.42.42.0 --open 10.42.42.0/24

# The final combination.  These two could potentially be combined to port scan multiple hosts but is not recommended
seq 1 254 | xargs -P 50 -I{} proxychains nmap --top-ports 20 -sT -Pn --open -n -T4 --min-parallelism 100 --min-rate 1 --oG proxychains_nmap --append-output 192.168.1.{}
```

### Double Pivot Proxychains

```bash
# Pivot 1 using proxychains
ssh -D 1080 user@IP_Network1

# Configure /etc/proxychains to set port 1080
# Pivot 2 using proxychains
proxychains ssh -D 1081 user@IP_Network2

# Configure /etc/proxychains to set port 1081

proxychains nmap...
```

## Proxychains configuration

ProxyChains looks for the configuration file in the following order:

1. SOCKS5 proxy port in environment variable `${PROXYCHAINS_SOCKS5}`
2. File listed in environment variable `${PROXYCHAINS_CONF_FILE}`
3. The `-f configfile_name` argument provided to the proxychains command
4. `./proxychains.conf`
5. `$(HOME_DIRECTORY)/.proxychains/proxychains.conf`
6. `/etc/proxychains.conf`

### Specify proxy on command line

Using number 1 from above, you can see there is no need to exit the config file every time!

```bash
ssh -fN -D 4321 $user@$target
PROXYCHAINS_SOCKS5=4321 proxychains zsh
```
