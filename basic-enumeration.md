# Basic Initial Enumeration

This guide covers network enumeration and service discovery techniques for red team operators after gaining initial access to a network. These methods help identify targets and potential attack vectors while minimizing detection.

## Host Discovery

Host discovery identifies active systems on the target network. Methods vary in speed, noise level, and effectiveness depending on network defenses.

### Using nmap (Ping Sweep)

Fast network discovery using ICMP echo requests:

```bash
# Standard ping sweep
nmap -sn -v -T4 $ip/$mask

# Without port verification (faster, less accurate)
nmap -sn -PE -PP -PS21,22,25,80,139,443,445,465,993,995,1433,3306,3389,5985,8080,8443 -PU53 $ip/$mask

# Aggressive, faster scan (louder)
nmap -sn -T5 $ip/$mask
```

**Parameters:**
- `-sn`: Ping scan (no port scan)
- `-PE`: ICMP echo request
- `-PP`: ICMP timestamp request
- `-PS`: TCP SYN to specific ports
- `-PU`: UDP ping

### Using netdiscover (ARP-based)

ARP-based discovery, effective on local networks, harder to detect than ICMP:

```bash
# Standard ARP scan
netdiscover -r $ip/$mask

# Passive discovery (listen for ARP replies, slower but stealthy)
netdiscover -p

# Fast scan with extended range
netdiscover -r $ip/$mask -N
```

### Using ping (Simple but noisy)

Ping sweep through address range:

**Windows:**
```bat
for /L %i in (1,1,255) do @ping.exe -n 1 -w 50 10.10.10.%i | findstr TTL
```

**PowerShell (Windows, more efficient):**
```powershell
$subnet = "10.10.10"
1..254 | ForEach-Object {
  $ip = "$subnet.$_"
  if (Test-Connection -ComputerName $ip -Count 1 -Quiet -TimeoutSeconds 1) {
    Write-Output "$ip is alive"
  }
}
```

**Linux/Bash:**
```bash
for i in {1..254}; do ping -c 1 -w 50 10.10.10.$i | grep TTL && echo "10.10.10.$i is up"; done
```

**Change the IP `10.10.10.` to match the target network.** These examples scan /24 networks; modify the range for different sizes (e.g., `{1..254}` for /24, adjust for /25, /22, etc.).

### Using ARP scan (Stealthier)

ARP is layer 2 and less likely to trigger IDS alerts compared to ICMP:

```bash
# arp-scan for local network
sudo arp-scan -l

# Specific range
sudo arp-scan 10.10.10.0/24

# Verbose with detailed output
sudo arp-scan -v 10.10.10.0/24
```

### Using fping (Efficient parallel pinging)

```bash
# Ping entire subnet
fping -a -g 10.10.10.0/24

# Ping specific range
fping -a -g 10.10.10.1 10.10.10.254
```

**Parameters:**
- `-a`: Show alive hosts only
- `-g`: Generate target list from range


## Port Enumeration and Service Discovery

Port enumeration identifies open services on discovered hosts. Efficient scanning balances speed, accuracy, and stealth.

### Two-Stage Nmap Scanning (Recommended)

**Stage 1: Quick port discovery**
```bash
# Fast all-port scan (identifies open ports)
nmap -Pn -n -p- --min-rate=1000 -T4 10.10.10.189

# For multiple hosts, use parallel scanning
nmap -Pn -n -p- --min-rate=1000 -T4 10.10.10.0/24
```

**Stage 2: Service fingerprinting**
```bash
# Extract open ports into variable
ports=$(nmap -Pn -n -p- --min-rate=1000 -T4 10.10.10.189 | grep ^[0-9] | cut -d '/' -f1 | tr '\n' ',' | sed s/,$//)

# Detailed scan of discovered ports
nmap -vvv -n -p $ports -sC -sV 10.10.10.189
```

**Full details scan (comprehensive enumeration):**
```bash
nmap -vvv --reason -sCV -Pn -A --osscan-guess --version-all -p $ports -oA host.nmap-full 10.10.10.189
```

**Parameters:**
- `-Pn`: Skip ping (assume host is up)
- `-n`: No DNS resolution (faster)
- `-p-`: Scan all 65535 ports
- `--min-rate=1000`: Send at least 1000 packets/sec
- `-T4/-T5`: Timing template (4=aggressive, 5=insane)
- `-sC`: Run default scripts
- `-sV`: Service/version detection
- `-A`: Enable OS detection, version detection, script scanning, traceroute
- `-oA`: Output in all formats (normal, greppable, XML)

### Simple Bash Port Scan Script

Useful when nmap is unavailable:

```bash
#!/bin/bash
target=$1
for port in {1..65535}; do
  (echo >/dev/tcp/$target/$port) >& /dev/null && echo "Port $port is open"
done
```

**Usage:**
```bash
chmod +x portscan.sh
./portscan.sh 10.10.10.189
```

More efficient with timeout:

```bash
#!/bin/bash
target=$1
timeout=1
for port in {1..65535}; do
  timeout $timeout bash -c "echo >/dev/tcp/$target/$port" 2>/dev/null && \
  echo "Port $port is open"
done
```

### Parallel Port Scanning (with GNU Parallel)

For faster scanning across multiple targets:

```bash
# Scan multiple hosts in parallel
echo -e "10.10.10.1\n10.10.10.2\n10.10.10.3" | \
parallel -j 5 "nmap -Pn -p- --min-rate=1000 -T4 {} -oA results_{//} 2>/dev/null"

# Or with xargs
seq 1 254 | xargs -I {} -P 10 nmap -Pn -n -p- --min-rate=1000 -T4 10.10.10.{}
```

### UDP Port Scanning

Many services use UDP; don't forget to enumerate them:

```bash
# SYN scan + UDP scan with service detection
nmap -sS -sU -sV --top-ports=100 10.10.10.189

# Full UDP scan (slower)
nmap -sU --min-rate=1000 10.10.10.189
```

**Common UDP Services:**
- DNS (53)
- DHCP (67/68)
- NTP (123)
- SNMP (161)
- Syslog (514)

## Service Enumeration and Fingerprinting

Once ports are identified, detailed enumeration reveals service information and potential vulnerabilities.

### HTTP/HTTPS Service Enumeration

**Banner grabbing:**
```bash
# Simple HTTP banner
curl -v http://10.10.10.189/ 2>&1 | grep -i "Server:"

# Using netcat
nc -v 10.10.10.189 80
# Then type: GET / HTTP/1.0

# Using nmap scripts
nmap -p 80 --script http-enum 10.10.10.189
nmap -p 443 --script ssl-enum-ciphers 10.10.10.189
```

**Web discovery:**
```bash
# Enumerate web directories
nmap -p 80,443 --script http-enum 10.10.10.189

# Get web server info and headers
curl -I http://10.10.10.189/

# Comprehensive header analysis
curl -v http://10.10.10.189/ 2>&1 | head -20
```

### SMB Service Enumeration (Windows Networks)

**Detect SMB and enumerate shares:**
```bash
# Nmap SMB enumeration
nmap -p 139,445 --script smb-enum-shares,smb-enum-users,smb-os-discovery 10.10.10.189

# Using enum4linux (comprehensive enumeration)
enum4linux -a 10.10.10.189

# SMB null session enumeration
smbclient -L //10.10.10.189 -N

# List shares
smbclient -L \\\\10.10.10.189\\
```

**Using impacket tools:**
```bash
# Get system information
impacket-smbclient -N -L 10.10.10.189

# Enumerate users
impacket-lookupsid 10.10.10.189

# Connect to share (if accessible)
impacket-smbclient //10.10.10.189/share
```

### SSH Service Enumeration

**Banner and version detection:**
```bash
# SSH banner and version
ssh -v 10.10.10.189 2>&1 | head -5

# Nmap SSH enumeration
nmap -p 22 --script ssh-hostkey,ssh2-enum-algos 10.10.10.189

# Get list of supported algorithms
ssh -Q cipher 10.10.10.189
```

### DNS Enumeration

**Discover DNS services and gather information:**
```bash
# Identify DNS server
nmap -p 53 --script dns-brute 10.10.10.189

# Zone transfer attempt
dig @10.10.10.189 example.com axfr

# DNS records enumeration
nslookup
server 10.10.10.189
set type=ANY
domain.com
```

### SNMP Enumeration

**Network information via SNMP:**
```bash
# Detect SNMP
nmap -p 161 --script snmp-sysdescr,snmp-processes,snmp-netstat 10.10.10.189

# SNMP walk with common community string
snmpwalk -c public -v 2c 10.10.10.189

# Enumerate Windows users
snmpwalk -c public -v2c 10.10.10.189 1.3.6.1.4.1.77.1.2.25
```

### RPC and NetBIOS Enumeration

**Identify RPC and NetBIOS services:**
```bash
# NetBIOS name service enumeration
nmap -p 137 --script nbstat 10.10.10.189

# RPC endpoint enumeration
nmap -p 135 --script rpc-grind 10.10.10.189

# Using nbtscan
nbtscan 10.10.10.189
nbtscan 10.10.10.0/24
```

### FTP/SFTP Service Enumeration

**Banner and credential checking:**
```bash
# FTP banner
nmap -p 21 --script ftp-anon,ftp-syst 10.10.10.189

# Check for anonymous FTP
ftp 10.10.10.189
# Login with: anonymous [email]

# SFTP enumeration
nmap -p 22 --script ssh-auth-methods 10.10.10.189
```

### Database Service Enumeration

**MySQL/MariaDB:**
```bash
nmap -p 3306 --script mysql-info,mysql-databases,mysql-users 10.10.10.189

# Direct connection (if credentials obtained)
mysql -h 10.10.10.189 -u root
```

**MSSQL:**
```bash
nmap -p 1433 --script ms-sql-info,ms-sql-tables 10.10.10.189

# Using impacket
impacket-mssqlclient -sa 10.10.10.189
```

**MongoDB:**
```bash
nmap -p 27017 --script mongodb-info 10.10.10.189

mongo 10.10.10.189:27017
```

## Network-Level Service Discovery

### Using Shodan-style Local Enumeration

Gather all service information without external tools:

```bash
# Create comprehensive service inventory
for ip in $(seq 1 254); do
  echo "=== 10.10.10.$ip ==="
  nmap -Pn -p- --min-rate=2000 -T4 10.10.10.$ip 2>/dev/null | grep open
done
```

### Nessus/Vulnerability Scanning (If Available)

For comprehensive vulnerability assessment:

```bash
# Basic safe scan
nessus scan -template "basic" -target 10.10.10.0/24

# Or use OpenVAS (open-source)
openvas-start  # Start OpenVAS services
```

## Operational Security (OPSEC) Considerations

When enumerating networks, balance thoroughness with stealth:

- **Avoid continuous scanning**: Space out scans to avoid detection
- **Use slower timing templates**: `-T2` or `-T3` instead of `-T4`/`-T5` for stealth
- **Randomize scan order**: Use `--randomize-hosts`
- **Scan from legitimate services**: Schedule scans during typical business traffic
- **Monitor logs**: Check for IDS/IPS alerts during your scans
- **Use fragmentation**: nmap's `-f` flag to fragment packets (evades some IDS)
- **Vary user-agents**: Change HTTP user-agent in web enumeration

Example stealthy scan:
```bash
nmap -Pn -n -p- --min-rate=100 -T2 --randomize-hosts --reason 10.10.10.0/24
```

## Quick Reference: Common Ports and Services

| Port | Service | Protocol | Tool |
|------|---------|----------|------|
| 21 | FTP | TCP | ftp, nmap |
| 22 | SSH | TCP | ssh, nmap |
| 23 | Telnet | TCP | telnet, nmap |
| 25 | SMTP | TCP | nmap, nc |
| 53 | DNS | TCP/UDP | dig, nslookup, nmap |
| 80 | HTTP | TCP | curl, nmap |
| 110 | POP3 | TCP | nmap |
| 139 | NetBIOS | TCP | nmap, enum4linux |
| 143 | IMAP | TCP | nmap |
| 443 | HTTPS | TCP | curl, nmap |
| 445 | SMB | TCP | smbclient, enum4linux |
| 3306 | MySQL | TCP | mysql, nmap |
| 3389 | RDP | TCP | rdesktop, nmap |
| 5900 | VNC | TCP | vncviewer, nmap |
| 139 | Netbios | TCP | nmap |
| 1433 | MSSQL | TCP | nmap, impacket |
| 5432 | PostgreSQL | TCP | psql, nmap |


