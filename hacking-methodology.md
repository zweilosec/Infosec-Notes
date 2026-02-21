# Hacking Methodology

{% hint style="success" %}
Hack Responsibly.

Always ensure you have **explicit** permission to access any computer system **before** using any of the techniques contained in these documents.  You accept full responsibility for your actions by applying any knowledge gained here. &#x20;
{% endhint %}

{% hint style="danger" %}
Not much here yet...please feel free to contribute at [my GitHub page](https://github.com/zweilosec/Infosec-Notes).
{% endhint %}

## MITRE ATT\&CK

{% embed url="https://attack.mitre.org" %}

| [Initial Access](https://attack.mitre.org/tactics/TA0001) | [Execution](https://attack.mitre.org/tactics/TA0002) | [Persistence](https://attack.mitre.org/tactics/TA0003) | [Privilege Escalation](https://attack.mitre.org/tactics/TA0004) | [Defense Evasion](https://attack.mitre.org/tactics/TA0005) | [Credential Access](https://attack.mitre.org/tactics/TA0006) | [Discovery](https://attack.mitre.org/tactics/TA0007) | [Lateral Movement](https://attack.mitre.org/tactics/TA0008) | [Collection](https://attack.mitre.org/tactics/TA0009) | [Command and Control](https://attack.mitre.org/tactics/TA0011) | [Exfiltration](https://attack.mitre.org/tactics/TA0010) | [Impact](https://attack.mitre.org/tactics/TA0040) |
| --------------------------------------------------------- | ---------------------------------------------------- | ------------------------------------------------------ | --------------------------------------------------------------- | ---------------------------------------------------------- | ------------------------------------------------------------ | ---------------------------------------------------- | ----------------------------------------------------------- | ----------------------------------------------------- | -------------------------------------------------------------- | ------------------------------------------------------- | ------------------------------------------------- |

### Categories

The hacking methodology categories align with the enterprise attack tactics in the MITRE ATT\&CK matrix. The categories are:

* **Initial access** - Gaining initial entry to the target network, usually involving password-guessing, exploits, or phishing emails
* **Execution** - Launching attacker tools and malicious code, including RATs and backdoors
* **Persistence** - Creating autostart extensibility points (ASEPs) to remain active and survive system restarts
* **Privilege escalation** - Obtaining higher permission levels for code by running it in the context of a privileged process or account
* **Defense evasion** - Avoiding security controls by, for example, turning off security apps, deleting implants, and running rootkits
* **Credential access** - Obtaining valid credentials to extend control over devices and other resources in the network
* **Discovery** - Gathering information about important devices and resources, such as administrator computers, domain controllers, and file servers
* **Lateral movement** - Moving between devices in the target network to reach critical resources or gain network persistence
* **Collection** - Locating and collecting data for exfiltration
* **Command and control** - Connecting to attacker-controlled network infrastructure to relay data or receive commands
* **Exfiltration** - Extracting data from the network to an external, attacker-controlled location

****

## General Methodology

A systematic approach is critical for success at CTFs (and red team engagements!). This methodology outlines the key phases from reconnaissance to post-exploitation.

### Phase 0: Pre-Engagement Setup

Establish a proper working environment before starting:

*   **Create a session log** to track all commands and output

    ```bash
    script $engagement_name_$(date +%Y%m%d_%H%M%S).log
    
    # when finished
    exit
    ```

*   **Use a notetaking program** for organizing findings (Joplin, OneNote, CherryTree, Obsidian, etc.)
    - Document all discovered services, credentials, and vulnerabilities
    - Track successful and failed exploit attempts
    - Note dead-ends and lessons learned
    - Maintain a timeline of actions taken

*   **Set environment variables** for efficiency

Set the Target IP Address to the `$ip` system variable and so on:

    ```bash
    export ip=target_ip
    export subnet=10.10.10.0/24
    export output_dir=./results
    mkdir -p $output_dir
    ```

*   **Create a structured workspace**
    - Separate directories for scans, exploits, payloads, and notes
    - Establish a naming convention for output files with timestamps
    - Keep exploit code and custom tools organized

### Phase 1: Information Gathering & Reconnaissance

Gather passive and active intelligence about the target.

*   **DNS and Domain Information**
    - Query DNS records (A, AAAA, MX, TXT, CNAME)
    - Perform reverse DNS lookups
    - Search WHOIS information
    - Identify subdomains and DNS servers

*   **Network Range Discovery** (if applicable)
    - Identify target network ranges
    - Determine network size and structure
    - Note any public IP addresses or ranges

*   **Host Discovery** on the target network (see [Basic Initial Enumeration](basic-enumeration.md#host-discovery))
    ```bash
    # ARP-based discovery (stealthier on local networks)
    nmap -sn -PR -v $subnet
    
    # ICMP-based discovery
    nmap -sn -PE -PP -PS22,80,443 -v $subnet
    
    # Save results to file
    nmap -sn $subnet -oN $output_dir/hosts.txt
    ```

### Phase 2: Scanning and Enumeration

Systematically identify services and gather detailed information about each target.

*   **Initial Port Scanning** (Two-stage approach)

    **Stage 1: Quick all-port scan**
    ```bash
    # Fast scan to identify open ports
    nmap -Pn -n -p- --min-rate=1000 -T4 $ip -oN $output_dir/ports.txt
    
    # For multiple hosts
    nmap -Pn -n -p- --min-rate=1000 -T4 -iL $output_dir/hosts.txt -oA $output_dir/allports
    ```

    **Stage 2: Detailed service enumeration**
    ```bash
    # Extract open ports and run detailed scan
    ports=$(grep "^[0-9]" $output_dir/ports.txt | cut -d '/' -f1 | tr '\n' ',' | sed 's/,$//')
    
    # Comprehensive service fingerprinting
    nmap -vvv -Pn -n -p $ports -sCV -A --version-all \
      --script vuln,discovery $ip -oA $output_dir/services
    ```

*   **For Every Open Port/Service:**
    - Identify the service name and version
    - Research known vulnerabilities (CVE databases)
    - Note configuration issues or weak settings
    - Perform banner grabbing to retrieve service information
    - Document default credentials for the service
    - Check for common misconfigurations

*   **Protocol-Specific Enumeration**

    - **HTTP/HTTPS**: Directory enumeration, certificate analysis, technology fingerprinting
    - **SMB (445/139)**: Share enumeration, user enumeration, OS detection
    - **SSH (22)**: Key exchange algorithms, supported auth methods
    - **DNS (53)**: Zone transfers, DNS records, server information
    - **SNMP (161)**: Community strings, system information
    - **FTP (21)**: Anonymous access, version information
    - **RDP (3389)**: BlueKeep and other RDP vulnerabilities
    - **Databases (3306, 5432, 1433, 27017)**: Default credentials, configuration

*   **Research Every Finding**
    - Google unknown services and programs
    - Search for error messages and stack traces
    - Research URL paths and parameters for application versions
    - Check Exploit-DB and CVE databases for versions
    - Review GitHub for public exploits and proof-of-concepts

    ```bash
    # Use searchsploit for quick vulnerability lookup
    searchsploit -u  # Update database
    searchsploit "service_name version"
    
    # Check multiple sources
    # - exploit-db.com
    # - cvedetails.com
    # - packetstormsecurity.com
    ```

### Phase 3: Vulnerability Assessment

Analyze findings to identify exploitable weaknesses.

*   **Catalog all vulnerabilities**
    - Severity and exploitability rating
    - CVSS score and impact
    - Requirements (authentication, network access)
    - Proof-of-concept availability

*   **Automated vulnerability scanning** (supplementary)
    ```bash
    # Nmap vulnerability scanning
    nmap -p $ports --script vuln $ip
    
    # Metasploit auxiliary scans
    msfconsole -q -x "use auxiliary/scanner/smb/smb_version; set RHOSTS $ip; run"
    ```

*   **Prioritize targets**
    - Unauthenticated remote code execution (highest priority)
    - Authentication bypasses or weak credentials
    - Privilege escalation vectors
    - Information disclosure vulnerabilities
    - Denial of service (lower priority in most engagements)

### Phase 4: Exploitation & Initial Access

Develop and execute exploits to gain initial system access.

*   **Identify exploit candidates**
    - Search for public exploits matching discovered versions
    - Evaluate reliability and compatibility with target
    - Test exploits in lab environment if possible
    - Modify exploits as needed for target environment

*   **Exploitation strategies**
    - Start with easiest/most reliable exploits first
    - Try default credentials before brute force
    - Test unauthenticated exploits before authenticated ones
    - Document all exploitation attempts (successes and failures)

*   **Example exploitation flow**
    ```bash
    # 1. Default credentials
    ssh admin@$ip  # Try common defaults: admin/admin, root/root, etc.
    
    # 2. Known service vulnerability
    searchsploit "service" | grep -i "RCE\|remote"
    
    # 3. Metasploit exploitation
    msfconsole
    > search "service"
    > use exploit/path/to/exploit
    > set RHOSTS $ip
    > set LHOST attacker_ip
    > set LPORT listening_port
    > exploit
    
    # 4. Custom exploitation
    # Develop or adapt exploit code for the target
    python exploit.py -t $ip -p port
    ```

*   **Maintain multiple access methods**
    - Create backup shells/backdoors for reliability
    - Establish persistent reverse shells
    - Document all credentials and access points

### Phase 5: Post-Exploitation & Enumeration

Once initial access is obtained, perform thorough system enumeration.

*   **Identify system information**
    ```bash
    # Linux
    uname -a
    cat /etc/os-release
    whoami && id
    hostname
    
    # Windows
    systeminfo
    whoami
    ver
    ```

*   **Discover local privilege escalation vectors** (see [Privilege Escalation](#Phase-6-Privilege-Escalation))
    - Kernel vulnerabilities
    - Weak file permissions
    - Sudo misconfigurations
    - Scheduled tasks/cron jobs
    - SUID/SGID binaries
    - Writable system files
    - Installed applications with known vulnerabilities

*   **Enumerate network information**
    ```bash
    # Network configuration
    ip addr / ipconfig
    ip route / route print
    arp -a
    
    # Network connections
    netstat -tulpn / netstat -ano
    ss -tulpn
    
    # Firewall rules
    iptables -L / Get-NetFirewallRule
    ```

*   **Discover other users and accounts**
    ```bash
    # Linux: local users
    cat /etc/passwd
    cat /etc/sudoers
    
    # Windows: local users  
    net user
    whoami /groups
    ```

### Phase 6: Privilege Escalation

Escalate from current user to higher privilege level (root/SYSTEM), or laterally (to a domain user, etc.).

Privilege escalation is all about:

* Collecting - Enumeration, more enumeration, and some more enumeration.
* Processing - Sort through data, analyze, and prioritize.
* Searching - Know what to search for and where to find the exploit code.
* Adapting - Customize the exploit so it fits. Not every exploit works for every system "out of the box".
* Trying - Get ready for (lots of) trial and error.

*   **Collecting** - Extensive enumeration of system configuration
    - Run automated tools: `linpeas.sh`, `winpeas.exe`, `privilege-escalation-awesome-scripts-suite`
    - Manually check weak configurations
    - Review application configurations for hardcoded credentials

*   **Processing** - Analyze and prioritize findings
    - Identify which vulnerabilities are exploitable in this environment
    - Consider dependencies and access requirements
    - Rank by reliability and speed

*   **Searching** - Locate exploit code
    - `searchsploit` for kernel exploits
    - GitHub for application-specific privilege escalation
    - Exploit-DB and SecurityFocus
    - Adapt existing code for target environment

*   **Adapting** - Customize exploit code
    - Compile for correct architecture and OS version
    - Adjust hardcoded paths and parameters
    - Bypass security measures (ASLR, DEP, etc.)

*   **Trying** - Execute and iterate
    - Expect multiple failures before success
    - Document what works and what doesn't
    - Learn from failures for future attempts

### Phase 7: Lateral Movement

Extend access to other systems on the network.

*   **Identify network topology and targets**
    - Scan from compromised host (may have different network views)
    - Enumerate network shares and accessible systems
    - Identify high-value targets (domain controllers, file servers, admin systems)

*   **Credential harvesting**
    - Extract cached credentials from memory
    - Search for credential files and configuration
    - Crack hashes if obtained
    - Perform pass-the-hash or pass-the-ticket attacks

*   **Establish pathways**
    - Create proxy/pivot chains to reach isolated networks
    - Use tools: `chisel`, `sshuttle`, `proxychains`, `plink`, `fpipe`
    - Maintain multiple access routes for redundancy

*   **Propagate access**
    - Deploy agents on newly compromised systems
    - Establish persistent backdoors
    - Create rogue accounts for future access

### Phase 8: Data Collection & Exfiltration

Locate, collect, and extract sensitive data from the network.

*   **Data discovery**
    - Identify files with keywords (password, config, secret, key, etc.)
    - Search user directories and common storage locations
    - Check database contents
    - Review email and communications

*   **Data exfiltration methods**
    - File transfer protocols (SCP, FTP, SFTP)
    - Encrypted channels (SSH tunnels, VPN)
    - Cloud services (if permitted)
    - DNS tunneling or other stealthy methods
    - Out-of-band channels (email, web requests with encoded data)

### Phase 9: Cleanup & Documentation

Remove artifacts and revert changes, as well as document all actions taken.

*   **Artifact removal**
    - Delete uploaded tools and scripts
    - Delete artifacts from temp directories
    - Remove created accounts
    - Uninstall backdoors (if required by rules)
    - Clean registry/system files (Windows)


*   **Documentation**
    - Document all actions taken
    - Provide timeline for incident response
    - List all system and data modifications
    - Recommend remediation steps


If you like this content and would like to see more, please consider [buying me a coffee](https://www.buymeacoffee.com/zweilosec)!
