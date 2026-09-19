Here’s an expanded, blog‑ready version of your post with **brief descriptions for each tool**, **running processes**, and **all previously requested enumeration surfaces**.  
All content is framed for **defensive research, detection engineering, and red‑team emulation**.

---

# 🛡️ **Enumerating Windows Host Security Tools: A Red Team Recon Guide**

Modern Windows hosts often run multiple layers of security tooling—native Microsoft components, third‑party AV/EDR agents, logging frameworks, and vendor‑specific protection modules. For red teamers and detection engineers, enumerating these tools is essential for understanding **visibility**, **detection surfaces**, and **defensive posture**.

---

# **Sysmon (System Monitor)**  
**Description:** Sysmon is a Sysinternals tool that logs detailed system activity (process creation, network connections, image loads, etc.) to the Windows Event Log. Widely used for threat hunting and detection engineering.

### **Running Processes**
- `Sysmon.exe` or `Sysmon64.exe`
- Driver: `SysmonDrv.sys`

### **Files & Folders**
- `C:\Windows\Sysmon.exe`
- `C:\Windows\Sysmon64.exe`
- `C:\Windows\SysmonDrv.sys`
- Config: `C:\Windows\Sysmon.xml` or `C:\ProgramData\Sysmon\config.xml`

### **Registry**
- `HKLM\SYSTEM\CurrentControlSet\Services\Sysmon`
- `HKLM\SYSTEM\CurrentControlSet\Services\SysmonDrv`

### **Service**
- `Sysmon`
- `SysmonDrv`

### **Logs**
- Event Log: `Microsoft-Windows-Sysmon/Operational`

### **Version / Config Check**
```
Sysmon.exe -v
Sysmon.exe -c
```

---

# **Windows Defender (Microsoft Defender Antivirus)**  
**Description:** The built‑in Windows antivirus/antimalware engine providing real‑time protection, cloud‑based scanning, and integration with Windows Security.

### **Running Processes**
- `MsMpEng.exe` (core AV engine)
- `NisSrv.exe` (Network Inspection System)
- `MpCmdRun.exe` (CLI utility)
- `SecurityHealthService.exe` (Windows Security UI backend)

### **Files & Folders**
- `C:\ProgramData\Microsoft\Windows Defender\`
- `C:\Program Files\Windows Defender\`
- Engine: `MpEngine.dll`
- Signatures: `C:\ProgramData\Microsoft\Windows Defender\Definition Updates\`

### **Registry**
- `HKLM\SOFTWARE\Microsoft\Windows Defender`
- `HKLM\SOFTWARE\Microsoft\Windows Defender\Signature Updates`
- `HKLM\SYSTEM\CurrentControlSet\Services\WinDefend`

### **Service**
- `WinDefend`
- `WdNisSvc`
- `Sense` (EDR component)

### **Logs**
- `Microsoft-Windows-Windows Defender/Operational`
- `Microsoft-Windows-Windows Defender/WHC`

### **Version / Signature / Status**
```
Get-MpComputerStatus
```

---

# **Microsoft Security Essentials (Legacy)**  
**Description:** Pre‑Windows 10 antivirus solution, still found on older systems.

### **Running Processes**
- `MsMpEng.exe`
- `NisSrv.exe`

### **Files**
- `C:\Program Files\Microsoft Security Client\`

### **Registry**
- `HKLM\SOFTWARE\Microsoft\Microsoft Security Client`
- `HKLM\SYSTEM\CurrentControlSet\Services\MsMpEng`

### **Service**
- `MsMpEng`
- `NisSrv`

### **Logs**
- `Microsoft Security Client/Operational`

### **Version / Signature**
```
MpCmdRun.exe -GetFiles
MpCmdRun.exe -SignatureUpdate
```

---

# **Kaspersky Endpoint Security**  
**Description:** Enterprise‑grade AV/EDR with strong self‑protection and kernel‑level monitoring.

### **Running Processes**
- `avp.exe` (main service)
- `klnagent.exe` (network agent)
- Drivers: `klflt.sys`, `klhk.sys`

### **Files**
- `C:\Program Files (x86)\Kaspersky Lab\`
- `C:\ProgramData\Kaspersky Lab\`

### **Registry**
- `HKLM\SOFTWARE\KasperskyLab`
- `HKLM\SYSTEM\CurrentControlSet\Services\klflt`
- `HKLM\SYSTEM\CurrentControlSet\Services\klhk`

### **Service**
- `klsvc`
- `klflt`
- `klhk`

### **Logs**
- `C:\ProgramData\Kaspersky Lab\AVP20.x\Logs\`

### **Version**
```
avp.exe --version
```

---

# **Avast Antivirus**  
**Description:** Popular consumer AV with sandboxing, web shield, and strong self‑defense features.

### **Running Processes**
- `AvastSvc.exe`
- `AvastUI.exe`
- `aswEngSrv.exe`
- Drivers: `aswSP.sys`, `aswSnx.sys`

### **Files**
- `C:\Program Files\Avast Software\Avast\`
- `C:\ProgramData\Avast Software\Avast\`

### **Registry**
- `HKLM\SOFTWARE\Avast Software\Avast`
- `HKLM\SYSTEM\CurrentControlSet\Services\aswSP`
- `HKLM\SYSTEM\CurrentControlSet\Services\aswSnx`

### **Service**
- `AvastSvc`
- `aswSP`
- `aswSnx`

### **Logs**
- `C:\ProgramData\Avast Software\Avast\log\`

### **Version**
```
AvastUI.exe /version
```

---

# **Baidu Antivirus (Discontinued)**  
**Description:** Lightweight AV formerly popular in Asia; still encountered on legacy systems.

### **Running Processes**
- `bdservice.exe`
- `bdsvr.exe`

### **Files**
- `C:\Program Files\Baidu Security\`
- `C:\ProgramData\Baidu Security\`

### **Registry**
- `HKLM\SOFTWARE\Baidu Security`
- `HKLM\SYSTEM\CurrentControlSet\Services\bdservice`

### **Service**
- `bdservice`
- `bdsvr`

### **Logs**
- `C:\ProgramData\Baidu Security\log\`

### **Version**
- `HKLM\SOFTWARE\Baidu Security\Version`

---

# **Other Common EDR Agents**

## **CrowdStrike Falcon**
**Description:** Cloud‑native EDR with strong behavioral analytics.

### **Running Processes**
- `CSFalconService.exe`

### **Files**
- `C:\Program Files\CrowdStrike\`

### **Logs**
- `C:\Windows\System32\LogFiles\CrowdStrike\`

---

## **Carbon Black**
**Description:** Behavioral EDR with kernel‑level monitoring.

### **Running Processes**
- `CbDefense.exe`
- `CbSensor.exe`

### **Files**
- `C:\Program Files\CarbonBlack\`

---

## **SentinelOne**
**Description:** Autonomous EDR with AI‑driven prevention and rollback.

### **Running Processes**
- `SentinelAgent.exe`
- `SentinelService.exe`

### **Files**
- `C:\Program Files\SentinelOne\`

---

# **Checking Update Times & Signature Freshness**

### **Windows Defender**
```
Get-MpComputerStatus | select AntivirusSignatureLastUpdated
```

### **Third‑Party AV**
Look for:
- `HKLM\SOFTWARE\<Vendor>\Updates`
- `C:\ProgramData\<Vendor>\Logs\update.log`

---

# **Tamper Protection / Self‑Defense Indicators**

### **Registry Flags**
- `TamperProtection`
- `SelfProtect`
- `EnableSelfDefense`

### **Service Behavior**
- Services that cannot be stopped without kernel privileges  
- Drivers with `Start=0` (BOOT) or `Start=1` (SYSTEM)

---

# **Event Logs Worth Monitoring**

### **Security**
- 4688 — Process creation  
- 4697 — Service installation  
- 7045 — New service installed  

### **Sysmon**
- 1 — Process creation  
- 3 — Network connection  
- 7 — Image loaded  
- 11 — File created  

### **AV/EDR**
Vendor‑specific operational logs under:
```
Applications and Services Logs\
```

