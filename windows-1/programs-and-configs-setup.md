---
description: >-
  A collection of useful programs and configurations for getting your home box
  set up for pre-engagement use.
---

# System Hardening and Useful Programs

## Hardening the OS

TODO: Pull more info from these and move to resources section

"The best way to create a secure Windows workstation is to download the Microsoft Security Compliance Manager" https://technet.microsoft.com/en-us/solutionaccelerators/cc835245.aspx

- DoD STIG: http://iase.disa.mil/stigs/os/windows
- DoD Windows 10 Secure Host Baseline files: https://github.com/iadgov/Secure-Host-Baseline 
- Australian Information Security Manual: http://www.asd.gov.au/infosec/ism/index.htm
- CIS Benchmarks: https://benchmarks.cisecurity.org/downloads/browse/?category=benchmarks.os.windows
- https://blogs.technet.microsoft.com/secguide/2016/01/22/new-tool-policy-analyzer/
- https://docs.microsoft.com/en-us/archive/blogs/secguide/security-baseline-final-for-windows-10-v1903-and-windows-server-v1903
- https://support.microsoft.com/en-us/help/2458544/the-enhanced-mitigation-experience-toolkit
- https://www.microsoft.com/en-us/download/details.aspx?id=55319 Microsoft Security Compliance Toolkit 1.0
- https://adsecurity.org/?p=3299 <- this is good
- https://www.microsoft.com/en-us/download/details.aspx?id=25250 Group Policy Settings Reference for Windows and Windows Server
- https://www.microsoft.com/en-in/download/details.aspx?id=52630 Windows 10 and Windows Server 2016 security auditing and monitoring reference  
- https://docs.microsoft.com/en-us/powershell/scripting/samples/sample-scripts-for-administration?view=powershell-7

### Disable unused services

Disable WinRM, RDP, etc if not used
Disable Wifi-sense
disable cortana

#### Disable PowerShell v2.0
https://adsecurity.org/?p=3299 (with recommended event IDs to audit)
https://windowsloop.com/disable-powershell-v2/
Run as Administrator: `Disable-WindowsOptionalFeature -Online -FeatureName MicrosoftWindowsPowerShellV2Root`
or-
1. First, open the start menu, search for "Turn Windows features on or off" and click on the result to open the Optional Windows Features.
2. In this window, scroll down until you see the "Windows PowerShell 2.0" option. Uncheck the corresponding checkbox and click on the "Ok" button to save changes.

#### Disable Command Prompt
https://windowsloop.com/steps-to-disable-command-prompt/
Via Group Policy:
1. First, open the Start Menu, search for "Edit Group Policy' and click on the search result to open the Group Policy Editor.
2. After opening the group policy editor, go to the following folder on the left panel.
User Configuration → Administrative Templates → System
3. On the right panel, find and double-click on the "Prevent access to the Command Prompt" policy.
4. As soon as you double-click, a policy properties window will open. Here, select the "Enabled" radio option. If you want to restrict users from running any kind of CMD or BAT file, select "Yes" from the drop-down menu under the "Options" section.
5. Click "Apply" and "Ok" buttons to save changes.
6. Close the Group Policy Editor and reboot Windows to make the changes take effect.
Via Regedit
1. First, open the start menu, search for "Registry Editor" and click on the first result to open the Windows Registry Editor.
2. Now, copy the below path, paste it in the address bar and press Enter. This action will take you to the target folder.
HKEY_CURRENT_USER\Software\Policies\Microsoft\Windows\
3. Now, right-click on the "Windows" folder and select "New → Key".
4. Name the new folder as "System" and press Enter to confirm it.
5. Select the System folder, right-click on the right panel and select the "New → Dword value" option.
6. Name the new value as "DisableCMD" and press Enter to confirm it.
7. Double-click on the newly created value. In the Edit Value window, set the value data as follows and click on the "Ok" button to save changes.
 - 1 - To disable Command Prompt and CMD and BAT script execution
 - 2 - To disable Command Prompt only and allow script execution
8. Close the registry editor and reboot Windows.

#### Disable Link Local Multicast Name Resolution (LLMNR) and NetBIOS Name Service (NBT-NS)

Disabling LLMNR:
 1. Open the Group Policy Editor in your version of Windows
 2. Navigate to Local Computer Policy > Computer Configuration > Administrative Templates > Network > DNS Client
 3. Under DNS Client, make sure that "Turn OFF Multicast Name Resolution" is set to Enabled
Disabling NBT-NS:
 1. Open your Network Connections and view the properties of your network adapter.
 2. Select Internet Protocol Version 4 (TCP/IPv4) and click on Properties.
 3. On the General tab click Advanced and navigate to the WINS tab, then select “Disable NetBIOS over TCP/IP.
 
### Permission, Privileges, and Access Control

Disable and rename Guest, Administrator accounts

#### Cached Credentials:
HKEY_LOCAL_MACHINE\Software\Microsoft\WindowsNT\Current Version\Winlogon\ as CachedLogonsCount (set to 0 to disable cached login credentials)
#### Disable LM/NTLM hashes:
HKLM\SYSTEM\CurrentControlSet\Control\Lsa\LMCompatibilityLevel. The LMCompatibilityLevel option takes a value between 0-5, but only a value of 5 will only allow NTLMv2 authentication while refusing any LM and NTLM requests. You must restart Windows to make changes to this entry effective.
#### Disable "Debug Programs" User Right 
Security SEttings>Local Policies>User Rights Assignment
#### Smart Card and Kerberos 
Think about using smart card rather than passwords.  However, smart card information is stored in a similar way to passwords. If smart cards are required for login, the DC will create a random password for that card, hash it, and store it in the user object.  These credentials would then be used by the computer to login silently to computers, whenever they are unreachable using Kerberos.   

### Reduce Privacy Disclosures

disable location, telemetry, etc
https://www.zdnet.com/article/how-to-secure-windows-10-the-paranoids-guide/

### Sandboxing

#### Sandboxie
Sandboxie is now FOSS
https://www.sandboxie.com/
https://github.com/sandboxie/sandboxie
32-bit download (last pre-compiled version)
https://www.sophos.com/Pages/DownloadRedirect.aspx?downloadKey={F42ECFD5-66C4-4A3E-B209-6A8C6AA7ABAF}
64-bit download (last pre-compiled version)
https://www.sophos.com/Pages/DownloadRedirect.aspx?downloadKey={F42ECFD5-66C4-4A3E-B209-6A8C6AA7ABAF}

#### Windows WDAG Browser
https://www.pcworld.com/article/3269280/how-microsoft-edges-hidden-wdag-browser-lets-you-surf-the-web-securely.html
WDAG Browser
You can’t import Favorites. Nor can you cut and paste a URL from another, non-WDAG window—or from a WDAG window to anywhere else.
Most downloads are currently blocked. 
Extensions are disabled.
WDAG doesn’t offer any way of blocking ads, so there’s still the possibility that you’ll see a deceptive ad, or one that takes you to a website where you’re encouraged to enter personal information. All WDAG does is secure the browser window.
Note that the October 2018 Update allows you to download files, and print, and cut and paste URLs in and out of WDAG, if you enable them via the Settings, above.

## HIDS and NIDS Monitoring

### Enable and monitor Sysmon
Microsoft’s Sysmon is a tool that monitors systems and adds granular events to be tracked even after a reboot.
https://github.com/darkoperator/Posh-Sysmon
https://www.darkoperator.com/blog/2017/2/17/posh-sysmon-powershell-module-for-creating-sysmon-configuration-files



Have a script monitor the antivirus process, restart the process if it is stopped and report the incident 

https://www.csoonline.com/article/3148823/10-essential-powershell-security-scripts-for-windows-administrators.html

## Recommended Programs

https://ninite.com

notepad++

Visual Studio Code

Tor Browser - based on Firefox.  Be careful of settings and extensions used as these can break the protection provided by the VPN.  

## Misc
Disable Windows Legacy & Typically Unused Features 

Disable Net Session Enumeration (NetCease)

Disable WPAD

Disable LLMNR

Disable Windows Browser Protocol

Disable NetBIOS

Disable Windows Scripting Host (WSH) & Control Scripting File Extensions

Deploy security back-port patch (KB2871997).

Prevent local Administrator (RID 500) accounts from authenticating over the network

Ensure WDigest is disabled

Remove SMB v1 support

## Resources

- https://resources.infosecinstitute.com/category/certifications-training/securing-windows-ten/windows-10-hardening-techniques/
- https://www.bleepingcomputer.com/forums/t/727921/i-tried-to-harden-my-windows-10-home-with-group-policy-plus-and-i-need-help/
- https://cccsecuritycenter.org/remediation/llmnr-nbt-ns
- https://www.sans.org/reading-room/whitepapers/testing/pass-the-hash-attacks-tools-mitigation-33283
