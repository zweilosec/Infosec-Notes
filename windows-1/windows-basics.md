---
description: Windows Fundamentals
---

# Windows Fundamentals

## History and Evolution of Windows

Windows is one of the most widely used operating systems in the world, developed by Microsoft. Its journey as Windows (post MS-DOS) began in the 1980s and has evolved significantly over the decades, introducing groundbreaking features and adapting to the needs of users and businesses.

### **Origins of Windows: From Windows 1.0 to Windows 11**

- **Windows 1.0 (1985):** The first graphical user interface (GUI) for MS-DOS, featuring overlapping windows and basic applications like Calculator and Paint.
- **Windows 3.x (1990-1992):** Introduced better multitasking, improved graphics, and became the first widely adopted version of Windows.
- **Windows 95 (1995):** Marked a major shift with the Start Menu, taskbar, and support for 32-bit applications.
- **Windows 98 (1998):** Improved hardware support, introduced USB support, and integrated Internet Explorer for web browsing.
- **Windows 98 SE (1999):** Enhanced system stability, improved USB support, and added Internet Connection Sharing for home networks.
- **Windows XP (2001):** Built on the NT kernel, it combined stability with a user-friendly interface, becoming one of the most popular versions.
- **Windows XP SP2 (2004):** A landmark update that introduced major security enhancements, including the Windows Firewall and Data Execution Prevention (DEP).
- **Windows 7 (2009):** Focused on performance and usability, it remains a favorite for many users.
- **Windows 8 (2012):** Introduced a touch-friendly interface with the Modern UI (formerly Metro) and the Windows Store, but faced criticism for removing the Start Menu.
- **Windows 8.1 (2013):** Addressed user feedback by reintroducing the Start Button and improving the Modern UI experience.
- **Windows 10 (2015):** Introduced a unified platform across devices and regular updates as a service.
- **Windows 11 (2021):** Modernized the interface with a centered Start Menu, improved multitasking, and enhanced security features.

### **Windows Server Versions**

Microsoft also developed server-specific versions of Windows to cater to enterprise environments, offering features like enhanced security, scalability, and support for server roles.

- **Windows NT Server (1993):** The first server-focused version, built on the NT kernel, offering stability and security for enterprise use.
- **Windows 2000 Server (2000):** Introduced Active Directory, a directory service for managing users, groups, and resources in a networked environment.
- **Windows Server 2003 (2003):** Improved scalability and introduced features like IIS 6.0 and enhanced security tools.
- **Windows Server 2008 (2008):** Added Hyper-V for virtualization, Server Core for minimal installations, and enhanced Active Directory features.
- **Windows Server 2008 R2 (2009):** Built on the Windows 7 kernel, introduced PowerShell 2.0, improved scalability, and enhanced virtualization with features like Live Migration in Hyper-V.
- **Windows Server 2012 (2012):** Focused on cloud integration, introduced the Modern UI, and enhanced virtualization with Hyper-V improvements.
- **Windows Server 2016 (2016):** Introduced Nano Server for lightweight deployments, Windows Containers, and enhanced security features like Shielded VMs.
- **Windows Server 2019 (2018):** Focused on hybrid cloud environments, added support for Kubernetes, and improved security with Windows Defender ATP.
- **Windows Server 2022 (2021):** Enhanced security with Secured-core server, improved hybrid cloud capabilities, and better support for large-scale applications.

### **Key Milestones in Windows Development**

1. **Introduction of the NT Kernel (1993):**
   - Windows NT (New Technology) introduced a robust, secure, and scalable kernel, forming the foundation for all modern Windows versions.
   - It separated user mode and kernel mode, improving system stability and security.

2. **Transition to 64-bit Architecture (2001-2005):**
   - Windows XP Professional x64 Edition and Windows Server 2003 introduced support for 64-bit processors, enabling larger memory addressing and better performance for demanding applications.

3. **Modern Security Enhancements:**
    - **Windows XP SP2 (2004):** Introduced the Windows Firewall, a built-in firewall to block unauthorized network traffic, and Data Execution Prevention (DEP) to prevent certain types of attacks.
    - **Windows Vista (2007):** Introduced User Account Control (UAC) to prevent unauthorized changes, BitLocker for full-disk encryption, and Windows Defender as an anti-spyware tool.
    - **Windows 7 (2009):** Enhanced BitLocker with BitLocker To Go for USB drives and introduced AppLocker to restrict application execution.
    - **Windows 8 (2012):** Introduced Secure Boot to prevent unauthorized operating systems or malware from loading during startup and Windows Defender as a full antivirus solution.
    - **Windows 8.1 (2013):** Improved Secure Boot with additional validation checks, introduced Device Encryption for all editions, and added support for biometric authentication through Windows Hello.
    - **Windows 10 (2015):** Added Windows Defender, Secure Boot, virtualization-based security (VBS), and Credential Guard to protect against credential theft.
    - **Windows 11 (2021):** Enhanced hardware-based security with TPM 2.0, Secure Boot requirements, and improved virtualization-based security features.

### **Comparison of Windows Versions**

This table highlights the evolution of both desktop and server versions of Windows, showcasing how each version introduced innovations to meet the changing demands of technology and users.

| **Version**             | **Release Year** | **Kernel**       | **Key Features**                                                                 | **Target Audience**                  |
|--------------------------|------------------|------------------|----------------------------------------------------------------------------------|---------------------------------------|
| **Windows 1.0**          | 1985             | MS-DOS-based     | Basic GUI, overlapping windows, simple applications like Paint and Calculator.   | Early PC users, hobbyists.           |
| **Windows NT Server**    | 1993             | NT-based         | Enterprise-grade stability and security.                                         | Businesses, enterprises.             |
| **Windows 95**           | 1995             | Hybrid (16/32-bit)| Start Menu, taskbar, Plug and Play support, and 32-bit application support.      | Home and business users.             |
| **Windows 98**           | 1998             | Hybrid (16/32-bit)| Improved hardware support, Internet Explorer integration, and USB support.       | Home and small business users.       |
| **Windows 98 SE**        | 1999             | Hybrid (16/32-bit)| Enhanced USB support, Internet Connection Sharing, and improved system stability.| Home and small business users.       |
| **Windows 2000 Server**  | 2000             | NT-based         | Active Directory, enhanced networking, and scalability.                          | Enterprises, IT administrators.       |
| **Windows XP**           | 2001             | NT-based         | Stable NT kernel, user-friendly interface, and improved networking.              | General users, businesses.           |
| **Windows XP SP2**       | 2004             | NT-based         | Major security enhancements, including a built-in firewall and DEP (Data Execution Prevention). | General users, businesses.           |
| **Windows XP SP3**       | 2008             | NT-based         | Cumulative updates, improved security, and support for WPA2 wireless encryption. | General users, businesses.           |
| **Windows Server 2003**  | 2003             | NT-based         | IIS 6.0, improved scalability, and security tools.                               | Enterprises, hosting providers.       |
| **Windows Vista**        | 2007             | NT-based         | UAC, Aero interface, and improved security features.                             | Security-conscious users, enterprises.|
| **Windows Server 2008**  | 2008             | NT-based         | Hyper-V, Server Core, and enhanced Active Directory.                             | Enterprises, virtualization users.    |
| **Windows Server 2008 R2** | 2009           | NT-based         | Introduced PowerShell 2.0, improved scalability, and enhanced virtualization.    | Enterprises, IT administrators.       |
| **Windows 7**            | 2009             | NT-based         | Performance improvements, taskbar enhancements, and better hardware support.     | General users, gamers, businesses.   |
| **Windows Server 2012**  | 2012             | NT-based         | Cloud integration, Modern UI, and improved virtualization.                       | Cloud-focused enterprises.            |
| **Windows 8**            | 2012             | NT-based         | Touchscreen support, Metro UI, and Windows Store.                                | Tablet users, modern device users.   |
| **Windows 8.1**          | 2013             | NT-based         | Reintroduced Start Button, improved Modern UI, and enhanced multitasking.        | General users, tablet users.         |
| **Windows Server 2016**  | 2016             | NT-based         | Nano Server, Windows Containers, and Shielded VMs.                               | Enterprises, developers.              |
| **Windows 10**           | 2015             | NT-based         | Unified platform, Cortana, Edge browser, and regular updates as a service.       | All users, enterprises, developers.  |
| **Windows Server 2019**  | 2018             | NT-based         | Hybrid cloud support, Kubernetes, and Windows Defender ATP.                      | Hybrid cloud users, enterprises.      |
| **Windows 11**           | 2021             | NT-based         | Modern UI, centered Start Menu, multitasking improvements, and enhanced security.| Modern users, professionals.         |
| **Windows Server 2022**  | 2021             | NT-based         | Secured-core server, hybrid cloud improvements, and large-scale app support.     | Enterprises, cloud-focused users.     |

## Boot and Login

The Windows boot and login process is a detailed sequence of operations that transitions the system from initial power-on to a fully functional desktop environment, ready for user interaction. It begins with firmware initialization, and ends when the user's profile is loaded, startup programs are executed, and the desktop environment is initialized.

### **Step 1: Power-On and Firmware Initialization**

When the system is powered on, the **firmware** (BIOS or UEFI) initializes hardware components and performs a **POST** (Power-On Self Test) to ensure all components are functioning correctly. Next, the firmware initializes and loads either the **UEFI** (*Unified Extensible Firmware Interface*) or **BIOS** (*Basic Input/Ouput System*) into memory. If the system supports UEFI, it can also optionally start the **Secure Boot** process.

  - **BIOS (Legacy):** Typically used on older systems or for compatibility with legacy hardware and software. It identifies bootable devices and loads the Master Boot Record (MBR) from the selected boot device. BIOS is limited to drives up to 2 TB and does not support modern features like Secure Boot or faster boot times.

  - **UEFI (Modern):** Preferred for newer systems due to its advanced capabilities. It loads the bootloader directly from the EFI System Partition (ESP), supporting larger drives (via GPT, or *GUID Partition Table*), faster boot times, and enhanced security features like Secure Boot. UEFI also provides a more user-friendly interface and supports additional features like network booting and graphical menus.

- **Secure Boot (UEFI Only, Optional):**

  - UEFI **Secure Boot** works by verifying the digital signatures of bootloaders and other critical components during the boot process. When the system starts, the UEFI firmware checks the bootloader against a database of trusted certificates stored in the firmware. If the bootloader's signature matches an entry in the database, the boot process continues. Otherwise, the system halts or alerts the user, preventing unauthorized or malicious software from executing.

### **Step 2: Bootloader Execution**

The bootloader is initiated after the firmware (BIOS or UEFI) completes its hardware initialization and selects the bootable device. It is responsible for loading the operating system into memory and preparing the system for execution. On Windows systems, the bootloader, typically `bootmgr` (Windows Boot Manager), reads the Boot Configuration Data (BCD) to determine which operating system to load. It then locates and executes the operating system loader (`winload.exe`)

- **Bootloader Location:**
  - **MBR (Legacy):** Contains the bootloader and partition table, used in BIOS systems. Commonly found on older systems or those requiring compatibility with legacy hardware and software. Windows versions up to and including Windows 7 primarily used MBR by default, although GPT was supported in limited scenarios.

  - **GPT (Modern):** Used with UEFI systems, supporting more partitions and larger drives. Windows Vista was the first version to introduce GPT support, but it became the default for new installations starting with Windows 8 on UEFI-enabled systems. GPT is required for features like Secure Boot and drives larger than 2 TB.

- **Windows Boot Manager (`bootmgr`):**
  - Reads the **Boot Configuration Data** (BCD) to determine which operating system to load.
  - Located in the **EFI System Partition** (ESP) on UEFI systems or the **system partition** on BIOS systems.

- **Fast Startup (Optional):**
  - If enabled, the kernel session and device drivers are loaded from a hibernation file (`hiberfil.sys`) to speed up the boot process.

### **Step 3: Operating System Loader**

`winload.exe` is then started by `bootmgr` (Windows Boot Manager) after it reads the **Boot Configuration Data** (BCD). `winload.exe` is responsible for loading the Windows kernel (`ntoskrnl.exe`), the **Hardware Abstraction Layer** (HAL), and system drivers into memory. Once these components are loaded, `winload.exe` hands over control to `ntoskrnl.exe`, which initializes the core subsystems of the operating system, including the memory manager, process manager, and I/O manager. This process sets the stage for the operating system to take full control of the system and continue the to the session initialization sequence.

- **`winload.exe`:**
  - Responsible for loading the Windows kernel (`ntoskrnl.exe`), the Hardware Abstraction Layer (HAL), and essential system drivers.
  - Reads the Boot Configuration Data (BCD) to determine the system's startup configuration.
  - Prepares the system for kernel execution by initializing memory and loading critical components.

- **Kernel Initialization (`ntoskrnl.exe`):**
  - The kernel initializes core subsystems, including:
    - **Memory Manager:** Manages physical and virtual memory, ensuring efficient allocation and usage.
    - **Process Manager:** Handles process creation, scheduling, and termination.
    - **I/O Manager:** Manages input/output operations, including file systems and device communication.
  - Loads the **Hardware Abstraction Layer (HAL)** (`hal.dll`), which abstracts hardware-specific details, ensuring compatibility across different hardware platforms.
  - Launches the **Windows Executive** for managing system resources and services.
  - Starts essential services and drivers required for system operation.

- **System Call Interface:**
  - Acts as a bridge between user-mode applications and kernel-mode operations.
  - Provides a secure mechanism for user-mode applications to request access to hardware and system resources.
  - Ensures that system calls are executed efficiently and securely, maintaining system stability.

- **Windows Executive:**
  - A collection of kernel-mode components responsible for managing system resources and services.
  - Processes registry configuration data and initializes critical system services and drivers during startup from the **HKEY_LOCAL_MACHINE\SYSTEM** hive, specifically the **CurrentControlSet** key. This key contains essential information about system services, drivers, and hardware configurations required during the startup process.

### **Step 4: Session Initialization**

After the kernel and drivers have been loaded, the system transitions into the session initialization phase. The **Session Manager Subsystem** (`smss.exe`) is the first user-mode process to start, responsible for initializing the system session and creating user sessions. It sets up the environment for critical processes, such as the **Client/Server Runtime Subsystem** (`csrss.exe`, often pronounced '*scissors*'), which manages console windows and threads, **Windows Initialization** (`Wininit.exe`), which initializes system services, and **Windows Logon Application** (`winlogon.exe`), which handles user authentication. During this phase, the system also prepares the registry, initializes virtual memory, and starts essential services, ensuring the operating system is ready for user interaction.

- **Session Manager Subsystem (`smss.exe`):**
  - The first user-mode process started by the kernel.
  - Initializes the system session and user sessions.
  - Starts critical processes like the Client/Server Runtime Subsystem (`csrss.exe`) and the Windows Logon Application (`winlogon.exe`).

- **Client/Server Runtime Subsystem (`csrss.exe`):**
  - Manages graphical and console windows, as well as threads and processes.
  - Provides essential services for user-mode applications.

- **Windows Initialization (`Wininit.exe`):**  
  - Starts immediately after the **Session Manager (`smss.exe`)** completes its tasks.  
  - Responsible for initializing system services, including:
    - **Service Control Manager (`services.exe`)**, which manages Windows services.
    - **Local Security Authority Subsystem (`lsass.exe`)**, which handles authentication and security policies.
    - **Local Session Manager (`lsm.exe`)**, which manages Terminal Server connections.  
  - Runs **only in Session 0** (system processes) and remains active until shutdown.

### **Step 5: User Authentication**

After `wininit.exe` starts, it initializes the Local Security Authority Subsystem Service (`lsass.exe`), which manages authentication and enforces security policies. At this stage, the system also loads credential providers, which handle various authentication methods such as passwords, PINs, biometrics, or smart cards. If the system is domain-joined, `lsass.exe` communicates with a domain controller to validate credentials using protocols like Kerberos or NTLM. Once authentication is successful, the system generates an access token for the user, which defines their permissions and access rights. This process ensures that only authorized users can proceed to the next stage, where their profile is loaded.

- **Windows Logon (`Winlogon.exe`):**  
  - Starts **after Wininit.exe** and is responsible for **handling user authentication**.  
  - Manages **secure user interactions**, including:
    - **Credential collection** via the logon UI.
    - **Passing credentials** to the Local Security Authority (LSA) for validation.
    - **Handling Ctrl+Alt+Del security enforcement**.
    - **Loading the user profile** after authentication.  
  - Runs in **user sessions** and remains active to manage login/logout events.

- **Local Session Manager (`lsm.exe`)** 
  - Starts after `winlogon.exe` and manages local and remote user sessions. 
  - Handles **Terminal Services** and **Remote Desktop Protocol (RDP)** connections.
  - Coordinates **session switching** for multi-user environments.
  - Ensures **proper session isolation** for security.
  - If `lsm.exe` fails to start properly, it can cause login delays or prevent remote desktop connections.

#### **GINA and the Login Screen**

The **Graphical Identification and Authentication (GINA)** module is loaded by `winlogon.exe` before the user is presented with the login screen. GINA is responsible for handling the secure authentication interface, including the login dialog box. It interacts with `lsass.exe` to process user credentials and enforce security policies.

When the system is ready for user interaction, the login screen is displayed. At this point, the user can input their credentials using the available authentication methods provided by the credential providers.

#### **Login Security and Auditing**

- **Secure Attention Sequence (Ctrl+Alt+Delete):**
  - Pressing **Ctrl+Alt+Delete** at the login screen triggers the **Secure Attention Sequence (SAS)**. This sequence ensures that the login interface is presented by the trusted Windows subsystem, preventing malicious programs from mimicking the login screen. SAS is a critical security feature designed to protect against credential theft and unauthorized access.

- **Credential Providers:**
  - Handle user authentication methods such as passwords, PINs, biometrics, or smart cards.
  - Provide flexibility for different authentication mechanisms based on user or organizational requirements.

- **Local Security Authority Subsystem Service (`lsass.exe`):**
  - Manages security policies, user authentication, and access tokens.
  - Supports authentication protocols like Kerberos and NTLM.
  - Communicates with the domain controller (if applicable) to validate credentials.

- **Password Hashing:**
  - User passwords are hashed and stored securely using NTLM or Kerberos.
    - **NTLM** uses the **MD4** hashing algorithm to store password hashes.
    - **Kerberos** (in Active Directory) uses **AES** (Advanced Encryption Standard) for modern systems, but may also use **RC4-HMAC** or **DES** for compatibility with older systems.

- **Domain Authentication (If Applicable):**
  - For domain-joined systems, authentication is performed against a domain controller using Kerberos or NTLM.
  - By default, Windows caches credentials for the last **10** users who have logged in, allowing them to authenticate even if the domain controller is unavailable (this value can be changed via Group Policy).

- **Single Sign-On (SSO):**
  - Enables users to authenticate once and gain access to multiple resources without re-entering credentials.
  - SSO works by using the access token generated during the initial login to authenticate the user to other services and applications seamlessly.
  - Commonly used in enterprise environments to improve user experience and reduce the need for repeated logins.
  - **Kerberos:** Windows domains use the Kerberos protocol as the primary SSO mechanism.
    - After the initial login, Kerberos issues a Ticket Granting Ticket (TGT) that allows users to request service tickets for other resources without re-entering credentials.

- **Account Lockout Policies:**
  - Enforce lockouts after a specified number of failed login attempts to prevent brute-force attacks.
  - By default, Windows does not enable account lockout for local accounts. 
  - In domain environments, the default is typically **10 invalid attempts** within **10 minutes** triggers a lockout for **10 minutes**. These values can be configured via Group Policy under **Account Lockout Policy**.

- **Audit Logs and Login Events:**
  - Login attempts and session activities are logged in the Windows Event Viewer for auditing and troubleshooting.
  - Relevant logs include:
    - **Security Log**: Tracks successful and failed login attempts.
    - **Application Log**: Logs application-specific events.
    - **System Log**: Logs system-level events.

- **AutoLogon (Optional):**
  - AutoLogon allows a system to bypass the login screen and automatically log in a specific user account.
  - This feature is configured by storing the username and password in the registry (encrypted) and is typically used for kiosk systems or environments where user interaction is minimal.
  - **Security Note:** AutoLogon should be used cautiously, as it may expose credentials to unauthorized access if the system is compromised.

Once authentication is successful, the system generates an access token for the user, defining their permissions and access rights. This token is then used to initialize the user session and load the user's profile.

### **Step 6: User Profile Loading**

After the user is authenticated by `lsass.exe`, the system begins the process of initializing the user session. This involves loading the user's profile, which includes settings, preferences, and environment variables stored in the registry and the user's profile directory. Once authentication is successful, `winlogon.exe` starts the process of creating the user session by launching the **Userinit** process (`userinit.exe`). 

- **`userinit.exe`**
  - Responsible for running any login scripts defined in Group Policy or the user's profile.
  - Maps network drives, and initializing other user-specific settings. 
  - Prepares the environment by loading the user's desktop configuration and applying any policies or restrictions defined by administrators. 

- **Profile Initialization:**
  - The user's profile is loaded from the local system or a roaming profile stored on a network share.
  - Includes user-specific settings, files, and registry keys.

- **Group Policy Login Scripts:**
  - Group Policy is a feature in Windows that allows administrators to define and enforce settings for users and computers in an Active Directory environment. During login, Group Policy processes and applies various configurations to ensure compliance with organizational policies.
  - **Key Functions of Group Policy at Login:**
    - **User Configuration:** Applies settings specific to the user, such as desktop backgrounds, Start menu layouts, and folder redirection.
    - **Computer Configuration:** Enforces policies related to the computer, such as security settings, software installations, and power management.
    - **Login Scripts:** Executes scripts (e.g., batch, PowerShell, or VBScript) to automate tasks like mapping network drives, setting environment variables, or launching applications.
    - **Software Deployment:** Installs or updates software packages defined in the Group Policy Object (GPO).
    - **Security Settings:** Enforces password policies, account lockout thresholds, and other security-related configurations.
    - **Registry Modifications:** Applies registry changes to customize system behavior or enforce restrictions.
    - **Drive and Printer Mapping:** Automatically maps network drives and printers based on user or group membership.
    - **Folder Redirection:** Redirects user folders (e.g., Documents, Desktop) to network locations for centralized storage and backup.
    - **Startup Applications:** Launches specific applications or services required for the user's session.
  - **Processing Order:**
    - Group Policy settings are applied in a specific order: **Local Policies → Site Policies → Domain Policies → Organizational Unit (OU) Policies.**
    - If there are conflicts, the last applied policy takes precedence.
    - Administrators can use tools like the Group Policy Management Console (GPMC) or `gpresult` to troubleshoot and verify applied policies.

### **Step 7: Desktop Initialization**

After completing the login tasks, `userinit.exe` launches the Windows shell specified in the registry, typically `explorer.exe`, which provides the graphical user interface including the desktop, taskbar, and Start menu. Additionally, any startup applications configured to run during login are launched. During this phase, the system ensures that the necessary permissions and security policies are applied to the user session, preparing the environment for interaction. Once these tasks are completed, the desktop is fully initialized and ready for use.

- **Windows Shell**
   - The shell setting is a **per-user configuration**, stored in the registry under `HKCU\Software\Microsoft\Windows NT\CurrentVersion\Winlogon\Shell`.
   - The default shell for Windows is **explorer.exe**.

- **Startup Programs:**
  - Applications configured to start automatically are launched. Some of the locations these can be defined in:
    - The `Startup` folder (located at `%APPDATA%\Microsoft\Windows\Start Menu\Programs\Startup` for the current user, or `%ProgramData%\Microsoft\Windows\Start Menu\Programs\Startup` for all users).
    - The `Run` registry keys (`HKCU\Software\Microsoft\Windows\CurrentVersion\Run` for the current user, and `HKLM\Software\Microsoft\Windows\CurrentVersion\Run` for all users).
    - Third-party auto-start managers (e.g., antivirus or hardware utilities) may use their own registry or file-based mechanisms.

  > **Tip:** Tools like Sysinternals Autoruns can enumerate all known auto-start locations for a comprehensive view.

- **Services and Scheduled Tasks:**
  - The Windows registry contains entries for tasks and services that start during login.
  - **Services** are loaded from the registry key: `HKLM\SYSTEM\CurrentControlSet\Services\`
  - **Scheduled Tasks** are defined as XML files in: `%SystemRoot%\System32\Tasks\`
    - **Task metadata and state** are also stored in the registry at: `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\`

- **Session Initialization:**
  - The user's desktop environment is initialized, including the taskbar, Start menu, and system tray.

---

## Windows Services

Windows Services are long-running executable applications that operate in the background and provide core operating system features, application support, and system management capabilities. Unlike regular applications, services can start automatically at boot, run without user interaction, and often have elevated privileges. Examples include networking, printing, security, and update services.

- **Service Control Manager (SCM):** The central component that manages all services. It starts, stops, and monitors services based on configuration and system events.
- **Service Processes:** Services typically run as separate processes or as part of a shared process (e.g., `svchost.exe`).
- **Service Accounts:** Services run under specific accounts that define their permissions:
  - **Local System:** High privileges, can access most system resources.
  - **Network Service:** Limited local privileges, can access network resources as the computer account.
  - **Local Service:** Limited privileges, intended for services that do not need extensive access.
  - **Custom/User Accounts:** Services can be configured to run under specific user accounts for granular control.

### Service Processes

The **Service Control Manager (`services.exe`)** is a critical system process that starts during the **Windows boot process**, specifically after the **Windows Startup Application (`wininit.exe`)** initializes system services. Once `services.exe` is running, it is responsible for **starting, stopping, and managing all Windows services** according to their configured startup type (automatic, delayed, manual, or disabled).

#### How Service Processes Work

- **Service Hosting:**  
  Most Windows services do not run as standalone processes. Instead, they are typically hosted within a generic process called **`svchost.exe`** (*Service Host*). This design allows multiple services to share a single process, reducing resource usage and improving system efficiency.

- **Service Grouping:**  
  Services with similar functions or dependencies are grouped together in a single `svchost.exe` instance. For example, networking-related services may run together in one instance, while system services run in another. The grouping is defined in the Windows registry under `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Svchost`.

- **Process Isolation (Windows 10 and Later):**  
  Starting with Windows 10 (version 1703), Microsoft improved service isolation for better security and reliability. On systems with sufficient memory, **each service may run in its own `svchost.exe` process** rather than being grouped. This change helps prevent a failure or compromise in one service from affecting others, and makes troubleshooting easier by providing a one-to-one mapping between services and processes.

- **Service Accounts:**  
  Services run under specific accounts (such as Local System, Network Service, or Local Service), which determine their permissions and access to system resources.

#### Key Points

- **`services.exe`** manages the lifecycle of all services, including dependency handling and recovery actions.
- **`svchost.exe`** acts as a container for one or more services, reducing overhead and improving management.
- **Windows 10 and later**: More services run in isolated processes for security and stability.
- **Service failures** are logged in the Windows Event Viewer, and recovery actions (restart, run a program, etc.) can be configured per service.

#### View Services Hosted by `svchost.exe`

You can view which services are running under each `svchost.exe` instance using either the GUI (**Task Manager** or Sysinternals **Process Explorer**) or command-line tools.

##### Using Task Manager or Process Explorer (GUI)

- Open **Task Manager** (`Ctrl+Shift+Esc`), go to the **Details** tab, right-click a `svchost.exe` process, and select **Go to Service(s)** to highlight associated services.
- **Process Explorer** (from Sysinternals) provides even more detail: just hover over or expand a `svchost.exe` process to see hosted services.

##### Using the Command Line

{% tabs %}
{% tab title="cmd.exe" %}

**To list all services and their associated processes:**

- **cmd.exe:**
  ```cmd
  :: List all running processes and the services they host (svchost.exe highlighted)
  tasklist /svc /fi "imagename eq svchost.exe"

  :: List all services with their process IDs
  sc queryex type= service

  :: List all services and their status
  sc query type= service
  ```

**To see which services are hosted by a specific `svchost.exe` process:**

- **cmd.exe:**
  ```cmd
  :: Replace <PID> with the svchost.exe process ID
  tasklist /svc /fi "pid eq <PID>"
  ```

{% endtab %}
{% tab title="PowerShell" %}

**To list all services and their associated processes:**

- **PowerShell:**
  ```powershell
  # List all svchost.exe processes with their IDs and paths
  Get-Process -Name svchost | Select-Object Id, ProcessName, Path

  # List all services with their process IDs and service accounts
  Get-WmiObject Win32_Service | Select-Object Name, ProcessId, StartName

  # Combine to see which services are running under each svchost.exe
  Get-WmiObject Win32_Service | Where-Object { $_.ProcessId -ne 0 } | Sort-Object ProcessId | Format-Table Name, ProcessId, StartName
  ```

**To see which services are hosted by a specific `svchost.exe` process:**

- **PowerShell:**
  ```powershell
  # Replace <PID> with the svchost.exe process ID of interest
  Get-WmiObject Win32_Service | Where-Object { $_.ProcessId -eq <PID> } | Select-Object Name, State, StartName
  ```

{% endtab %}
{% endtabs %}

### Service Start Types

Each service has a configured start type that determines when and how it starts. The corresponding registry value is found under `HKLM\SYSTEM\CurrentControlSet\Services\<ServiceName>` in the `Start` value.

| Start Type                | Description                                                    | Registry Value |
|---------------------------|----------------------------------------------------------------|---------------|
| **Automatic**             | Starts at system boot.                                         | `2`           |
| **Automatic (Delayed Start)** | Starts after boot, with a delay to improve startup performance. | `2` + `DelayedAutoStart=1` |
| **Manual**                | Starts only when explicitly requested.                         | `3`           |
| **Disabled**              | Cannot be started until re-enabled.                            | `4`           |

### Service Status Codes

Services can be in various states. The status code is reflected in the `Status` value (if present) or via the Service Control Manager API.

| Status           | Description                         | Registry/SCM Value |
|------------------|-------------------------------------|--------------------|
| **Running**      | Service is active and operational.  | `4`                |
| **Stopped**      | Service is not running.             | `1`                |
| **Paused**       | Service is temporarily suspended.   | `7`                |
| **Start Pending**| Service is in the process of starting. | `2`             |
| **Stop Pending** | Service is in the process of stopping. | `3`             |

> **Note:**  
> - The `Start` value is always in the registry, but the current status is typically managed by the Service Control Manager and not always stored in the registry.  
> - Status codes are most reliably retrieved using `sc query` or PowerShell's `Get-Service`.

### Additional Notes

- **Dependencies:** Some services depend on others; stopping a required service may affect system functionality.
- **Security:** Running services under the least-privileged account necessary reduces security risks.
- **Event Logs:** Service events (start, stop, failures) are logged in the Windows Event Viewer for troubleshooting.

For more details, see Microsoft's official documentation on [Windows Services](https://learn.microsoft.com/en-us/windows/win32/services/) and [svchost.exe](https://learn.microsoft.com/en-us/windows/win32/services/svchost-group).

### Managing Services

{% tabs %}
{% tab title="cmd.exe" %}

#### Using `cmd.exe`

- **List all services:**
  ```cmd
  sc query type= service
  ```
- **Get the status of a specific service:**
  ```cmd
  sc query <ServiceName>
  ```
- **Start a service:**
  ```cmd
  net start <ServiceName>
  ```
- **Stop a service:**
  ```cmd
  net stop <ServiceName>
  ```
- **Change the start type:**
  ```cmd
  sc config <ServiceName> start= auto
  sc config <ServiceName> start= demand
  sc config <ServiceName> start= disabled
  ```
- **Create or delete a service:**
  ```cmd
  sc create <ServiceName> binPath= "C:\Path\To\Executable.exe"
  sc delete <ServiceName>
  ```

{% endtab %}
{% tab title="PowerShell" %}

#### Using PowerShell

- **List all services:**
  ```powershell
  Get-Service
  ```
- **Get the status of a specific service:**
  ```powershell
  Get-Service -Name <ServiceName>
  ```
- **Start a service:**
  ```powershell
  Start-Service -Name <ServiceName>
  ```
- **Stop a service:**
  ```powershell
  Stop-Service -Name <ServiceName>
  ```
- **Restart a service:**
  ```powershell
  Restart-Service -Name <ServiceName>
  ```
- **Change the start type:**
  ```powershell
  Set-Service -Name <ServiceName> -StartupType Automatic
  Set-Service -Name <ServiceName> -StartupType Manual
  Set-Service -Name <ServiceName> -StartupType Disabled
  ```
- **Get detailed service information:**
  ```powershell
  Get-WmiObject -Class Win32_Service | Select-Object Name, StartName, State, StartMode
  ```

{% endtab %}
{% endtabs %}


---

## Scheduled Tasks

Windows Scheduled Tasks are automated jobs managed by the **Task Scheduler** service, enabling users and the system to run programs, scripts, or commands at specified times or in response to specific events. Scheduled tasks are widely used for maintenance, automation, updates, monitoring, and persistence.

### **Underlying Mechanisms**

Scheduled Tasks in Windows are managed by the Task Scheduler Engine, a built-in service that automates the launching of programs or scripts at predefined times or in response to specific events. The engine continuously monitors triggers, such as system startup, user logon, or a particular time of day, to determine when a task should be executed. Each task’s configuration, including its triggers, actions, and conditions, is stored as an XML file within protected system directories. When a task runs, the Task Scheduler executes the defined actions and records detailed information about the execution process in the Windows event logs. These logs provide valuable insights for monitoring task outcomes and troubleshooting any issues that may arise.

- **Task Scheduler Service (`Task Scheduler` / `taskschd.msc`):**  The core Windows service responsible for managing, triggering, and executing scheduled tasks. It runs as a background service (`Task Scheduler`), starting during system boot.
- **Task Definition:**  Each task is defined by an XML file specifying triggers, actions, conditions, and settings. These definitions are stored in the filesystem and referenced by the Task Scheduler.
- **Execution Context:**  Tasks can run under various user accounts (SYSTEM, NETWORK SERVICE, specific users), with configurable privileges and security contexts.

### Execution Timing & Triggers

Scheduled tasks can be set to execute after a variety of different of different timings and triggers, such as: at boot, at login, at a specific time, or upon the occurance of specific events or conditions.

- **Boot-Time Tasks:**  
  - Triggered after the Windows kernel and core services initialize, but **before user login**.
  - The Task Scheduler service starts after the Service Control Manager (`services.exe`) initializes system services.
  - Boot tasks execute as soon as the Task Scheduler is running and system dependencies are met.
- **Login-Time Tasks:**  
  - Triggered **after user authentication** (after `winlogon.exe` completes), but **before the desktop environment is fully loaded**.
  - These tasks often run in parallel with Group Policy scripts and startup applications.
- **Other Triggers:**  
  - **Time-based:** At a specific time of day, daily, weekly, etc.
  - **Event-based:** On system events (e.g., logon, workstation unlock, system idle, event log entry).
  - **Custom:** On demand, at task creation, or when a specific condition is met (e.g., network availability).

### Task Lifecycle & System Process Interaction

When a scheduled task is created, its definition (including triggers, actions, and conditions) is stored as an XML file and registered with the Task Scheduler service. The Task Scheduler service (`svchost.exe` hosting `Schedule`) continuously monitors for trigger events, such as system startup, user logon, or a specific time. When a trigger condition is met, Task Scheduler launches the task as a child process, running under the specified user account or service context. The Task Scheduler Engine manages task execution, monitors for completion or failure, and records results in the Task Scheduler event log. Throughout its lifecycle, a task may be queued, running, completed, or failed, and its status can be queried or managed via the GUI, `schtasks.exe`, or PowerShell. Task execution is isolated from the Task Scheduler service itself, ensuring that failures or resource issues in a task do not affect the scheduler or other tasks.

- **Task Scheduler Service** (`taskschd.msc`/`svchost.exe`):  Monitors triggers and launches tasks as child processes, using the specified user context.
- **Task Engine:**  Handles execution, monitors task status, and logs results.
- **Dependencies:**  Tasks can be configured to wait for network, idle state, or other conditions before running.

### Where Scheduled Task Data is Stored

- **Task Definitions (XML):**  Each task is stored as an XML file, organized by folder in `%SystemRoot%\System32\Tasks\`.
- **Task Scheduler GUI:**  Tasks can be viewed through the GUI in `taskschd.msc` (Start > Run > `taskschd.msc` or search "Task Scheduler").
- **Registry:**  Information about tasks is also stored in the registry in `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\`. Here you can find metadata, state, and security info.
- **Event Logs:**  The Windows event log **"Task Scheduler Operational"** contains details on task registration, execution, completion, and errors. It can be found in the Windows Event Viewer in  `Applications and Services Logs > Microsoft > Windows > TaskScheduler > Operational`.

### Managing Scheduled Tasks

#### Using the GUI (Task Scheduler)

- **Open Task Scheduler:**  Run `taskschd.msc` or search "Task Scheduler".
- **Browse Tasks:**  Navigate the left pane to see folders and tasks.
- **Create/Edit Tasks:**  Right-click > "Create Task" or "Create Basic Task" for a wizard, where you can configure triggers, actions, conditions, and settings.
- **View History:**  Select a task > "History" tab for execution logs.
- **Disable/Delete Tasks:**  Right-click > Disable or Delete.

#### Using The Command Line

{% tabs %}
{% tab title="cmd.exe" %}

- **List all tasks:**  
  ```cmd
  schtasks /query /fo LIST /v
  ```
- **Create a task:**  
  ```cmd
  schtasks /create /tn "MyTask" /tr "C:\script.bat" /sc onlogon /ru SYSTEM
  ```
- **Run a task on demand:**  
  ```cmd
  schtasks /run /tn "MyTask"
  ```
- **Delete a task:**  
  ```cmd
  schtasks /delete /tn "MyTask"
  ```
- **Change a task:**  
  ```cmd
  schtasks /change /tn "MyTask" /enable
  ```

{% endtab %}
{% tab title="PowerShell" %}

- **List all tasks:**  
  ```powershell
  Get-ScheduledTask
  ```
- **View task details:**  
  ```powershell
  Get-ScheduledTask -TaskName "MyTask" | Get-ScheduledTaskInfo
  ```
- **Register (create) a new task:**  
  ```powershell
  $action = New-ScheduledTaskAction -Execute "notepad.exe C:Users\tester\mynotes.txt"
  $trigger = New-ScheduledTaskTrigger -AtLogOn
  Register-ScheduledTask -TaskName "MyTask" -Action $action -Trigger $trigger -User "SYSTEM"
  ```
- **Disable/Enable a task:**  
  ```powershell
  Disable-ScheduledTask -TaskName "MyTask"
  Enable-ScheduledTask -TaskName "MyTask"
  ```
- **Remove a task:**  
  ```powershell
  Unregister-ScheduledTask -TaskName "MyTask" -Confirm:$false
  ```

{% endtab %}
{% endtabs %}

#### Advanced Management

- **Modify Task Conditions:**  
  - In Task Scheduler GUI: Edit a task > "Conditions" tab (e.g., "Start only if idle", "Wake computer", "Start only if network available").
  - PowerShell: Use `Set-ScheduledTask -TaskName "MyTask" -Trigger $NewTrigger` with updated triggers/conditions.
- **Set Dependencies:**  
  - Use "Settings" tab to configure behavior if the task is already running, stop on battery, etc.
  - For complex dependencies, use scripts or event-based triggers.
- **Troubleshooting Failed Tasks:**  
  - Check the "History" tab in Task Scheduler for error codes and messages.
  - Review the Task Scheduler Operational event log for detailed errors.
  - Ensure correct permissions for the user context.
  - Verify that required files, scripts, or network resources are available at execution time.
  - Use `schtasks /query /fo LIST /v` or `Get-ScheduledTaskInfo` for last run results and error codes.

### Scheduled Tasks Best Practices

- **Task Security:**  
  - Run tasks with the least privilege necessary.
  - Use "Run with highest privileges" only when required.
- **Audit for Persistence:**  Scheduled tasks are a common persistence mechanism for attackers, so regularly audit tasks for suspicious entries.
- **Export/Import Tasks:**  Tasks can be exported/imported as XML via the GUI or PowerShell (`Export-ScheduledTask`, `Register-ScheduledTask -Xml`).
- **Task Folders:**  Organize tasks in folders for clarity and delegation.
- **Audit & Monitoring:**  Regularly review the Task Scheduler event logs and task definitions for unauthorized changes.

For more information, see Microsoft's [Task Scheduler documentation](https://learn.microsoft.com/en-us/windows/win32/taskschd/task-scheduler-start-page).

---

## Windows Shells

Windows ships with a full set of Win32 console commands that can automate tasks, manage files, and interact directly with the operating system. These commands run in either **Command Prompt** or **PowerShell**, and offer distinct approaches to automation, scripting, and system control. Each is shaped by different eras of Windows computingand they cover everything from file operations to network diagnostics. Microsoft notes that all supported versions of Windows include these built‑in commands, which can be used in scripts or executed interactively. 

Both shells coexist in Windows because they serve different needs: **cmd.exe** maintains compatibility with decades of scripts and tools, while **PowerShell** provides a modern, extensible environment for automation and administration. Many users switch between them depending on the task—quick legacy commands in CMD, complex scripting and system orchestration in PowerShell. 

### Command Prompt (cmd.exe)

**Command Prompt** is the classic Windows command processor, rooted in MS‑DOS conventions. It provides a lightweight, text‑based interface for running batch scripts, managing files, and executing legacy tools. Its syntax is simple and familiar to long‑time Windows users, but it lacks the structured data handling and extensibility found in modern shells. Many traditional utilities still rely on cmd.exe, making it a reliable choice for quick tasks and backward‑compatible workflows.

See my cmd.exe reference here: [cmd.exe](cmd-shell.md)

### PowerShell (powershell.exe)

**PowerShell** is Microsoft’s modern, object‑oriented shell designed for automation at scale. Unlike cmd.exe, which works with plain text, PowerShell passes rich .NET objects through its pipeline, enabling precise control over system configuration, cloud services, and complex administrative tasks. It supports advanced scripting, modules, remote management, and flexible command‑line parameters, making it a powerful tool for developers and IT professionals. PowerShell can also run many legacy CMD commands for compatibility, though some behave differently due to PowerShell’s parsing rules. 

See my PowerShell reference here: [PowerShell](powershell.md)

---

## **Windows built-in Utilities**

These utilities can be combined in batch scripts or used interactively to automate and streamline system  management tasks. Most of these utilities are either built into the cmd shell, or are executables shipped with Windows that can mainly be found in `C:\Windows\System32\`. 

Windows includes a wide collection of built‑in utilities and command‑line tools that help with system management, troubleshooting, automation, and everyday maintenance. These tools range from classic console commands to graphical diagnostics, giving users multiple ways to control and optimize their system. 

See my Windows Utilities reference here: [Windows Utilities](utilities.md)

### Graphical built‑in tools

Alongside console commands, Windows includes several graphical utilities designed to diagnose and repair system issues. These tools are accessible through the Start menu, Run dialog (`[Win+r]`), or the Control Panel.

These utilities complement command‑line tools by offering quick, user‑friendly ways to maintain system health. Windows maintains both classic and modern utilities so users can choose the right tool for the task. Command‑line tools excel at automation and repeatable workflows, while graphical tools simplify diagnostics and configuration. Power users often combine both—running scripts for routine tasks and launching built‑in utilities for deeper troubleshooting.

---

## The Windows Filesystem

The Windows filesystem is a critical component of the operating system, responsible for managing how data is stored, organized, and accessed on storage devices. Windows supports several filesystems, each with unique features and use cases. 

### Filesystems Used in Windows

1. **FAT32 (File Allocation Table 32):**
  - An older filesystem that is widely supported across various operating systems and devices.
  - Maximum file size: 4 GB.
  - Maximum partition size: 8 TB.
  - Commonly used for USB drives and external storage devices due to its compatibility.
  - Lacks advanced features like file permissions and journaling.

2. **exFAT (Extended File Allocation Table):**
  - Designed as an improvement over FAT32, primarily for flash drives and external storage.
  - Supports larger file sizes (up to 16 EB) and larger partitions.
  - Compatible with both Windows and macOS, making it ideal for cross-platform use.
  - Does not include advanced features like journaling or file permissions.

3. **NTFS (New Technology File System):**
  - The default filesystem for modern Windows operating systems.
  - Supports large file sizes and partitions (up to 16 EB).
  - Includes advanced features such as file permissions, encryption (EFS), compression, journaling, and disk quotas.
  - Optimized for performance and reliability, making it suitable for internal drives and system partitions.

4. **ReFS (Resilient File System):**
  - Designed for high availability, scalability, and data integrity.
  - Primarily used in server environments and for storage spaces.
  - Features include automatic data integrity checks, built-in resilience to corruption, and support for large volumes.
  - Not commonly used for consumer systems.

### Filesystem Tools

By understanding the different filesystems tools available in Windows, users can effectively manage their storage devices to ensure data integrity and performance.

1. **fsutil:**
  - A powerful command-line utility for managing and querying filesystem-related information.
  - Common use cases include:
    - Managing hard links, symbolic links, and junction points.
    - Querying volume information and free space.
    - Enabling or disabling volume-level features like short file names.
    - Managing quotas and sparse files.
  - Basic Example: `fsutil fsinfo drives` (Lists all drives on the system).
  - Advanced Example: `fsutil behavior query bugcheckoncorrupt`

     The `fsutil behavior query bugcheckoncorrupt` command checks whether the system is configured to issue a bug check (stop error) when it encounters corruption on NTFS volumes. This setting prevents NTFS from silently deleting files during self-healing, allowing administrators to back up data before any automatic repair.

     - **Purpose**: Ensures the system halts with a `0x00000024` stop error when NTFS volume corruption is detected.
     - **Use Case**: Prevents data loss by enabling administrators to address corruption manually before NTFS attempts self-healing.
     - **Example Output**:
    ```bat
    fsutil behavior query bugcheckoncorrupt
    :: bugcheckoncorrupt = 0 (Disabled)
    ```
    A value of `1` indicates that the system will issue a bug check on corruption, while `0` disables this behavior.

     - **Related Commands**:
       - `fsutil behavior set bugcheckoncorrupt 1` – Enables bug check on corruption.
       - `fsutil behavior set bugcheckoncorrupt 0` – Disables bug check on corruption.

2. **chkdsk (Check Disk):**
  - A utility for scanning and repairing filesystem errors and bad sectors on a disk.
  - Can be run from the command line or through the disk properties dialog in File Explorer.
  - Example command: `chkdsk C: /f` (Scans and fixes errors on the C: drive).

3. **Disk Management:**
  - A graphical tool for managing disks, partitions, and volumes.
  - Allows users to create, format, resize, and delete partitions.
  - Accessible via the Control Panel or by running `diskmgmt.msc`.

4. **Diskpart:**
  - A command-line utility for advanced disk and partition management.
  - Supports tasks such as creating, deleting, and resizing partitions, as well as assigning drive letters.
  - Example command: `diskpart` (Launches the utility).

5. **PowerShell Cmdlets:**
  - Windows PowerShell includes cmdlets for managing filesystems and storage.
  - Examples include `Get-Volume`, `Format-Volume`, and `New-Partition`.


### NTFS File Attributes

Windows **file attributes** are metadata properties assigned to files and folders that define their visibility, accessibility, and behavior. These attributes help control read/write access, security settings, and system file classifications.

File attributes can be **modified using built-in commands** like `attrib` in **cmd.exe** or `Set-ItemProperty` in **PowerShell**. Some attributes, such as **Read-Only and Hidden**, are commonly used for file protection and organizational purposes, while system attributes ensure that essential files are safeguarded from accidental modifications.

Here is a list of the most common Windows file attributes: 

| **Attribute** | **Description** | **Example Use Case** |
|--------------|---------------|------------------|
| **Read-Only (R)** | Prevents modifications to the file. | Used on important documents to avoid accidental changes. |
| **Hidden (H)** | Hides the file from standard directory views. | Hiding configuration files from casual users. |
| **System (S)** | Marks a file as a system file, restricting user modifications. | Applied to critical Windows system files. |
| **Archive (A)** | Flags the file for backup or archiving purposes. | Automatically marked when a file is edited, useful for backup software. |
| **Compressed (C)** | Indicates the file is compressed via NTFS compression. | Reduces file size on NTFS partitions. |
| **Encrypted (E)** | Encrypts the file using NTFS encryption. | Protects sensitive data by restricting unauthorized access. |
| **Temporary (T)** | Indicates the file is for temporary use. | Used by applications for cache storage. |
| **Sparse (P)** | Allocates disk space efficiently by storing only non-zero data. | Used for database and virtualization scenarios. |
| **Offline (O)** | Marks the file as **offline**, meaning it's stored remotely. | Useful for files managed by cloud storage systems. |

#### **Managing File Attributes**

You can view and change file attributes using the following commands:

- **CMD:**  
  `attrib +H secret.txt` → Hide `secret.txt`  
  `attrib -R report.docx` → Remove Read-Only from `report.docx`  
- **PowerShell:**  
  `$file = Get-Item "C:\example.txt"; $file.Attributes += 'Hidden'` → Hide the file  

{% tabs %}
{% tab title="cmd.exe" %}

The `attrib` command is used in Windows to display, set, or remove file and directory attributes. It allows you to manage attributes such as read-only, hidden, system, and archive. Common switches include:

- `+R` / `-R`: Add or remove the read-only attribute.
- `+H` / `-H`: Add or remove the hidden attribute.
- `+S` / `-S`: Add or remove the system attribute.
- `+A` / `-A`: Add or remove the archive attribute.
- `+I` / `-I`: Add or remove the `not-content-indexed` attribute, which excludes the file or folder from Windows Search indexing.
- Note: Flags must be added separately (`-h -a -r` not `-har`).

Example: Set a file as **Hidden** (`-h`) using `attrib`.

```bat
:: Show the file attributes
attrib <C:\path\filename>

:: Add the 'hidden' attribute
attrib +h <C:\path\filename>

:: Remove the 'hidden' property
attrib -h <C:\path\filename>
```

{% endtab %}
{% tab title="PowerShell" %}

Example: Set a file as `Hidden`. (This can also be used to change other file property flags such as `Archive` and `ReadOnly`)

```powershell
# Get File attributes
$file = (Get-ChildItem <file>) # Need the file as an object to get attributes directly
$file.attributes # Show the file's attributes
#Normal

# Flip the bit of the Hidden attribute using xor
$file.attributes = $file.Attributes -bxor ([System.IO.FileAttributes]::Hidden)
$file.attributes
#Hidden

# Change attribute with direct assignment (beware, using = will set ONLY that attribute)
$file.Attributes += 'Hidden'

# To remove the 'Hidden' attribute, flip the bit back using xor (or direct assignement)
$file.attributes = $file.Attributes -bxor ([System.IO.FileAttributes]::Hidden)
$file.attributes
#Normal
```

{% endtab %}
{% endtabs %}

---

## Access Control: Rights versus Permissions

Windows enforces the user's ability to access files and perform actions on a system through a combination of authentication, authorization, and access control mechanisms. These are accomplished through application of **rights** and **permissions**, which sound like similar concepts but serve different purposes in access control.

In Windows, **Rights** apply to **user accounts** and define what actions a user can perform on a system-wide level. Examples include the ability to **log in**, **change system time**, or **install drivers**. These are managed through **Group Policy** and affect the entire system.

This differs from **Permissions**, which apply to **objects** (such as files, folders, or registry keys) and determine what a user can do with them. Examples include **read**, **write**, **execute**, or **modify** access to a file. Permissions are set by the **owner** of an object and are enforced through **Access Control Lists (ACLs)**.  They are applied at the filesystem level, and are stored in each file's NTFS metadata.

In short, **rights** control *system-wide actions*, while **permissions** control *access to specific objects*. 

### NTFS Permissions

NTFS (New Technology File System) permissions are a security feature in Windows that controls who can access files and folders on NTFS-formatted drives. These permissions allow administrators to **restrict or grant access** to users and groups, ensuring data security and integrity.

NTFS permissions are **more granular** than share permissions and apply at the **file system level**, meaning they remain in effect regardless of how the file or folder is accessed (locally or over a network). Permissions can be **explicitly assigned** or **inherited** from parent folders.

#### **NTFS Permission Types & Applicability**

Below is a table describing the different NTFS permissions:

| **Permission** | **Description** | **Applicable To** | **Example Use Case** |
|---------------|---------------|------------------|------------------|
| **Full Control** | Grants complete access, including modifying permissions and taking ownership. | Files & Folders | Administrators managing system files. |
| **Modify** | Allows reading, writing, and deleting files/folders. | Files & Folders | Users editing documents but restricted from changing permissions. |
| **Read & Execute** | Allows viewing and executing files but prevents modifications. | Files & Folders | Running applications without modifying them. |
| **List Folder Contents** | Allows viewing folder contents but prevents file modifications. | Folders Only | Browsing directories without altering files. |
| **Read** | Grants permission to view files and folder contents. | Files & Folders | Users needing access to reference documents. |
| **Write** | Allows creating and modifying files but prevents deletion. | Files & Folders | Users adding new files to a shared directory. |
| **Traverse Folder / Execute File** | Allows navigating through folders or executing files. | Files & Folders | Running scripts or accessing nested directories. |
| **Delete** | Grants permission to remove files or folders. | Files & Folders | Users managing temporary files. |
| **Change Permissions** | Allows modifying NTFS permissions for files and folders. | Files & Folders | Administrators adjusting access control settings. |
| **Take Ownership** | Allows users to take ownership of files or folders. | Files & Folders | Recovering access to locked files. |

#### **Key Features of NTFS Permissions**

- **Inheritance**: Permissions assigned to a parent folder automatically apply to its subfolders and files unless explicitly overridden.
- **Explicit vs. Inherited Permissions**: Explicit permissions are manually set, while inherited permissions come from parent directories.
- **Deny Overrides Allow**: If a user has both "Allow" and "Deny" permissions, "Deny" takes precedence.
- **Combining Permissions**: If a user belongs to multiple groups, their permissions are combined.

### **Windows Share Permissions**

Windows uses **two types of permissions** to control access to files and folders: **Share Permissions** and **NTFS Permissions**. While they serve similar purposes, they function differently and apply in different scenarios.

#### **Share Permissions**

- **Apply only to shared folders accessed over a network** (not local access).
- **Three levels of access**:  
  - **Read** - Users can view files and folders but cannot modify them.  
  - **Change** - Users can read, modify, and delete files.  
  - **Full Control** - Users can read, modify, delete, and change permissions.  
- **Set at the folder level** (not individual files).
- **Cannot be inherited** - each shared folder has its own permissions.

#### **NTFS Permissions**

- **Apply to both local and network access**.
- **More granular control**: permissions can be set for individual files and folders.
- **Can be inherited**: permissions assigned to a parent folder apply to subfolders and files (unless explicitly disabled).
- **Includes advanced permissions** like **Modify, Read & Execute, Write, and Full Control**.

#### **Precedence of Share vs. NTFS Permissions**

When a user accesses a shared folder over the network, **both Share and NTFS permissions apply**. The **most restrictive** permission takes precedence.

| **Permission Type** | **Explicit vs. Inherited** | **Allow vs. Deny** | **Precedence Level** |
|---------------------|--------------------------|--------------------|----------------------|
| **Explicit Deny (NTFS)** | Directly assigned to a file or folder | Deny | **Highest Precedence** |
| **Explicit Deny (Share)** | Directly assigned to a shared folder | Deny | **High Precedence** |
| **Explicit Allow (NTFS)** | Directly assigned to a file or folder | Allow | **Medium Precedence** |
| **Explicit Allow (Share)** | Directly assigned to a shared folder | Allow | **Medium Precedence** |
| **Inherited Deny (NTFS)** | Inherited from a parent folder | Deny | **Lower Precedence** |
| **Inherited Allow (NTFS)** | Inherited from a parent folder | Allow | **Lowest Precedence** |

##### **Key Takeaways**

- **Deny always overrides Allow**: if a user is explicitly denied access via NTFS or Share permissions, they cannot access the resource.
- **NTFS permissions apply to both local and network access**, while **Share permissions apply only to network access**.
- **File permissions override folder permissions**, unless Full Control is granted at the folder level.
- **The most restrictive permission applies**: if NTFS allows access but Share denies it, the user is denied.

### Access Control Lists (ACLs)

In Windows, **Access Control Lists (ACLs)** are security structures that define who can access files and folders and what actions they can perform. ACLs consist of **Access Control Entries (ACEs)**, which specify **users, groups, or processes** and their corresponding permissions.

Every **file and folder** has an ACL that determines its accessibility:

- ACLs contain a **list of permissions** assigned to different users or groups.
- **Permissions can be explicitly assigned** or inherited from a parent directory.
- ACLs help enforce **security policies** and protect sensitive data.

To view an ACL for a file or folder: right-click on the item in Explorer and select 'Properties'. Click on the 'Security' tab, the view the section marked 'Permissions for <USERNAME>'. 

#### **Windows ACL Components**

- **Discretionary Access Control List (DACL)** - Defines who has **allow or deny** permissions.
- **System Access Control List (SACL)** - Used for auditing access attempts.
- **Owner** - The user who controls the resource and can change permissions.
- **Inheritance** - Determines if child files/folders receive permissions from a parent directory.

#### **Common ACL Permissions**

| **Permission** | **Description** | **Example Use Case** |
|---------------|---------------|------------------|
| **Full Control** | Grants complete access, including modifying ACLs and taking ownership. | Used by administrators to manage security settings. |
| **Modify** | Allows reading, writing, and deleting files/folders. | Editors and contributors modifying shared project files. |
| **Read & Execute** | Allows viewing and running files but prevents modifications. | Running applications without altering them. |
| **List Folder Contents** | Allows browsing directories without modifying files. | Users needing access to a directory’s structure without altering data. |
| **Read** | Grants permission to view files and folder contents. | Viewing reference documents without editing. |
| **Write** | Allows creating and modifying files but prevents deletion. | Users adding new content to shared folders without deletion rights. |
| **Change Permissions** | Allows modifying ACL settings for files and folders. | Administrators adjusting access control settings. |
| **Take Ownership** | Allows users to take ownership of files or folders. | Recovering access to locked files. |

#### **Key Takeaways**

- **ACLs control file/folder access** by assigning permissions to users and groups.
- **Explicit Deny overrides Allow** when conflicting permissions exist.
- **Inheritance determines** whether child objects receive parent permissions.

### **Managing ACLs in Windows**

#### **Using File Explorer**
1. **Right-click** a file or folder → **Properties** → **Security** tab.
2. Click **Edit** to modify **permissions**.
3. Add, remove, or adjust permissions for **users and groups**.

#### Using the shell

{% tabs %}
{% tab title="cmd.exe" %}

#### **Using `icacls`**

**View ACLs:**  
  ```cmd
  icacls C:\SensitiveData
  ```

**Grant Permissions (Example: Full Control):**  
  ```cmd
  icacls C:\SensitiveData /grant tester:F
  ```

**Remove All Permissions for a User to a Specific File:**  
  ```cmd
  icacls C:\SensitiveData /remove tester
  ```

**Copy Permissions from One File or Directory to Another:**

  ```cmd
  icacls C:\File1 /save perms.txt
  icacls C:\File2 /restore perms.txt
  ```

{% endtab %}
{% tab title="PowerShell" %}

**View ACLs:**

```powershell
Get-Acl C:\SensitiveData | Format-List
```

**Grant Permissions (Example: Full Control):**

```powershell
$acl = Get-Acl C:\SensitiveData
$rule = New-Object System.Security.AccessControl.FileSystemAccessRule("tester", "FullControl", "Allow")
$acl.SetAccessRule($rule)
Set-Acl C:\SensitiveData $acl
```

**Remove All Permissions from a Folder or File for a Specific User or Group:**

```powershell
$path = "C:\temp" #Replace with whatever file you want to do this to.
$acl = Get-Acl $path
$rules = $acl.Access | where IsInherited -eq $false #Gets all non inherited rules.
#Filter your $rules however you want to remove permissions.

#For example, to target a specific user or group:
$targetrule = $rules | where IdentityReference -eq "$Domain\$User" #Leave domain off for local accounts.

$acl.RemoveAccessRule($targetrule)
$acl | Set-Acl -Path $path
```

**Copy Permissions from One File or Directory to Another:**

```powershell
Get-ACL C:\File1 | Set-Acl C:\File2
```

**Advanced: Add a Specific List of Permissions to a Folder (or File):**

```powershell
function Edit-Perms {
Param
(   
    $Path = "C:\temp", #Replace with whatever file you want to do this to.
    $User = "$env:username", #Format: "$domain\$useraccount" User account to grant permisions too.
    $Rights = "Read, ReadAndExecute, ListDirectory", #Comma seperated list.
    $InheritSettings = "Containerinherit, ObjectInherit", #Controls how permissions are inherited by children
    $PropogationSettings = "None", #Usually set to none but can setup rules that only apply to children.
    $RuleType = "Allow" #Allow or Deny.
)
$acl = Get-Acl $path
$perm = $user, $Rights, $InheritSettings, $PropogationSettings, $RuleType
$rule = New-Object -TypeName System.Security.AccessControl.FileSystemAccessRule -ArgumentList $perm
$acl.SetAccessRule($rule)
$acl | Set-Acl -Path $path
}
```

{% endtab %}
{% endtabs %}

### Windows Rights 

Rights (also called user rights or privileges) define what actions a user can perform on the system, not on individual files. These include abilities such as logging on locally, shutting down the system, backing up files, or changing the system time. Rights are managed through Local Security Policy and Group Policy, and they apply at the OS level rather than the object level.

Examples of rights include:
- Log on locally
- Shut down the system
- Back up files and directories
- Change the system time

Rights determine the level of authority a user has when interacting with the operating system itself. They are distinct from permissions and can override or limit what permissions allow. Rights determine the level of authority when working in the system, while permissions govern access to specific resources.

#### How rights differ from permissions

Although both are part of Windows access control, they operate at different layers:

- Scope
  - Permissions apply to objects (files, folders, registry keys).
  - Rights apply to system‑level actions (logon, shutdown, backup).
- Where they are configured
  - Permissions are set on the object itself through ACLs.
  - Rights are assigned through Local Security Policy or Group Policy.
- Who controls them
  - Permissions are granted by the object’s owner.
  - Rights are granted by administrators and apply to users or groups.
- Effect on access
  - Permissions determine whether a user can read, write, or modify a resource.
  - Rights determine whether a user can perform privileged system operations.
- Interaction
  - Rights can take precedence over permissions. For example, the “Back up files and directories” right allows reading files regardless of their permissions, because backup operations bypass normal ACL checks.

### Common settings for Rights:

| Setting                      | Description                                                                                                                                                                                                                                                                          |
| ---------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| AppendData                   | Specifies the right to append data to the end of a file.                                                                                                                                                                                                                             |
| ChangePermissions            | Specifies the right to change the security and audit rules associated with a file or folder.                                                                                                                                                                                         |
| CreateDirectories            | Specifies the right to create a folder.                                                                                                                                                                                                                                              |
| CreateFiles                  | Specifies the right to create a file.                                                                                                                                                                                                                                                |
| Delete                       | Specifies the right to delete a folder or file.                                                                                                                                                                                                                                      |
| DeleteSubdirectoriesAndFiles | Specifies the right to delete a folder and any files contained within that folder.                                                                                                                                                                                                   |
| ExecuteFile                  | Specifies the right to run an application file.                                                                                                                                                                                                                                      |
| FullControl                  | Specifies the right to exert full control over a folder or file, and to modify access control and audit rules. This value represents the right to do anything with a file and is the combination of all rights in this enumeration.                                                  |
| ListDirectory                | Specifies the right to read the contents of a directory.                                                                                                                                                                                                                             |
| Modify                       | Specifies the right to read, write, list folder contents, delete folders and files, and run application files. This right includes the ReadAndExecute right, the Write right, and the Delete right.                                                                                  |
| Read                         | Specifies the right to open and copy folders or files as read-only. This right includes the ReadData right, ReadExtendedAttributes right, ReadAttributes right, and ReadPermissions right.                                                                                           |
| ReadAndExecute               | Specifies the right to open and copy folders or files as read-only, and to run application files. This right includes the Read right and the ExecuteFile right.                                                                                                                      |
| ReadAttributes               | Specifies the right to open and copy file system attributes from a folder or file. For example, this value specifies the right to view the file creation or modified date. This does not include the right to read data, extended file system attributes, or access and audit rules. |
| ReadData                     | Specifies the right to open and copy a file or folder. This does not include the right to read file system attributes, extended file system attributes, or access and audit rules.                                                                                                   |
| ReadExtendedAttributes       | Specifies the right to open and copy extended file system attributes from a folder or file. For example, this value specifies the right to view author and content information. This does not include the right to read data, file system attributes, or access and audit rules.     |
| ReadPermissions              | Specifies the right to open and copy access and audit rules from a folder or file. This does not include the right to read data, file system attributes, and extended file system attributes.                                                                                        |
| Synchronize                  | Specifies whether the application can wait for a file handle to synchronize with the completion of an I/O operation.                                                                                                                                                                 |
| TakeOwnership                | Specifies the right to change the owner of a folder or file. Note that owners of a resource have full access to that resource.                                                                                                                                                       |
| Traverse                     | Specifies the right to list the contents of a folder and to run applications contained within that folder.                                                                                                                                                                           |
| Write                        | Specifies the right to create folders and files, and to add or remove data from files. This right includes the WriteData right, AppendData right, WriteExtendedAttributes right, and WriteAttributes right.                                                                          |
| WriteAttributes              | Specifies the right to open and write file system attributes to a folder or file. This does not include the ability to write data, extended attributes, or access and audit rules.                                                                                                   |
| WriteData                    | Specifies the right to open and write to a file or folder. This does not include the right to open and write file system attributes, extended file system attributes, or access and audit rules.                                                                                     |
| WriteExtendedAttributes      | Specifies the right to open and write extended file system attributes to a folder or file. This does not include the ability to write data, attributes, or access and audit rules.                                                                                                   |

#### Inherit settings:

| Setting          | Description                                      |
| ---------------- | ------------------------------------------------ |
| ContainerInherit | The ACE is inherited by child container objects. |
| None             | The ACE is not inherited by child objects.       |
| ObjectInherit    | The ACE is inherited by child leaf objects.      |

{% hint style="info" %}
Set the **`$InheritSettings`** to **`None`** if targeting a file instead of a folder.
{% endhint %}

#### Propagation Settings: 

| Setting            | Description                                                                                                      |
| ------------------ | ---------------------------------------------------------------------------------------------------------------- |
| InheritOnly        | Specifies that the ACE is propagated only to child objects. This includes both container and leaf child objects. |
| None               | Specifies that no inheritance flags are set.                                                                     |
| NoPropagateInherit | Specifies that the ACE is not propagated to child objects.                                                       |

---

## Shared Folders/SMB

Windows shared folders rely on the **SMB/CIFS** family of protocols to let users access files, printers, and other resources over a network. Understanding how SMB works, and how **share permissions** differ from **NTFS permissions**, is essential for anyone managing Windows environments.

### How Windows shared folders work

A Windows shared folder is any local directory that has been published to the network so other users can access it. When a folder is shared, Windows exposes it through the **Server Message Block (SMB)** protocol, which handles authentication, file access, and communication between clients and servers.

Shared folders are commonly used for:

- Centralized file storage  
- Departmental shares  
- Home directories  
- Application data shares  
- Printer and device sharing  

Windows manages these shares through the **Server service**, and clients connect using SMB.

### SMB and CIFS

**SMB (Server Message Block)** is the core network file‑sharing protocol used by Windows. **CIFS (Common Internet File System)** is an older dialect of SMB, essentially **SMB 1.0**, that Microsoft introduced in the 1990s. Modern Windows systems use SMB 2.x and SMB 3.x, which offer major improvements in performance, security, and reliability.

Protocol overview:
- SMB is a **client–server** protocol used for file access, directory operations, printing, and network browsing.  
- CIFS is a **specific dialect** of SMB, now considered obsolete.  
- SMB supports features such as dialect negotiation, authentication, file locking, change notifications, and opportunistic locks. 

Modern security guidance strongly discourages CIFS/SMBv1 because it lacks encryption, integrity protection, and is vulnerable to downgrade and man‑in‑the‑middle attacks. 

### How permissions work on shared folders

Windows uses **two layers of permissions** for shared folders:

#### 1. Share permissions

These apply only when accessing a folder **over the network** (via SMB). They are simple and coarse‑grained:
- Read  
- Change  
- Full Control  

Share permissions are evaluated first and act as a **gatekeeper** for network access.

### 2. NTFS permissions

These apply to both **local** and **network** access. They are far more granular, supporting:
- Read  
- Write  
- Modify  
- Full Control  
- Special permissions (delete, traverse, read attributes, etc.)

See [NTFS Permissions section](#ntfs-permissions) above for more details.

NTFS permissions are evaluated **after** share permissions.

### How share permissions differ from NTFS permissions

The two permission systems combine to determine the final effective access. Their differences matter for both administration and security.

### Scope
- **Share permissions**: Only apply to SMB network access.  
- **NTFS permissions**: Apply everywhere—local and remote.

### Granularity
- **Share permissions**: Simple, three‑level model.  
- **NTFS permissions**: Highly granular and hierarchical.

### Evaluation order

1. Share permissions  
2. NTFS permissions  

The **most restrictive** permission always wins.

### Common best practice

Administrators often set share permissions to **Everyone: Full Control** and rely entirely on NTFS permissions for fine‑grained control. This avoids confusion and ensures consistent access rules.

{% tabs %}
{% tab title="cmd.exe" %}

### Mount a remote CIFS/SMB share

```bat
net use z: \\$ip\$sharename
#Adding /persistent:yes will make this survive reboots.
```

A great example is to mount the Sysinternals Live drive to use the tools directly from Microsoft:

```bat
net use z: \live.sysinternals.com\tools\ /persistent:yes
```

The `/persistent:yes` argument makes the system add this permanently to the registry and reconnect to the same drive letter each time the computer boots.

### Map drive with credentials

```bat
net use z: \\server\share /user:DOMAIN\User
```

### List all current SMB mappings

```bat
net use
```

### To remove a previously mounted share:

```bat
net use z: /delete
```

{% endtab %}
{% tab title="PowerShell" %}

### Mount a remote CIFS/SMB share

```powershell
New-SmbMapping -LocalPath "Z:" -RemotePath "\\$ip\$sharename"
```

Adding `-Persistent $true` will make this survive reboots.

```powershell
New-SmbMapping -LocalPath "Z:" -RemotePath "\\server\share" -Persistent $true
```

A great example is to mount the Sysinternals Live drive to use the tools directly from Microsoft:

```powershell
New-SmbMapping -LocalPath "Z:" -RemotePath "\\live.sysinternals.com\tools" -Persistent $true
```

The `/persistent:yes` argument makes the system add this permanently to the registry and reconnect to the same drive letter each time the computer boots.

### Map drive with credentials

```powershell
New-SmbMapping -UserName $user -Password $pass
```

### To remove a previously mounted share:

```powershell
Remove-SmbMapping -LocalPath "Z:" -Force
```

`-Force` suppresses confirmation prompts.

### List all current SMB mappings

```powershell
Get-SmbMapping
```

{% endtab %}
{% endtabs %}

---

## **Environment Variables**

The command `set` will display all current environment variables and their values in cmd.exe. In PowerShell use `Get-ChildItem env:` (or one of its aliases!) to list environment variables.

Many of the environment variables in the cmd.exe column can be used in other places inside Windows as well, such as the **Address Bar** of a browser or **Explorer** window.

You can find more about Windows environment variables on the [PowerShell page](powershell.md#environment-variables).

Below is a comparison between the environment variables used in PowerShell versus those used in the classic cmd.exe environment (which are also used in many other places throughout Windows, such as Task Scheduler, Event logs, and more).

### User & Identity Variables

| Meaning | PowerShell | cmd.exe |
|--------|------------|---------|
| User Name | `$env:USERNAME` | `%USERNAME%` |
| Domain Name | `$env:USERDOMAIN` | `%USERDOMAIN%` |
| Roaming Profile Domain | `$env:USERDOMAIN_ROAMINGPROFILE` | `%USERDOMAIN_ROAMINGPROFILE%` |
| User Home Folder | `$env:USERPROFILE` | `%USERPROFILE%` |
| Current User's home folder (path only) | `$env:HOMEPATH` | `%HOMEPATH%` |
| Current User's AppData\Roaming Folder | `$env:APPDATA` | `%APPDATA%` |
| Current User's AppData\Local Folder | `$env:LOCALAPPDATA` | `%LOCALAPPDATA%` |
| Current User's AppData\Local\Temp Folder | `$env:TEMP` | `%TEMP%` |
| Current User's AppData\Local\Temp Folder | `$env:TMP` | `%TMP%` |
| Current User's OneDrive folder | `$env:OneDrive` | `%OneDrive%` |
| Current User's OneDrive Consumer folder | `$env:OneDriveConsumer` | `%OneDriveConsumer%` |
| UNC Path of Logon Server | `$env:LOGONSERVER` | `%LOGONSERVER%` |

### Directories & File System Locations

| Meaning | PowerShell | cmd.exe |
|--------|------------|---------|
| C:\ProgramData | `$env:ALLUSERSPROFILE` | `%ALLUSERSPROFILE%` |
| C:\ProgramData | `$env:ProgramData` | `%ProgramData%` |
| C:\Users\Public | `$env:PUBLIC` | `%PUBLIC%` |
| C:\Program Files | `$env:ProgramFiles` | `%ProgramFiles%` |
| C:\Program Files (x86) | `$env:ProgramFiles(x86)` | `%ProgramFiles(x86)%` |
| C:\Program Files | `$env:ProgramW6432` | `%ProgramW6432%` |
| C:\Program Files\Common Files | `$env:CommonProgramFiles` | `%CommonProgramFiles%` |
| C:\Program Files (x86)\Common Files | `$env:CommonProgramFiles(x86)` | `%CommonProgramFiles(x86)%` |
| C:\Program Files\Common Files | `$env:CommonProgramW6432` | `%CommonProgramW6432%` |
| C:\Windows | `$env:windir` | `%windir%` |
| C:\Windows | `$env:SystemRoot` | `%SystemRoot%` |
| C:\Windows\System32\Drivers\DriverData | `$env:DriverData` | `%DriverData%` |
| C:\ (system drive) | `$env:SystemDrive` | `%SystemDrive%` |
| C:\ (home drive) | `$env:HOMEDRIVE` | `%HOMEDRIVE%` |

### System Properties & OS Information

| Meaning | PowerShell | cmd.exe |
|--------|------------|---------|
| Operating System Family | `$env:OS` | `%OS%` |
| Computer Name | `$env:COMPUTERNAME` | `%COMPUTERNAME%` |
| Console Session Name | `$env:SESSIONNAME` | `%SESSIONNAME%` |
| C:\WINDOWS\system32\cmd.exe | `$env:ComSpec` | `%ComSpec%` |

### Processor & Hardware Information

| Meaning | PowerShell | cmd.exe |
|--------|------------|---------|
| Number of Processor Cores | `$env:NUMBER_OF_PROCESSORS` | `%NUMBER_OF_PROCESSORS%` |
| Processor Architecture | `$env:PROCESSOR_ARCHITECTURE` | `%PROCESSOR_ARCHITECTURE%` |
| Processor ID | `$env:PROCESSOR_IDENTIFIER` | `%PROCESSOR_IDENTIFIER%` |
| Processor Level | `$env:PROCESSOR_LEVEL` | `%PROCESSOR_LEVEL%` |
| Processor Revision | `$env:PROCESSOR_REVISION` | `%PROCESSOR_REVISION%` |

### Execution, PATH, and Module Search Paths

| Meaning | PowerShell | cmd.exe |
|--------|------------|---------|
| PATH to search when unspecified | `$env:Path` | `%Path%` |
| File Extensions Windows searches for | `$env:PATHEXT` | `%PATHEXT%` |
| PATH for PowerShell Modules | `$env:PSModulePath` | `%PSModulePath%` |


---

## **Explorer Navigation**

TODO: add description about how to navigate using the gui more efficiently

### Shortcuts

TODO: Description of explorer shortcuts

| **Shortcut**            | **Action**                                   |
|--------------------------|---------------------------------------------|
| **CTRL+N**              | Open a new Explorer window.                 |
| **CTRL+R**              | Refresh the current Explorer window.        |
| **CTRL+SHIFT+ESC**      | Open Task Manager.                          |
| **Windows+E**           | Open File Explorer.                         |
| **CTRL+L**              | Focus on the address bar.                   |
| **CTRL+O**              | Open the File/Open dialog.                  |
| **CTRL+P**              | Open the Print dialog.                      |
| **CTRL+S**              | Open the Save As dialog.                    |
| **CTRL+ESC**            | Open the Start Menu. |
| **ALT+UP**              | Navigate to the parent folder.              |
| **ALT+LEFT**            | Go back to the previous folder.             |
| **ALT+RIGHT**           | Go forward to the next folder.              |
| **F2**                  | Rename the selected file or folder.         |
| **F3**                  | Open the search bar.                        |
| **F4**                  | Select the address bar.              |
| **F5**                  | Refresh the current window (alternative).   |
| **F6**                  | Cycle through window elements (e.g., panes).|
| **CTRL+SHIFT+N**        | Create a new folder.                        |
| **SHIFT+DELETE**        | Permanently delete the selected item.       |
| **ALT+ENTER**           | Open the Properties dialog for the selected item. |
| **CTRL+W**              | Close the current Explorer window.          |
| **CTRL+SHIFT+E**        | Expand all folders in the navigation pane.  |
| **CTRL+SHIFT+ESC**      | Open Task Manager directly.                 |
| **Windows+D**           | Show desktop (minimize all windows).        |
| **Windows+Arrow Keys**  | Snap windows to the screen edges.           |
| **Windows+Tab**         | Open Task View for virtual desktops.        |
| **CTRL+Mouse Scroll**   | Change the size of icons in the current view.|

For a full list, check out the official Microsoft documentation [here](https://support.microsoft.com/en-us/windows/keyboard-shortcuts-in-windows-dcc61a57-8ff0-cffe-9796-cb9706c75eec)

### **Shell URIs**

TODO: add Description of shell uri's

* `shell:Administrative Tools`
* `shell:DocumentsLibrary`
* `shell:Libraries`
* `shell:UserProfiles`
* `shell:Personal`
* `shell:SearchHomeFolder`
* `shell:NetworkPlacesFolder`
* `shell:SendTo`
* `shell:UserProfiles`
* `shell:Common Administrative Tools`
* `shell:MyComputerFolder`
* `shell:InternetFolder`
* `Shell:Profile`
* `Shell:ProgramFiles`
* `Shell:System`
* `Shell:ControlPanelFolder`
* `Shell:Windows`
* `shell:::{21EC2020-3AEA-1069-A2DD-08002B30309D}` --> Control Panel
* `shell:::{20D04FE0-3AEA-1069-A2D8-08002B30309D}` --> This PC/My Computer
* `shell:::{208D2C60-3AEA-1069-A2D7-08002B30309D}` --> Network Places

---

## References

- [Keyboard shortcuts in Windows](https://support.microsoft.com/en-us/windows/keyboard-shortcuts-in-windows-dcc61a57-8ff0-cffe-9796-cb9706c75eec)
- [Windows Process Genealogy](https://medium.com/@leo.valentic9/windows-process-genealogy-understanding-and-analyzing-key-system-processes-in-digital-forensics-a88cd5b9698f)

If you like this content and would like to see more, please consider [buying me a coffee](https://www.buymeacoffee.com/zweilosec)!
