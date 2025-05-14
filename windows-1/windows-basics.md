---
description: Commands and programs that all Windows users need to know (but many don't!).
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
  - User passwords are hashed and stored securely using algorithms like NTLM or Kerberos.

- **Domain Authentication (If Applicable):**
  - For domain-joined systems, authentication is performed against a domain controller using Kerberos or NTLM.
  - Cached credentials are used if the domain controller is unavailable, allowing users to log in even when disconnected from the network.

- **Single Sign-On (SSO):**
  - Enables users to authenticate once and gain access to multiple resources without re-entering credentials.
  - SSO works by using the access token generated during the initial login to authenticate the user to other services and applications seamlessly.
  - Commonly used in enterprise environments to improve user experience and reduce the need for repeated logins.

- **Account Lockout Policies:**
  - Enforce lockouts after a specified number of failed login attempts to prevent brute-force attacks.

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
    - Group Policy settings are applied in a specific order: **Local Policies → Site Policies → Domain Policies → Organizational Unit (OU) Policies.** If there are conflicts, the last applied policy takes precedence.
    - Administrators can use tools like the Group Policy Management Console (GPMC) or `gpresult` to troubleshoot and verify applied policies.

### **Step 7: Desktop Initialization**

After completing the login tasks, `userinit.exe` launches the Windows shell, typically `explorer.exe`, which provides the graphical user interface, including the desktop, taskbar, and Start menu. Additionally, any startup applications configured to run during login are launched. During this phase, the system ensures that the necessary permissions and security policies are applied to the user session, preparing the environment for interaction. Once these tasks are completed, the desktop is fully initialized and ready for use.

- **Startup Programs:**
  - Applications configured to start automatically are launched. Some of the locations these can be defined in:
    - The `Startup` folder.
    - The `Run` registry keys (`HKLM\Software\Microsoft\Windows\CurrentVersion\Run` and `HKCU\Software\Microsoft\Windows\CurrentVersion\Run`).

- **Registry-Based Startup:**
  - The Windows registry contains entries for programs and services that start during login.

- **Session Initialization:**
  - The user's desktop environment is initialized, including the taskbar, Start menu, and system tray.

---

## Windows Services

TODO: section on services goes here

The **Service Control Manager (`services.exe`)** starts during the **Windows boot process**, specifically after the **Windows Startup Application (`wininit.exe`)** initializes system services. Once `services.exe` is running, it begins **starting system services** based on their configured startup type (automatic, delayed, manual, or disabled).

---

## Scheduled Tasks

TODO: section on scheduled tasks goes here

Scheduled tasks that are set to run at boot or login are triggered at specific points in the Windows startup sequence:

- **Boot-Time Tasks:** These tasks execute **after the Windows kernel initializes** but **before user login**. They typically start when the **Task Scheduler service** (`taskschd.msc`) is initialized, which happens **after system services and drivers are loaded**. Once the Service Control Manager (services.exe) starts, the Task Scheduler service kicks in and executes tasks scheduled to run at boot.
- **Login-Time Tasks:** These tasks run **after a user logs in**, specifically **after Winlogon.exe completes authentication** and **before the user profile is fully loaded**. They are triggered once the **Group Policy login scripts and startup applications begin execution**.

The precise timing depends on system performance, startup delays, and dependencies configured within the scheduled task settings. If a task is set to run **at boot**, it will generally execute **before interactive login**. If set to run **at login**, it will execute **after authentication but before the desktop environment is fully available**.

---

## Sysinternals

If you don't know about Mark Russinovich's amazing tools then go and check them out. Many, many use cases for a lot of these tools, from enumeration, persistence, threat-hunting, to ordinary system administration. [https://docs.microsoft.com/en-us/sysinternals/](https://docs.microsoft.com/en-us/sysinternals/)

Red-teamers and penetration testers can leverage Sysinternals tools for enumeration, privilege escalation, and lateral movement. This table includes a few of the Sysinternals tools useful for offensive security:

| Tool | Description | Example Use Case | Cyber Kill Chain Phase |
|------|------------|------------------|------------------------|
| **PsExec** | Executes processes remotely on another system. | Used for lateral movement by executing commands on remote hosts. | **Lateral Movement** |
| **AccessChk** | Checks user permissions for files, registry keys, and objects. | Identify privilege escalation opportunities by analyzing access control settings. | **Privilege Escalation** |
| **ProcMon (Process Monitor)** | Captures real-time system activity, including file, registry, and network events. | Monitor security controls and detect potential weaknesses in endpoint defenses. | **Exploitation** |
| **TCPView** | Monitors active TCP/UDP connections in real time. | Identify open ports and active connections for reconnaissance. | **Reconnaissance** |
| **Autoruns & Autorunsc** | Displays all auto-start programs, services, and registry entries. | Find persistence mechanisms used by malware or adversaries. | **Persistence** |
| **Handle** | Lists open handles to files, registry keys, and other system objects. | Investigate (i.e. unlock) locked files that may contain sensitive data or credentials. | **Credential Access** |
| **ListDLLs** | Displays loaded DLLs for running processes. | Identify DLL injection opportunities for stealthy code execution (i.e. Running malware) | **Defense Evasion** |
| **SigCheck** | Verifies digital signatures of files. | Detect unsigned or tampered executables that may be malicious. | **Execution** |
| **Strings** | Extracts readable text from binary files. | Analyze malware binaries for embedded commands or indicators of compromise. | **Reconnaissance** |
| **PsSuspend** | Suspends processes without terminating them. | Disable security tools temporarily during red-team operations. | **Defense Evasion** |

- A full list of the current tools can be found [here](https://learn.microsoft.com/en-us/sysinternals/downloads/).
- Sysinternals tools can be linked to directly and run in-memory from [https://live.sysinternals.com/](https://live.sysinternals.com/)
    - This command maps the current full list of Sysinternals tools to the first available drive letter as a network share, ready for use!
    ```powershell
    net use * //live.sysinternals.com
    ```

## Windows Shells

### CMD.EXE

The **Windows Command Prompt (`cmd.exe`)** is an essential interface for executing text-based commands that control the operating system, automate tasks, and troubleshoot system issues. Unlike a graphical user interface (GUI), `cmd.exe` provides direct access to system functionalities through typed commands, making it a powerful tool for administrators, developers, and security professionals.

### **Use Cases for `cmd.exe`**

- **System Administration:** Modify system settings, manage processes, and configure user accounts.
- **Networking:** Troubleshoot connectivity, scan ports, and manage network shares.
- **Security & Forensics:** Analyze logs, check permissions, and identify suspicious activities.
- **Scripting & Automation:** Write batch scripts for repetitive tasks and scheduled jobs.
- **File & Directory Management:** Copy, move, delete, and modify file attributes efficiently.

### Shell Functionality

The shell in `cmd.exe` serves as a command-line interpreter that allows users to interact with the operating system by executing commands, running scripts, and managing system resources. It provides a text-based interface for performing a wide range of tasks, from basic file operations to advanced system configurations.

#### Key Features of the `cmd.exe` Shell

1. **Command Execution**:
  - The shell processes both built-in commands and external executables.
  - Commands can be executed interactively or through batch scripts (`.bat` or `.cmd` files).

2. **Batch Scripting**:
  - Automate repetitive tasks using batch scripts.
  - Supports control structures like loops (`for`), conditionals (`if`), and error handling (`goto` and `errorlevel`).
  - See [scripting reference](../../os-agnostic/scripting/script-language-comparison) for more information (TODO: add link to scripting page)

3. **Environment Variable Management**:
  - Access and modify environment variables using the `set` command.
  - Use variables like `%PATH%`, `%USERNAME%`, and `%TEMP%` to customize the shell environment.

4. **Redirection and Piping**:
  - Redirect input and output using operators like `>`, `>>`, and `<`.
  - Chain commands using pipes (`|`) to pass output from one command as input to another.

8. **Error Handling**:
  - Use `errorlevel` to check the exit status of commands and handle errors in scripts.
  - Combine with conditional statements to create robust automation workflows.

9. **Customization**:
  - Customize the shell prompt using the `prompt` command.
  - Change the appearance of the shell window (e.g., title, colors) using commands like `title` and `color`.

#### Advanced Shell Features

- **Command Chaining**:
TODO: add more
  - Use `&&` to execute the next command only if the previous one succeeds.
  - Use `||` to execute the next command only if the previous one fails.
  - Example: `mkdir new_folder && echo Folder created || echo Failed to create folder`.

- **Wildcards and Pattern Matching**:
TODO: add more
  - Use `*` and `?` for pattern matching in file and directory names.
  - Example: `del *.txt` deletes all `.txt` files in the current directory.

- **Input/Output Streams and Redirection**
TODO: add more
- Windows **cmd.exe** uses three streams: **Standard Input (`stdin`)**, **Standard Output (`stdout`)**, and **Standard Error (`stderr`)** to process command-line interactions (similar to Unix).  
- **Redirection (`>`, `>>`, `<`, `2>`)** – You can **redirect output to files or another command**, such as:  
  ```bat
  dir > output.txt  :: Redirects `dir` command output to a file
  command 2> errors.txt  :: Redirects error messages to a file
  ```

- **Environment Variables (`%VAR%`)** – Used to store system paths, user settings, and configurations dynamically. Example:
TODO: add more
  ```bat
  echo %USERNAME%
  ```
  This displays the current logged-in user.

- **EXIT Codes (`ERRORLEVEL`)** – Returns status codes after command execution for scripting logic. Example:  
TODO: add more
  ```bat
  dir file.txt
  echo %ERRORLEVEL%
  ```

- **Background Task Execution (`start`, `start /b`)** – Runs processes asynchronously without blocking the shell. Example:  
TODO: add more
  ```bat
  start notepad.exe
  ```

- **String Manipulation (`set /a`, `set /p`, substring operations)** – Used for numeric calculations and text handling. Example:  
TODO: add more
  ```bat
  set /a sum=5+10
  echo %sum%
  ```

### **Types of Commands in `cmd.exe`**

There are two primary types of commands that can be executed in `cmd.exe`:

1. **Built-in Commands**:  
   - These commands are **directly processed** within the `cmd.exe` shell, meaning they do **not** rely on external programs to execute.
   - Built-ins provide essential functionality such as **file manipulation, directory navigation, and environment management**.
   - **Examples:** `cd` (change directory), `dir` (list files), `echo` (display text), `set` (manage environment variables), and `exit` (close command prompt).

2. **External Executables**:  
   - These commands **call separate `.exe` files**, typically stored in **system directories** like `C:\Windows\System32\`.
   - External commands extend the shell’s capabilities by invoking system utilities and tools.
   - **Examples:** `ping.exe` (network testing), `ipconfig.exe` (network configuration), `tasklist.exe` (list running processes), and `robocopy.exe` (advanced file copy operations).

For example:
- `cd`, `dir`, `echo`, `set`, `exit` **are all built-ins** handled directly by `cmd.exe`.
- **Commands like** `ping`, `ipconfig`, `tasklist`, and `robocopy` are external, i.e. they invoke separate `.exe` files located in system directories (e.g. `C:\Windows\System32\`).

#### **Windows CMD built-in commands**

Windows **cmd.exe built-in commands** provide essential functionality for managing files, processes, networking, and system settings directly from the command line. **Built-in commands** are **internal functions** of `cmd.exe`, meaning they run within the shell itself rather than calling external binaries.

| Command | Description | Example Use Case |
|---------|------------|------------------|
| **cd** | Changes the current directory. | `cd C:\Users\tester\Documents` – Navigate to the Documents folder for user `tester`. |
| **dir** | Lists files and directories in the current folder. | `dir /s /b` – List all files in the current directory and subdirectories. |
| **echo** | Displays text or variables in the command prompt. | `echo Hello, World!` – Print "Hello, World!" to the screen. |
| **set** | Sets or displays environment variables. | `set PATH` – Show the current PATH variable. |
| **exit** | Closes the command prompt. | `exit` – Close the terminal session. |
| **cls** | Clears the command prompt screen. | `cls` – Wipe the screen clean. |
| **ver** | Displays the Windows version. | `ver` – Show the OS version number. |
| **help** | Displays help information for CMD commands. | `help dir` – Show details on how to use the `dir` command. |
| **copy** | Copies files from one location to another. | `copy file.txt D:\Backup\` – Copy `file.txt` to the `Backup` folder. |
| **move** | Moves files from one location to another. | `move file.txt D:\Backup\` – Move `file.txt` to the `Backup` folder. |
| **del** | Deletes files. | `del /F /Q file.txt` – Force delete `file.txt` without confirmation. |
| **ren** | Renames a file or folder. | `ren oldname.txt newname.txt` – Rename `oldname.txt` to `newname.txt`. |
| **mkdir** | Creates a new directory. | `mkdir C:\NewFolder` – Create a folder named `NewFolder`. |
| **rmdir** | Deletes a directory. | `rmdir /s /q C:\OldFolder` – Remove `OldFolder` and its contents. |
| **attrib** | Changes file attributes (hidden, read-only, etc.). | `attrib +H file.txt` – Hide `file.txt`. |
| **title** | Changes the title of the command prompt window. | `title Custom CMD Window` – Set the window title to "Custom CMD Window". |
| **prompt** | Changes the command prompt display style. | `prompt $P$G` – Set prompt to display the current path followed by `>`. |

#### Getting Help With Commands

Unlike Unix-based systems, Windows `cmd.exe` does not have traditional **`man` pages** for commands. Instead, Windows provides several methods to get help with command-line tools.

1. **Using the `help` command**  
   - Simply type `help` in the Command Prompt to see a **list of built-in commands**.  
   - To get help on a specific command:  
     ```bat
     help dir
     ```
     This will display basic information about the `dir` command.

2. **Using `command /?` for detailed help**  
   - Many commands support the `/?` flag, which provides more detailed usage instructions and available options.  
     ```bat
     dir /?
     ```
     This will list **all available parameters** for the `dir` command.
   - Some commands will even support this with `-?` in addition.  Windows commands do not all follow POSIX standardization.

3. **Checking Microsoft Docs (Online Documentation)**  
   - Microsoft provides extensive official documentation on Windows commands via **Microsoft Learn**.  
   - For example, the `dir` command documentation can be found at:  
     [https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/dir](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/dir)

### ***Useful Windows Utilities**

Most of these utilities can be found in `C:\Windows\System32\`.

#### **File and Directory Management**
TODO: fill this section
   - Perform operations like creating, deleting, copying, and moving files and directories.
   - Navigate the filesystem using commands like `cd`, `dir`, and `mkdir`.

#### **System Information**
TODO: fill this section
   - **`systeminfo`** – Displays **detailed system configuration details**, including OS version, CPU, memory, and installed updates. 
   - **`wmic OS get Caption, Version, BuildNumber`** – Retrieves **Windows OS version details** in a clean format without extra information.  This is useful for quickly checking Windows version details.

#### **Process and Task Management**
TODO: fill this section
   - View and manage running processes using commands like `tasklist`, `timeout`, and `taskkill`.
   - Launch applications or scripts directly from the shell.

#### **Networking Utilities**
TODO: fill this section
   - Troubleshoot and configure network settings with commands like `ping`, `ipconfig`, and `netstat`.
   - Manage network shares and connections using `net use` and `net share`.

#### The 'Net' Commands

The Windows **`net`** commands are a set of command-line tools that allow administrators and users to perform a variety of tasks related to system configurations, network services, and security. Here’s a **brief overview** of some of the key `net` commands:

| Command | Description | Example Use Case | Common Options |
|---------|------------|------------------|----------------|
| **net user** | Manages user accounts on a computer. You can add, remove, and modify users. | `net user tester /add` – Adds a new user named `tester`. | `/delete` – Remove a user, `/domain` – Execute on a domain controller. |
| **net localgroup** | Manages local groups on the computer. You can add, remove, and list members. | `net localgroup Administrators tester /add` – Adds `tester` to the Administrators group. | `/delete` – Remove a group, `/add` – Create a new group. |
| **net share** | Creates, deletes, and manages shared resources on the network. | `net share myshare=C:\MyFolder /grant:tester,full` – Creates a share named `myshare` with full access for user `tester`. | `/delete` – Stop sharing a resource, `/grant` – Assign access permissions. |
| **net start / stop** | Starts or stops network services. | `net start "Web Client"` – Starts the Web Client service. | Specify service names to start or stop. |
| **net session** | Displays all current sessions or disconnects them. | `net session \\RemotePC /delete` – Disconnects the session with `RemotePC`. | `/delete` – End a session. |
| **net use** | Connects, disconnects, and displays shared network resources. | `net use Z: \\Server\Share` – Maps the network share at `\\Server\Share` to the `Z:` drive. | `/delete` – Disconnect a network drive, `/persistent` – Make the connection persistent across reboots. |
| **net view** | Displays a list of computers or network resources. | `net view \\Server` – Shows shared resources on the server named `Server`. | `/domain` – List domains or computers in a domain. |
| **net accounts** | Displays or modifies password and logon policies for user accounts. | `net accounts /maxpwage:90` – Set maximum password age to 90 days. | `/forcelogoff` – Force logoff after inactivity, `/minpwlen` – Set minimum password length. |
| **net statistics** | Displays statistics for network services like Workstation or Server. | `net statistics workstation` – View workstation statistics. | Specify `workstation` or `server` for different stats. |
| **net print** | Displays or manages print jobs on a network printer. | `net print \\Server\Printer` – View print jobs on a shared printer. | `/delete` – Remove a print job. |
| **net file** | Displays open files on a network and allows closing them. | `net file` – View open files. | `/close` – Close an open file. |
| **net group** | Manages global groups on a domain. | `net group "IT Admins" /add` – Creates a new global group named "IT Admins". | `/delete` – Remove a group, `/add` – Create a new group. |
| **net time** | Synchronizes the system clock with a network time server. | `net time \\Server /set /yes` – Sync time with `Server`. | `/querysntp` – Query the SNTP time server. |
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

Windows **file attributes** are metadata properties assigned to files and folders that define their **visibility, accessibility, and behavior**. These attributes help control **read/write access, security settings, and system file classifications**.

File attributes can be **modified using built-in commands** like `attrib` in `cmd.exe` or PowerShell. Some attributes, such as **Read-Only and Hidden**, are commonly used for **file protection and organizational purposes**, while system attributes ensure that essential files are safeguarded from accidental modifications.

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
- **Can be inherited**: permissions assigned to a parent folder apply to subfolders and files.
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

TODO: finish this: Add explanation of what Rights are and how they differ from Permissions

Valid settings for Rights are as follows:

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

#### Valid Inherit settings:

| Setting          | Description                                      |
| ---------------- | ------------------------------------------------ |
| ContainerInherit | The ACE is inherited by child container objects. |
| None             | The ACE is not inherited by child objects.       |
| ObjectInherit    | The ACE is inherited by child leaf objects.      |

{% hint style="info" %}
Set the **`$InheritSettings`** to **`None`** if targeting a file instead of a folder.
{% endhint %}

#### Valid Propagation Settings: 

| Setting            | Description                                                                                                      |
| ------------------ | ---------------------------------------------------------------------------------------------------------------- |
| InheritOnly        | Specifies that the ACE is propagated only to child objects. This includes both container and leaf child objects. |
| None               | Specifies that no inheritance flags are set.                                                                     |
| NoPropagateInherit | Specifies that the ACE is not propagated to child objects.                                                       |



## Shared Folders/SMB

TODO: add descriptions, to include short description of how permissions differ from standard NTFS, and link to above section

TODO: add powershell examples of these

{% tabs %}
{% tab title="cmd.exe" %}

### Mount a remote CIFS/SMB share

```cmd
net use z: \\$ip\$sharename
#Adding /persistent:yes will make this survive reboots.
```

A great example is to mount the Sysinternals Live drive to use the tools directly from Microsoft:

```cmd
net use z: \live.sysinternals.com\tools\ /persistent:yes
```

The `/persistent:yes` argument makes the system add this permanently to the registry and reconnect to the same drive letter each time the comper boots.

### To remove a previously mounted share:

```cmd
net use z: /delete
```

{% endtab %}
{% tab title="PowerShell" %}

TODO: Powershell shares commands

{% endtab %}
{% endtabs %}

---

## **Environment Variables**

The command `set` will display all current environment variables and their values in cmd.exe. In PowerShell use `Get-ChildItem env:` (or one of its aliases!) to list environment variables.

Many of the environment variables in the cmd.exe column can be used in other places inside Windows as well, such as the Address Bar of a browser or Explorer window.

You can find more about Windows environment variables on the [PowerShell page](powershell.md#environment-variables).

Below is a comparison between the environment variables used in PowerShell versus those used in the classic cmd.exe environment (which are also used in many other places throughout Windows, such as Task Scheduler, Event logs, and more).

| Meaning                                           | PowerShell                      | cmd.exe                      |
| ------------------------------------------------- | ------------------------------- | ---------------------------- |
| C:\ProgramData                                    | $env:ALLUSERSPROFILE            | %ALLUSERSPROFILE%            |
| Current User's AppData\Roaming Folder             | $env:APPDATA                    | %APPDATA%                    |
| C:\Program Files\Common Files                     | $env:CommonProgramFiles         | %CommonProgramFiles%         |
| C:\Program Files (x86)\Common Files               | $env:CommonProgramFiles(x86)    | %CommonProgramFiles(x86)%    |
| C:\Program Files\Common Files                     | $env:CommonProgramW6432         | %CommonProgramW6432%         |
| Computer Name                                     | $env:COMPUTERNAME               | %COMPUTERNAME%               |
| C:\WINDOWS\system32\cmd.exe                       | $env:ComSpec                    | %ComSpec%                    |
| C:\Windows\System32\Drivers\DriverData            | $env:DriverData                 | %DriverData%                 |
| C:                                                | $env:HOMEDRIVE                  | %HOMEDRIVE%                  |
| Current User's home folder                        | $env:HOMEPATH                   | %HOMEPATH%                   |
| Current User's AppData\Local folder               | $env:LOCALAPPDATA               | %LOCALAPPDATA%               |
| UNC Path of Logon Server                          | $env:LOGONSERVER                | %LOGONSERVER%                |
| Number of Processor (cores)                       | $env:NUMBER\_OF\_PROCESSORS     | %NUMBER\_OF\_PROCESSORS%     |
| Current User's Onedrive folder                    | $env:OneDrive                   | %OneDrive%                   |
| Current User's Onedrive folder                    | $env:OneDriveConsumer           | %OneDriveConsumer%           |
| Operating System Family                           | $env:OS                         | %OS%                         |
| PATH to search when unspecified                   | $env:Path                       | %Path%                       |
| File Extensions that Windows will search PATH for | $env:PATHEXT                    | %PATHEXT%                    |
| Processor Architecture                            | $env:PROCESSOR\_ARCHITECTURE    | %PROCESSOR\_ARCHITECTURE%    |
| Processor ID                                      | $env:PROCESSOR\_IDENTIFIER      | %PROCESSOR\_IDENTIFIER%      |
| Processor Level                                   | $env:PROCESSOR\_LEVEL           | %PROCESSOR\_LEVEL%           |
| Processor Revision                                | $env:PROCESSOR\_REVISION        | %PROCESSOR\_REVISION%        |
| C:\ProgramData                                    | $env:ProgramData                | %ProgramData%                |
| C:\Program Files                                  | $env:ProgramFiles               | %ProgramFiles%               |
| C:\Program Files (x86)                            | $env:ProgramFiles(x86)          | %ProgramFiles(x86)%          |
| C:\Program Files                                  | $env:ProgramW6432               | %ProgramW6432%               |
| PATH for PowerShell Modules                       | $env:PSModulePath               | %PSModulePath%               |
| C:\Users\Public                                   | $env:PUBLIC                     | %PUBLIC%                     |
| Console                                           | $env:SESSIONNAME                | %SESSIONNAME%                |
| C:                                                | $env:SystemDrive                | %SystemDrive%                |
| C:\WINDOWS                                        | $env:SystemRoot                 | %SystemRoot%                 |
| Current User's AppData\Local\Temp Folder          | $env:TEMP                       | %TEMP%                       |
| Current User's AppData\Local\Temp Folder          | $env:TMP                        | %TMP%                        |
| Domain Name                                       | $env:USERDOMAIN                 | %USERDOMAIN%                 |
| Roaming Profile Domain                            | $env:USERDOMAIN\_ROAMINGPROFILE | %USERDOMAIN\_ROAMINGPROFILE% |
| User Name                                         | $env:USERNAME                   | %USERNAME%                   |
| User Home Folder                                  | $env:USERPROFILE                | %USERPROFILE%                |
| C:\WINDOWS                                        | $env:windir                     | %windir%                     |

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

## Powershell

PowerShell is a large and important enough topic that it has its [own page](powershell.md).

---

## References

- [Keyboard shortcuts in Windows](https://support.microsoft.com/en-us/windows/keyboard-shortcuts-in-windows-dcc61a57-8ff0-cffe-9796-cb9706c75eec)
- [Windows Process Genealogy](https://medium.com/@leo.valentic9/windows-process-genealogy-understanding-and-analyzing-key-system-processes-in-digital-forensics-a88cd5b9698f)

If you like this content and would like to see more, please consider [buying me a coffee](https://www.buymeacoffee.com/zweilosec)!
