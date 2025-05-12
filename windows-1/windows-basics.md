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

The **Windows Command Prompt (`cmd.exe`)** is the legacy interface for executing text-based commands that control the operating system, automate tasks, and troubleshoot system issues. Unlike a graphical user interface (GUI), `cmd.exe` provides direct access to system functionalities through typed commands that can be chained together into automated scripts, making it a powerful tool for administrators, developers, and security professionals.

### **Use Cases for `cmd.exe`**

- **System Administration:** Modify system settings, manage processes, and configure user accounts.
- **Networking:** Troubleshoot connectivity, scan ports, and manage network shares.
- **Security & Forensics:** Analyze logs, check permissions, and identify suspicious activities.
- **Scripting & Automation:** Write batch scripts for repetitive tasks and scheduled jobs.
- **File & Directory Management:** Copy, move, delete, and modify file attributes efficiently.

### **Types of Commands in `cmd.exe`**

There are two primary types of commands that can be executed in `cmd.exe`:

1. **Built-in Commands**:  
   - These commands are **directly processed** within the `cmd.exe` shell, meaning they do **not** rely on external programs to execute.
   - Built-ins provide essential functionality such as **file manipulation, directory navigation, and environment management**.
   - **Examples:** `cd` (change directory), `dir` (list files), `echo` (display text), `set` (manage environment variables), and `exit` (close command prompt).

2. **External Executables**:  
   - These commands **call separate `.exe` files**, typically stored in **system directories** like `C:\Windows\System32\`.
   - External commands extend the shell’s native capabilities by invoking system utilities and tools.
   - **Examples:** `ping.exe` (network testing), `ipconfig.exe` (network configuration), `tasklist.exe` (list running processes), and `robocopy.exe` (advanced file copy operations).

For example:
- `cd`, `dir`, `echo`, `set`, `exit` are all **built-ins** handled directly by `cmd.exe`.
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

#### The 'Net' Commands

The **Windows `net` commands** are a set of command-line tools that allow administrators and users to perform essential tasks related to system configurations, network services, and security. Here’s a **brief overview** of some key `net` commands:

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
    ```
    bugcheckoncorrupt = 1
    ```
    A value of `1` indicates that the system will issue a bug check on corruption, while `0` disables this behavior.

  - **Command**:
    ```cmd
    fsutil behavior query bugcheckoncorrupt
    ```
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
  ```
  icacls C:\SensitiveData
  ```

**Grant Full Control:**  
  ```
  icacls C:\SensitiveData /grant tester:F
  ```

**Remove Permissions:**  
  ```
  icacls C:\SensitiveData /remove tester
  ```

{% endtab %}
{% tab title="PowerShell" %}

Copy permissions from one file or directory to another

```powershell
Get-ACL C:\File1 | Set-Acl C:\File2
```

Remove permissions from a folder or file

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

Advanced: Add a specific list of permissions to a Folder (or file)

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

### Windows Rights (TODO: finish this)

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

### Mount a remote CIFS/SMB share

```
net use z: \\$ip\$sharename
#Adding /persistent:yes will make this survive reboots.
```

A great example is to mount the Sysinternals Live drive to use the tools directly from Microsoft:

```
net use z: \live.sysinternals.com\tools\ /persistent:yes
```

You can thank me later.

### To remove a previously mounted share:

```
net use z: /delete
```

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

## **Explorer Navigation**

### Shortcuts <a href="#bypassing-path-restrictions" id="bypassing-path-restrictions"></a>

(TODO: Make table**s**)

CTRL+N (open new session), CTRL+R (Execute Commands), CTRL+SHIFT+ESC (Task Manager), Windows+E (open explorer), CTRL-B, CTRL-I (Favourites), CTRL-H (History), CTRL-L, CTRL-O (File/Open Dialog), CTRL-P (Print Dialog), CTRL-S (Save As)

Hidden Administrative menu: CTRL-ALT-F8, CTRL-ESC-F9

### **Shell URIs**

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

## Powershell

PowerShell is a large and important enough topic that it has its [own page](powershell.md).

## Thanks

If you like this content and would like to see more, please consider [buying me a coffee](https://www.buymeacoffee.com/zweilosec)!
