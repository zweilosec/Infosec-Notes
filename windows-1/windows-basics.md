---
description: Commands and programs that all Windows users need to know (but many don't!).
---

# Windows Fundamentals

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
- **Commands like** `ping`, `ipconfig`, `tasklist`, and `robocopy` **are external**—they invoke separate `.exe` files located in system directories (e.g., `C:\Windows\System32\`).

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

## File manipulation

### Change file attributes

{% tabs %}
{% tab title="PowerShell" %}
Set a file as `Hidden`. This can also be used to change other file property flags such as `Archive` and `ReadOnly`.

```
$file = (Get-ChildItem $file) #can shorten command with gci or ls
$file.attributes #Show the files attributes
Normal

#Flip the bit of the Hidden attribute
$file.attributes = $file.Attributes -bxor ([System.IO.FileAttributes]::Hidden)
$file.attributes
Hidden

#To remove the 'Hidden' attribute
$file.attributes = $file.Attributes -bxor ([System.IO.FileAttributes]::Hidden)
$file.attributes
Normal
```
{% endtab %}

{% tab title="cmd.exe" %}
Set a file as **Hidden** (`-h`). This can also be used to change other file property flags such as (`a`) Archive and (`r`) ReadOnly. Flags must be added separately (`-h -a -r` not `-har`).

```
#show the file attributes
attrib <C:\path\filename>

#add the 'hidden' attribute
attrib +h <C:\path\filename>

#to remove the 'hidden' property
attrib -h <C:\path\filename>
```
{% endtab %}
{% endtabs %}

### Changing file permissions

[https://ss64.com/nt/icacls.html](https://ss64.com/nt/icacls.html) Interesting permissions

#### Windows icacls file permissions

D - Delete access

F - Full access (Edit\_Permissions+Create+Delete+Read+Write)

N - No access

M - Modify access (Create+Delete+Read+Write)

RX - Read and eXecute access

R - Read-only access

W - Write-only access

{% tabs %}
{% tab title="PowerShell" %}
#### Copy permissions from one file or directory to another

```powershell
Get-ACL C:\File1 | Set-Acl C:\File2
```

#### Add specific permissions to a Folder (or file)

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

#### Valid settings for Rights are as follows: <a href="#valid-settings-for-rights-are-as-follows" id="valid-settings-for-rights-are-as-follows"></a>

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

#### Valid Inherit settings: <a href="#valid-inherit-settings" id="valid-inherit-settings"></a>

| Setting          | Description                                      |
| ---------------- | ------------------------------------------------ |
| ContainerInherit | The ACE is inherited by child container objects. |
| None             | The ACE is not inherited by child objects.       |
| ObjectInherit    | The ACE is inherited by child leaf objects.      |

{% hint style="info" %}
Set the **`$InheritSettings`** to **`None`** if targeting a file instead of a folder.
{% endhint %}

#### Valid Propagation Settings: <a href="#valid-propagation-settings" id="valid-propagation-settings"></a>

| Setting            | Description                                                                                                      |
| ------------------ | ---------------------------------------------------------------------------------------------------------------- |
| InheritOnly        | Specifies that the ACE is propagated only to child objects. This includes both container and leaf child objects. |
| None               | Specifies that no inheritance flags are set.                                                                     |
| NoPropagateInherit | Specifies that the ACE is not propagated to child objects.                                                       |

#### Remove permissions from a folder or file

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
{% endtab %}

{% tab title="cmd.exe" %}

{% endtab %}
{% endtabs %}

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
