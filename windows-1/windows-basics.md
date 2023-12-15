---
description: Commands and programs that all Windows users need to know (but many don't!).
---

# Windows Basics

## Sysinternals

#### This. [https://docs.microsoft.com/en-us/sysinternals/](https://docs.microsoft.com/en-us/sysinternals/)

If you don't know about Mark Russinovich's amazing tools then go and check them out. Many, many use cases for a lot of these tools, from enumeration, persistence, threat-hunting, to ordinary system administration.

TODO: Add more information about Microsoft Sysinternals (issue [#23](https://github.com/zweilosec/Infosec-Notes/issues/23))

* Read about each tool and find the ones that work for Red Teaming
* Add highlights about best tools...psexec, accesschk, etc.
* Add examples of how to use each in a command-line only environment
* Link to relevant sections (privilege escalation, enumeration, etc.)

Sysinternals tools can be linked to directly and run in-memory from [https://live.sysinternals.com/](https://live.sysinternals.com/)

## CMD.EXE

### Useful cmd.exe programs

| Program name                                                            | Description                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                               |
| ----------------------------------------------------------------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| assoc                                                                   | <p>View all the file associations your computer knows</p><ul><li>You can set an association by typing <code>assoc .doc=Word.Document.8</code></li></ul>                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                   |
| attrib                                                                  | <p>Change file attributes.</p><ul><li>Example: <code>ATTRIB +R +H C:\temp\file.txt</code> sets file.txt as a hidden, read-only file.</li><li>There is no response when it’s successful, so, unless you see an error message the command should have worked.</li></ul>                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                     |
| bitsadmin                                                               | Initiate upload or download jobs over the network or internet and monitor the current state of those file transfers                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                       |
| chkdsk                                                                  | <p>Check the integrity of an entire drive.</p><ul><li>This command checks for file fragmentation errors, disk errors, and bad sectors. It will attempt to fix any disk errors. When the command is finished, you’ll see the status of the scan and what actions were taken.</li><li><code>CHKDSK /f C:</code> Check the C: drive and repair any problems (run as administrator) .</li></ul>                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                               |
| color                                                                   | Change the background color of the command prompt window                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                  |
| fc                                                                      | <p>Performs either an ascii or a binary file comparison and lists all of the differences that it finds.</p><ul><li><code>fc /a &#x3C;file1.txt> &#x3C;file2.txt></code>compare the contents of two ASCII text files.</li><li><code>fc /b &#x3C;pic1.jpg> &#x3C;pic2.jpg></code> will do a binary comparison of two images.</li></ul>                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                      |
| findstr                                                                 | <p>Search for strings inside of text files</p><ul><li>Supports multiple search strings</li><li>Can take as input a file containing file names or directories to search</li><li>Supports regular expressions</li><li><code>grep</code> for Windows, essentially</li></ul>                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                  |
| ipconfig /all                                                           | Get detailed information about your current network adapters. Includes: IP address, Subnet mask, Default gateway IP, Domain name                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                          |
| net (issue [#24](https://github.com/zweilosec/Infosec-Notes/issues/24)) | The net commands are a suite of command-line utilities in Windows that allow you to manage various aspects of a network and its settings. Below are brief descriptions of some of the net commands along with examples and common use cases                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                               |
| net user                                                                | <p>This command is used to manage user accounts on a computer. You can add, remove, and modify user accounts.</p><p>Example: <code>net user John /add</code> adds a new user named John.</p><p>Common options: <code>/delete</code> to remove a user, <code>/domain</code> to execute the command on a domain controller.</p>                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                             |
| net localgroup                                                          | <p>This command manages local groups on the computer. You can add, remove, and list members of a local group.</p><p>Example: <code>net localgroup Administrators John /add</code> adds John to the Administrators group.</p><p>Common options: <code>/delete</code> to remove a group, <code>/add</code> to add a new group.</p>                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                          |
| net share                                                               | <p>This command is used to create, delete, and manage shared resources on the network.</p><p>Example: <code>net share myshare=C:\MyFolder /grant:John,full</code> creates a share named myshare with full access for John.</p><p>Common options: <code>/delete</code> to stop sharing a resource, <code>/grant</code> to grant access permissions.</p>                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                    |
| net start/stop                                                          | <p>These commands are used to start and stop network services.</p><p>Example: <code>net start "Web Client"</code> starts the Web Client service.</p><p>Common options: Service names to specify which service to start or stop.</p>                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                       |
| net session                                                             | <p>This command displays all current sessions (with no options) or disconnects sessions between the computer and others on the network.</p><p>Example: <code>net session \\RemotePC /delete</code> disconnects the session with the computer named RemotePC.</p><p>Common options: <code>/delete</code> to end a session.</p>                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                             |
| net use                                                                 | <p>This command connects, disconnects, and displays information about shared network resources.</p><p>Example: <code>net use Z: \\Server\Share</code> maps the network share at \Server\Share to the Z: drive.</p><p>Common options: <code>/delete</code> to disconnect a network drive, <code>/persistent</code> to make the connection persistent across reboots.</p>                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                   |
| net view                                                                | <p>This command displays a list of computers or network resources.</p><p>Example: <code>net view \\Server</code> shows shared resources on the server named Server.</p><p>Common options: <code>/domain</code> to list domains or computers in a domain.</p>                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                              |
| net accounts                                                            | <p>This command configures password and logon requirements for users.</p><p>Example: <code>net accounts /maxpwage:30</code> sets the maximum password age to 30 days.</p><p>Common options: <code>/forcelogoff</code>, <code>/minpwlen</code>, <code>/maxpwage</code> to set various account policies.</p>                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                |
| net statistics                                                          | <p>This command displays the statistics log for the server or workstation service.</p><p>Example: <code>net statistics workstation</code> shows statistics for the workstation service.</p><p>Common options: server to view server service statistics.</p>                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                               |
| net config                                                              | <p>This command displays the configuration of the server or workstation service.</p><p>Example: <code>net config server</code> shows the configuration of the server service.</p><p>Common options: workstation to view workstation service configuration.</p>                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                            |
| netstat                                                                 | <p>Provides an overview of network activities and displays which ports are open or have established connections (default display active TCP connections). Common arguments: </p><ul><li><code>-a</code>: Displays all active TCP connections and the listening TCP and UDP ports.</li><li><code>-b</code>: Displays the executable involved in creating each connection or listening port.</li><li><code>-e</code>: Displays Ethernet statistics, such as the number of bytes and packets sent and received.</li><li><code>-n</code>: Host addresses and port numbers are expressed numerically with no name resolution.</li><li><code>-o</code>: Displays the process identifier (PID) associated with each connection.</li><li><code>-p &#x3C;Protocol></code>: Shows connections for the protocol specified by <code>Protocol</code> from <code>tcp</code>, <code>udp</code>, <code>tcpv6</code>, or <code>udpv6</code>.</li><li><code>-r</code>: Displays the IP routing table.</li><li><code>-s</code>: Displays statistics by protocol.</li><li><code>&#x3C;interval></code>: Redisplays the selected information every <code>interval</code> seconds. Press <code>CTRL+C</code> to stop.</li></ul> |
| ping                                                                    | <p>Test network connectivity.</p><ul><li>Test whether your computer can access another computer, a server, or even a website.</li><li>Also provides the transit time for the packets in milliseconds.</li></ul>                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                           |
| powercfg                                                                | <p>Configure power options</p><ul><li>to get a full power efficiency report <code>powercfg – energy</code></li></ul>                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                      |
| prompt                                                                  | Change the command prompt from `C:>` to something else                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                    |
| regedit                                                                 | Edit keys in the Windows registry                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                         |
| robocopy                                                                | A powerful file copy utility                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                              |
| schtasks                                                                | <p>Schedule tasks (similar to Unix cron).</p><ul><li>Example: <code>SCHTASKS /Create /SC HOURLY /MO 12 /TR &#x3C;task_name> /TN c:\temp\script.bat</code></li><li><code>/sc</code> accepts arguments like minute, hourly, daily, and monthly</li><li><code>/mo</code> specifies the frequency</li><li><code>/tr</code> name of the task</li><li>TODO: add more</li><li>If you typed the command correctly, you’ll see the response: <code>SUCCESS: The scheduled task “&#x3C;task_name>” has successfully been created</code></li><li>Running this command with no parameters with display all currently scheduled tasks</li></ul>                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                        |
| sfc                                                                     | <p>To check the integrity of protected system files (run cmd.exe as administrator first).</p><ul><li><code>/scannow</code> will check the integrity of all protected system files. If a problem is found, the files will be repaired with backed-up system files.</li><li><code>/VERIFYONLY</code>: Check the integrity but don’t repair the files.</li><li><code>/SCANFILE</code>: Scan the integrity of specific files and fix if corrupted.</li><li><code>/VERIFYFILE</code>: Verify the integrity of specific files but don’t repair them.</li><li><code>/OFFBOOTDIR</code>: Use this to do repairs on an offline boot directory.</li><li><code>/OFFWINDIR</code>: Use this to do repairs on an offline Windows directory.</li><li><code>/OFFLOGFILE</code>: Specify a path to save a log file with scan results. (This scan can take up to 10 or 15 minutes).</li></ul>                                                                                                                                                                                                                                                                                                                              |
| shutdown                                                                | <p>Shut down or restart the computer from the command line</p><ul><li><code>shutdown /i</code> will initiate a shutdown, but it will open a GUI window to give the user an option whether to restart or do a full shutdown.</li><li>If you don’t want to have a GUI window, you can use <code>shutdown /s</code> .</li><li>There is a long list of other parameters you can use such as log off, hibernate, restart, and more. Just type <code>shutdown</code> without any arguments to see them all.</li></ul>                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                           |
| systeminfo                                                              | <p>Get an overview of important system information</p><ul><li>Good for finding out processor details, the exact version of your Windows OS, installed updates, and more</li></ul>                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                         |
| title                                                                   | Change the title of the command prompt window.                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                            |
| tracert                                                                 | <p>Trace route to remote host.</p><p>Provides you with all of the following information:</p><ul><li>Number of hops (intermediate servers) before getting to the destination;</li><li>Time it takes to get to each hop;</li><li>The IP and sometimes the hostname of each hop</li></ul>                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                    |

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
