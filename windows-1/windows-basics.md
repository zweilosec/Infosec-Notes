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

| Program name  | Description                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                   |
| ------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| assoc         | <p>View all the file associations your computer knows</p><ul><li>You can set an association by typing <code>assoc .doc=Word.Document.8</code></li></ul>                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                       |
| attrib        | <p>Change file attributes.</p><ul><li>Example: <code>ATTRIB +R +H C:\temp\file.txt</code> sets file.txt as a hidden, read-only file.</li><li>There is no response when it’s successful, so, unless you see an error message the command should have worked.</li></ul>                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                         |
| bitsadmin     | Initiate upload or download jobs over the network or internet and monitor the current state of those file transfers                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                           |
| chkdsk        | <p>Check the integrity of an entire drive.</p><ul><li>This command checks for file fragmentation errors, disk errors, and bad sectors. It will attempt to fix any disk errors. When the command is finished, you’ll see the status of the scan and what actions were taken.</li><li><code>CHKDSK /f C:</code> Check the C: drive and repair any problems (run as administrator) .</li></ul>                                                                                                                                                                                                                                                                                                                                                                                                                                                                                   |
| color         | Change the background color of the command prompt window                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                      |
| fc            | <p>Performs either an ascii or a binary file comparison and lists all of the differences that it finds.</p><ul><li><code>fc /a &#x3C;file1.txt> &#x3C;file2.txt></code>compare the contents of two ASCII text files.</li><li><code>fc /b &#x3C;pic1.jpg> &#x3C;pic2.jpg></code> will do a binary comparison of two images.</li></ul>                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                          |
| findstr       | <p>Search for strings inside of text files</p><ul><li>Supports multiple search strings</li><li>Can take as input a file containing file names or directories to search</li><li>Supports regular expressions</li><li><code>grep</code> for Windows, essentially</li></ul>                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                      |
| ipconfig /all | Get detailed information about your current network adapters. Includes: IP address, Subnet mask, Default gateway IP, Domain name                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                              |
| net           | <p>many many...TODO: pick some of the most useful and add examples (issue [#24](https://github.com/zweilosec/Infosec-Notes/issues/24))</p><p>net user</p><p>net groups</p><p>net share</p>                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                    |
| net use       | <p>Map a network drive.</p><ul><li>The <code>/persistent:yes</code> switch tells your computer that you want this drive remapped every time you log back into your computer.</li></ul>                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                        |
| netstat       | <p>Get a list of all active TCP connections.</p><ul><li>TODO: add more options (issue [#24](https://github.com/zweilosec/Infosec-Notes/issues/24))</li></ul>                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                  |
| ping          | <p>Test network connectivity.</p><ul><li>Test whether your computer can access another computer, a server, or even a website.</li><li>Also provides the transit time for the packets in milliseconds.</li></ul>                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                               |
| powercfg      | <p>Configure power options</p><ul><li>to get a full power efficiency report <code>powercfg – energy</code></li></ul>                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                          |
| prompt        | Change the command prompt from `C:>` to something else                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                        |
| regedit       | Edit keys in the Windows registry                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                             |
| robocopy      | A powerful file copy utility                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                  |
| schtasks      | <p>Schedule tasks (similar to Unix cron).</p><ul><li>Example: <code>SCHTASKS /Create /SC HOURLY /MO 12 /TR &#x3C;task_name> /TN c:\temp\script.bat</code></li><li><code>/sc</code> accepts arguments like minute, hourly, daily, and monthly</li><li><code>/mo</code> specifies the frequency</li><li><code>/tr</code> name of the task</li><li>TODO: add more</li><li>If you typed the command correctly, you’ll see the response: <code>SUCCESS: The scheduled task “&#x3C;task_name>” has successfully been created</code></li><li>Running this command with no parameters with display all currently scheduled tasks</li></ul>                                                                                                                                                                                                                                            |
| sfc           | <p>To check the integrity of protected system files (run cmd.exe as administrator first).</p><ul><li> <code>/scannow</code> will check the integrity of all protected system files. If a problem is found, the files will be repaired with backed-up system files.</li><li><code>/VERIFYONLY</code>: Check the integrity but don’t repair the files.</li><li><code>/SCANFILE</code>: Scan the integrity of specific files and fix if corrupted.</li><li><code>/VERIFYFILE</code>: Verify the integrity of specific files but don’t repair them.</li><li><code>/OFFBOOTDIR</code>: Use this to do repairs on an offline boot directory.</li><li><code>/OFFWINDIR</code>: Use this to do repairs on an offline Windows directory.</li><li><code>/OFFLOGFILE</code>: Specify a path to save a log file with scan results. (This scan can take up to 10 or 15 minutes).</li></ul> |
| shutdown      | <p>Shut down or restart the computer from the command line</p><ul><li><code>shutdown /i</code> will initiate a shutdown, but it will open a GUI window to give the user an option whether to restart or do a full shutdown.</li><li>If you don’t want to have a GUI window, you can use <code>shutdown /s</code> .</li><li>There is a long list of other parameters you can use such as log off, hibernate, restart, and more. Just type <code>shutdown</code> without any arguments to see them all.</li></ul>                                                                                                                                                                                                                                                                                                                                                               |
| systeminfo    | <p>Get an overview of important system information</p><ul><li>Good for finding out processor details, the exact version of your Windows OS, installed updates, and more</li></ul>                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                             |
| title         | Change the title of the command prompt window.                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                |
| tracert       | <p>Trace route to remote host.</p><p>Provides you with all of the following information:</p><ul><li>Number of hops (intermediate servers) before getting to the destination;</li><li>Time it takes to get to each hop;</li><li>The IP and sometimes the hostname of each hop</li></ul>                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                        |

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

## Shared Folders/SMB

### Mount a remote CIFS/SMB share&#x20;

```
net use z: \\$ip\$sharename
#Adding /persistent:yes will make this survive reboots.
```

A great example is to mount the Sysinternals Live drive to use the tools directly from Microsoft:&#x20;

```
net use z: \live.sysinternals.com\tools\ /persistent:yes
```

You can thank me later.

### To remove a previously mounted share:

```
net use z: /delete
```



## **Environment Variables**

The command `set` will display all current environment variables and their values in cmd.exe.  In PowerShell use `Get-ChildItem env:` (or one of its aliases!) to list environment variables.

Many of the environment variables in the cmd.exe column can be used in other places inside Windows as well, such as the Address Bar of a browser or Explorer window.

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
