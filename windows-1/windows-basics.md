---
description: Commands and programs that all Windows users need to know (but many don't!).
---

# Windows Basics

## Sysinternals

#### This. [https://docs.microsoft.com/en-us/sysinternals/](https://docs.microsoft.com/en-us/sysinternals/)

If you don't know about Mark Russinovich's amazing tools go and check them out.  Many, many use cases for a lot of these tools, from enumeration, persistence, threat-hunting, to ordinary system administration.

...add highlights about best tools...psexec, accesschk, etc.

Sysinternals tools can be linked to directly and run in-memory from [https://live.sysinternals.com/](https://live.sysinternals.com/)

## SMB

Mount a remote CIFS/SMB share `net use z: \\<ip>\sharename`. Adding `/persistent:yes` will make this survive reboots. A great example is: `net use z: \live.sysinternals.com\tools\ /persistent:yes` You can thank me later.

Remove a previously mounted share: `"net use z: /delete"`

### CMD.EXE

* View all the file associations your computer knows: `assoc` You’ll see the file extension and the program it’s associated with. 
  * You can set an association by typing `assoc .doc=Word.Document.8`
* Compare files for differences: `fc` This command performs either an ascii or a binary file comparison and will list all of the differences that it finds. Examples:
  * `fc /a <file1.txt> <file2.txt>` will compare the contents of two ASCII text files. 
  * `fc /b <pic1.jpg> <pic2.jpg>` will do a binary comparison of two images.
* Get detailed information about your current network adapters with `ipconfig /all`.
  * Includes: Current IP address, Subnet mask, Default gateway IP, Domain name
* Get a list of all active TCP connections: `netstat` 
  * There are many useful options such as...TODO: add more 
* Test network connectivity: `ping <hostname or ip>`.  
  * You can use the `ping` command to test whether your computer can access another computer, a server, or even a website. 
  * Also provides the transit time for the packets in milliseconds.
* Trace route to remote host: `tracert <hostname or ip>` 
  * Sends packets out to a remote destination \(server or website\)
  * Provides you with all of the following information: 
    * Number of hops \(intermediate servers\) before getting to the destination; 
    * Time it takes to get to each hop; 
    * The IP and sometimes the hostname of each hop
  * It can be used to reveal how the routes of your internet requests change depending where you’re accessing the web, and helps with troubleshooting a router or switch on a local network that may be problematic.
* Configure power options: `powercfg`\(power configuration\) 
  * to get a full power efficiency report `powercfg – energy` .

Typing shutdown /i from the command prompt will initiate a shutdown, but it’ll upon a GUI to give the user an option on whether to restart or do a full shutdown. If you don’t want to have any GUI pop up, you can just issue a shutdown /s command. There is a long list of other parameters you can use to do a log off, hibernate, restart, and more. Just type shutdown without any arguments to see them all.

If you need to know what brand of network card you have, processor details, or the exact version of your Windows OS, the SYSTEMINFO command can help. This command polls your system and pulls the most important information about your system. It lists the information in a clean format that’s easy to read.

You need to launch CMD as administrator \(right click and choose Run as Administrator\). Typing SFC /SCANNOW will check the integrity of all protected system files. If a problem is found, the files will be repaired with backed-up system files. The SFC command also lets you: /VERIFYONLY: Check the integrity but don’t repair the files. /SCANFILE: Scan the integrity of specific files and fix if corrupted. /VERIFYFILE: Verify the integrity of specific files but don’t repair them. /OFFBOOTDIR: Use this to do repairs on an offline boot directory. /OFFWINDIR: Use this to do repairs on an offline Windows directory. /OFFLOGFILE: Specify a path to save a log file with scan results. The scan can take up to 10 or 15 minutes, so give it time.

If you want to map a new drive, you could always open File Explorer, right click on This PC, and go through the Map Network Drive wizard. However, using the NET USE command, you can do the same thing with one command string. For example, if you have a share folder on a computer on your network called \OTHER-COMPUTER\SHARE\, you can map this as your own Z: drive by typing the command: `Net use Z: “\\OTHER-COMPUTER\SHARE” /persistent:yes` The persistent switch tells your computer that you want this drive remapped every time you log back into your computer.

While the SFC command only checks the integrity of core system files, you can use the CHKDSK command to scan an entire drive. The command to check the C: drive and repair any problems, launch the command window as an administrator and type CHKDSK /f C:. This command checks for things like: File fragmentation Disk errors Bad sectors The command can fix any disk errors \(if possible\). When the command is finished, you’ll see a status of the scan and what actions were taken.

Windows comes with a wizard for creating scheduled tasks. For example, maybe you have a BAT file stored on C:\temp that you want to run every day at noon. You’d have to click through the Scheduled Task wizard to configure this. Or you can type a single SCHTASKS command to set it up. `SCHTASKS /Create /SC HOURLY /MO 12 /TR Example /TN c:\temp\File1.bat` The scheduled switch accepts arguments like minute, hourly, daily, and monthly. Then you specify the frequency with the /MO command. If you typed the command correctly, you’ll see the response, SUCCESS: The scheduled task “Example” has successfully been created.

In Windows, you can change file attributes by right clicking on a file and finding the right property to change. However, instead of hunting around for the file attribute, you can use the ATTRIB command to set the file attributes. For example, if you type: ATTRIB +R +H C:\temp\File1.bat, it’ll set File1.bat as a hidden, read-only file. There is no response when it’s successful, so unless you see an error message, the command worked.

Other Windows CMD Commands

BITSADMIN: Initiate upload or download jobs over the network or internet and monitor the current state of those file transfers. COLOR: Change the background color of the command prompt window. COMP: Compare the contents of any two files to see the differences. FIND/FINDSTR: Search for strings inside of any ASCII files. PROMPT: Change the command prompt from C:&gt; to something else. TITLE: Change the title of the command prompt window. REGEDIT: Edit keys in the Windows registry \(use with caution\). ROBOCOPY: A powerful file copy utility built right into Windows.

### Powershell

Show all current environment variables in PowerShell: `dir env:` \(in CMD just type `set`\)

Get tons of computer info in PowerShell: `Get-ComputerInfo`

