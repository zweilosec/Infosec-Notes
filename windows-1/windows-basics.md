---
description: Commands and programs that all Windows users need to know (but many don't!).
---

# Windows Basics

## Sysinternals

#### This. [https://docs.microsoft.com/en-us/sysinternals/](https://docs.microsoft.com/en-us/sysinternals/)

If you don't know about Mark Russinovich's amazing tools then go and check them out.  Many, many use cases for a lot of these tools, from enumeration, persistence, threat-hunting, to ordinary system administration.

TODO: Add more information about Microsoft Sysinternals (issue [#23](https://github.com/zweilosec/Infosec-Notes/issues/23))
* Read about each tool and find the ones that work for Red Teaming
* Add highlights about best tools...psexec, accesschk, etc.
* Add examples of how to use each in a command-line only environment
* Link to relevant sections (privilege escalation, enumeration, etc.)

Sysinternals tools can be linked to directly and run in-memory from [https://live.sysinternals.com/](https://live.sysinternals.com/)

## CMD.EXE

### Useful cmd.exe programs

<table>
  <thead>
    <tr>
      <th style="text-align:center">Program name</th>
      <th style="text-align:left">Description</th>
    </tr>
  </thead>
  <tbody>
    <tr>
      <td style="text-align:center">assoc</td>
      <td style="text-align:left">
        <p>View all the file associations your computer knows</p>
        <ul>
          <li>You can set an association by typing <code>assoc .doc=Word.Document.8</code>
          </li>
        </ul>
      </td>
    </tr>
    <tr>
      <td style="text-align:center">attrib</td>
      <td style="text-align:left">
        <p>Change file attributes.</p>
        <ul>
          <li>Example: <code>ATTRIB +R +H C:\temp\file.txt</code> sets file.txt as a hidden,
            read-only file.</li>
          <li>There is no response when it&#x2019;s successful, so, unless you see an
            error message the command should have worked.</li>
        </ul>
      </td>
    </tr>
    <tr>
      <td style="text-align:center">bitsadmin</td>
      <td style="text-align:left">Initiate upload or download jobs over the network or internet and monitor
        the current state of those file transfers</td>
    </tr>
    <tr>
      <td style="text-align:center">chkdsk</td>
      <td style="text-align:left">
        <p></p>
        <p>Check the integrity of an entire drive.</p>
        <ul>
          <li>This command checks for file fragmentation errors, disk errors, and bad
            sectors. It will attempt to fix any disk errors. When the command is finished,
            you&#x2019;ll see the status of the scan and what actions were taken.</li>
          <li><code>CHKDSK /f C:</code> Check the C: drive and repair any problems (run
            as administrator) .</li>
        </ul>
      </td>
    </tr>
    <tr>
      <td style="text-align:center">color</td>
      <td style="text-align:left">Change the background color of the command prompt window</td>
    </tr>
    <tr>
      <td style="text-align:center">fc</td>
      <td style="text-align:left">
        <p>Performs either an ascii or a binary file comparison and lists all of
          the differences that it finds.</p>
        <ul>
          <li><code>fc /a &lt;file1.txt&gt; &lt;file2.txt&gt;</code>compare the contents
            of two ASCII text files.</li>
          <li><code>fc /b &lt;pic1.jpg&gt; &lt;pic2.jpg&gt;</code> will do a binary comparison
            of two images.</li>
        </ul>
      </td>
    </tr>
    <tr>
      <td style="text-align:center">findstr</td>
      <td style="text-align:left">
        <p>Search for strings inside of text files</p>
        <ul>
          <li>Supports multiple search strings</li>
          <li>Can take as input a file containing file names or directories to search</li>
          <li>Supports regular expressions</li>
          <li><code>grep</code> for Windows, essentially</li>
        </ul>
      </td>
    </tr>
    <tr>
      <td style="text-align:center">ipconfig /all</td>
      <td style="text-align:left">Get detailed information about your current network adapters. Includes:
        IP address, Subnet mask, Default gateway IP, Domain name</td>
    </tr>
    <tr>
      <td style="text-align:center">net</td>
      <td style="text-align:left">
        <p>many many...TODO: pick some of the most useful and add examples (issue [#24](https://github.com/zweilosec/Infosec-Notes/issues/24))</p>
        <p>net user</p>
        <p>net groups</p>
        <p>net share</p>
      </td>
    </tr>
    <tr>
      <td style="text-align:center">net use</td>
      <td style="text-align:left">
        <p></p>
        <p>Map a network drive.</p>
        <ul>
          <li>The <code>/persistent:yes</code> switch tells your computer that you want
            this drive remapped every time you log back into your computer.</li>
        </ul>
      </td>
    </tr>
    <tr>
      <td style="text-align:center">netstat</td>
      <td style="text-align:left">
        <p>Get a list of all active TCP connections.</p>
        <ul>
          <li>TODO: add more options (issue [#24](https://github.com/zweilosec/Infosec-Notes/issues/24))</li>
        </ul>
      </td>
    </tr>
    <tr>
      <td style="text-align:center">ping</td>
      <td style="text-align:left">
        <p>Test network connectivity.</p>
        <ul>
          <li>Test whether your computer can access another computer, a server, or even
            a website.</li>
          <li>Also provides the transit time for the packets in milliseconds.</li>
        </ul>
      </td>
    </tr>
    <tr>
      <td style="text-align:center">powercfg</td>
      <td style="text-align:left">
        <p>Configure power options</p>
        <ul>
          <li>to get a full power efficiency report <code>powercfg &#x2013; energy</code>
          </li>
        </ul>
      </td>
    </tr>
    <tr>
      <td style="text-align:center">prompt</td>
      <td style="text-align:left">Change the command prompt from <code>C:&gt;</code> to something else</td>
    </tr>
    <tr>
      <td style="text-align:center">regedit</td>
      <td style="text-align:left">Edit keys in the Windows registry</td>
    </tr>
    <tr>
      <td style="text-align:center">robocopy</td>
      <td style="text-align:left">A powerful file copy utility</td>
    </tr>
    <tr>
      <td style="text-align:center">schtasks</td>
      <td style="text-align:left">
        <p>Schedule tasks (similar to Unix cron).</p>
        <ul>
          <li>Example: <code>SCHTASKS /Create /SC HOURLY /MO 12 /TR &lt;task_name&gt; /TN c:\temp\script.bat</code>
          </li>
          <li><code>/sc</code> accepts arguments like minute, hourly, daily, and monthly</li>
          <li><code>/mo</code> specifies the frequency</li>
          <li><code>/tr</code> name of the task</li>
          <li>TODO: add more</li>
          <li>If you typed the command correctly, you&#x2019;ll see the response: <code>SUCCESS: The scheduled task &#x201C;&lt;task_name&gt;&#x201D; has successfully been created</code>
          </li>
          <li>Running this command with no parameters with display all currently scheduled
            tasks</li>
        </ul>
      </td>
    </tr>
    <tr>
      <td style="text-align:center">sfc</td>
      <td style="text-align:left">
        <p></p>
        <p>To check the integrity of protected system files (run cmd.exe as administrator
          first).</p>
        <ul>
          <li> <code>/scannow</code> will check the integrity of all protected system
            files. If a problem is found, the files will be repaired with backed-up
            system files.</li>
          <li><code>/VERIFYONLY</code>: Check the integrity but don&#x2019;t repair
            the files.</li>
          <li><code>/SCANFILE</code>: Scan the integrity of specific files and fix if
            corrupted.</li>
          <li><code>/VERIFYFILE</code>: Verify the integrity of specific files but don&#x2019;t
            repair them.</li>
          <li><code>/OFFBOOTDIR</code>: Use this to do repairs on an offline boot directory.</li>
          <li><code>/OFFWINDIR</code>: Use this to do repairs on an offline Windows
            directory.</li>
          <li><code>/OFFLOGFILE</code>: Specify a path to save a log file with scan
            results. (This scan can take up to 10 or 15 minutes).</li>
        </ul>
      </td>
    </tr>
    <tr>
      <td style="text-align:center">shutdown</td>
      <td style="text-align:left">
        <p>Shut down or restart the computer from the command line</p>
        <ul>
          <li><code>shutdown /i</code> will initiate a shutdown, but it will open a GUI
            window to give the user an option whether to restart or do a full shutdown.</li>
          <li>If you don&#x2019;t want to have a GUI window, you can use <code>shutdown /s</code> .</li>
          <li>There is a long list of other parameters you can use such as log off,
            hibernate, restart, and more. Just type <code>shutdown</code> without any
            arguments to see them all.</li>
        </ul>
      </td>
    </tr>
    <tr>
      <td style="text-align:center">systeminfo</td>
      <td style="text-align:left">
        <p>Get an overview of important system information</p>
        <ul>
          <li>Good for finding out processor details, the exact version of your Windows
            OS, installed updates, and more</li>
        </ul>
      </td>
    </tr>
    <tr>
      <td style="text-align:center">title</td>
      <td style="text-align:left">Change the title of the command prompt window.</td>
    </tr>
    <tr>
      <td style="text-align:center">tracert</td>
      <td style="text-align:left">
        <p>Trace route to remote host.</p>
        <p>Provides you with all of the following information:</p>
        <ul>
          <li>Number of hops (intermediate servers) before getting to the destination;</li>
          <li>Time it takes to get to each hop;</li>
          <li>The IP and sometimes the hostname of each hop</li>
        </ul>
      </td>
    </tr>
  </tbody>
</table>

## File manipulation

### Change file attributes

{% tabs %}
{% tab title="PowerShell" %}
Set a file as `Hidden`.  This can also be used to change other file property flags such as `Archive` and `ReadOnly`.

```text
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
Set a file as **Hidden** \(`-h`\).  This can also be used to change other file property flags such as \(`a`\) Archive and \(`r`\) ReadOnly. Flags must be added separately \(`-h -a -r` not `-har`\).

```text
#show the file attributes
attrib <C:\path\filename>

#add the 'hidden' attribute
attrib +h <C:\path\filename>

#to remove the 'hidden' property
attrib -h <C:\path\filename>
```
{% endtab %}
{% endtabs %}

## SMB

Mount a remote CIFS/SMB share `net use z: \\$ip\$sharename`. 

Adding `/persistent:yes` will make this survive reboots. 

A great example is: `net use z: \live.sysinternals.com\tools\ /persistent:yes` You can thank me later.

To remove a previously mounted share: `"net use z: /delete"`

## Powershell

PowerShell is a large and important enough topic that it has its [own page](powershell.md).  

