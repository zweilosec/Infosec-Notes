---
description: Commands and programs that all Linux users need to know (but many don't!)
---

# Linux Basics

TODO: Add screenshots/code examples for each command; put commands in tables; clean and organize all (issue [#7](../../../issues/7))

## Command-line Basics

<table>
  <thead>
    <tr>
      <th style="text-align:left">Command</th>
      <th style="text-align:left">Description</th>
    </tr>
  </thead>
  <tbody>
    <tr>
      <td style="text-align:left"><code>man $command</code>
      </td>
      <td style="text-align:left">Get help with a command</td>
    </tr>
    <tr>
      <td style="text-align:left"><code>history</code>
      </td>
      <td style="text-align:left">View history of commands that have been typed into the terminal</td>
    </tr>
    <tr>
      <td style="text-align:left"><code>!&lt;number&gt;</code>
      </td>
      <td style="text-align:left">Repeat a specific command from command history</td>
    </tr>
    <tr>
      <td style="text-align:left"><code>Ctrl + r</code>
      </td>
      <td style="text-align:left">Search through command history: then cycle with Up or Down arrows. (Do
        not need to type <code>history</code> command first)</td>
    </tr>
    <tr>
      <td style="text-align:left"><code>alt + .</code>
      </td>
      <td style="text-align:left">Cycle through previously used command arguments</td>
    </tr>
    <tr>
      <td style="text-align:left"><code>ctrl + [arrow_keys]</code>
      </td>
      <td style="text-align:left">Move between &quot;words&quot; on a command line</td>
    </tr>
    <tr>
      <td style="text-align:left"><code>clear</code>
      </td>
      <td style="text-align:left">Clear all text off the terminal window</td>
    </tr>
    <tr>
      <td style="text-align:left"><code>echo $text</code>
      </td>
      <td style="text-align:left">
        <p>Print string to terminal.</p>
        <ul>
          <li>Most useful when piped into other commands.</li>
          <li>Can be used to display environment variables such as <code>$USER</code>, <code>$HOME</code>, <code>$PATH</code>
          </li>
        </ul>
      </td>
    </tr>
    <tr>
      <td style="text-align:left"><code>Ctrl + Shift + c</code>
      </td>
      <td style="text-align:left">Copy selected text</td>
    </tr>
    <tr>
      <td style="text-align:left"><code>Ctrl + Shift + v</code>
      </td>
      <td style="text-align:left">Paste clipboard contents</td>
    </tr>
    <tr>
      <td style="text-align:left"><code>lp $filename</code>
      </td>
      <td style="text-align:left">Print from file to printer</td>
    </tr>
    <tr>
      <td style="text-align:left"><code>cd $directory</code>
      </td>
      <td style="text-align:left">Change directories</td>
    </tr>
    <tr>
      <td style="text-align:left"><code>cd ..</code>
      </td>
      <td style="text-align:left">Move up one directory</td>
    </tr>
    <tr>
      <td style="text-align:left"><code>cd ~</code>
      </td>
      <td style="text-align:left">Change directory to current user&apos;s home directory</td>
    </tr>
    <tr>
      <td style="text-align:left"><code>cd -</code>
      </td>
      <td style="text-align:left">Return to previous directory</td>
    </tr>
    <tr>
      <td style="text-align:left"><code>exit</code>
      </td>
      <td style="text-align:left">Exit terminal session</td>
    </tr>
  </tbody>
</table>

### Special Symbols

| `Symbol` | Purpose |
| :--- | :--- |
| `|` | Send the output of one command to another. |
| `>` | Redirect output to a file. |
| `<` | Redirect input from a file. |
| `>>` | Append output to an existing file. |
| `/` | Separator used in path names. |
| `\` | Used to escape characters and to send multi-line commands. |
| `.` | Current directory. |
| `..` | Parent directory. |
| `&` | Process command in the background \(and give control of the terminal back. |
| `&&` | Run the next command only if the previous completed successfully. |
| `*` | Match any number of characters in file name. |
| `?` | Match any single character in file name. |
| `[ ]` | Match any one of the enclosed characters in file name. |
| `;` | Run commands in sequence, regardless if the previous succeeded. |
| `( )` | Group commands. |
| `!!` | Repeat the previous command. |

### Recover an unresponsive terminal

1. Press the **RETURN/ENTER** key.

   You may have typed a command but forgotten to press **RETURN** to tell the shell that you’re done typing and it should now interpret the command.

2. If you can type commands, but nothing happens when you press **RETURN**, try typing **CTRL-J**. If this works, your terminal needs to be reset to fix the **RETURN** key. Some systems have a **reset** command that you can run by typing **CTRL-J** **reset** **CTRL-J**. If this doesn’t work, you may need to log out and log back in or turn your terminal off and on again.
3. If your shell has job control type **CTRL-Z**.

   This suspends a program that may be running and gives you another shell prompt. Now you can enter the **jobs** command to find the program’s name, then restart the program with **fg** or terminate it with **kill**.

4. Use your interrupt key \(typically **DELETE** or **CTRL-C\)**.

   This interrupts a program that may be running. \(Unless a program is run in the background as the shell will wait for it to finish before giving a new prompt. A long-running program may thus appear to hang the terminal.\) If this doesn’t work the first time, try it once more, though doing it more than twice usually won’t help.

5. Type **CTRL-Q**.

   If output has been stopped with **CTRL-S**, this will restart it. \(Note that some systems will automatically issue **CTRL-S** if they need to pause output; this character may not have been typed by the user from the keyboard.\)

6. Check that the **SCROLL LOCK** key is not toggled on.

   This key stops the screen display from scrolling upward. If pressing it once does not work, make sure you’ve pressed it an even number of times as this leaves the key in the same state it was when you started.

7. Type **CTRL-D** at the beginning of a new line.

   Some programs \(like **mail**\) expect text from the user. A program may be waiting for an end-of-input character from you to tell it that you’ve finished entering text. However, typing **CTRL-D** may cause you to log out, so you should only try this as a last resort.

8. If you’re using a windowing system, close \(or terminate\) the terminal window and open a new one. 

## Filesystem Basics

Everything in Linux is are files, even directories and devices. Directories have some special restrictions, but for the most part can be treated like files.

### Listing and viewing Directories and Files

<table>
  <thead>
    <tr>
      <th style="text-align:left">Command</th>
      <th style="text-align:left">Description</th>
    </tr>
  </thead>
  <tbody>
    <tr>
      <td style="text-align:left"><code>ls -a</code>
      </td>
      <td style="text-align:left">
        <p></p>
        <p>List files in a folder, to include hidden files:</p>
        <ul>
          <li>Hidden files in Linux begin with a <b><code>.</code></b> these files can
            still be accessed normally, but the <b><code>.</code></b> must be added to
            the name.</li>
        </ul>
      </td>
    </tr>
    <tr>
      <td style="text-align:left"><code>ls -la</code>
      </td>
      <td style="text-align:left">List files with attributes (filesize, permissions, etc.)</td>
    </tr>
    <tr>
      <td style="text-align:left"><code>ls -lS</code>
      </td>
      <td style="text-align:left">List files, sorted by Size</td>
    </tr>
    <tr>
      <td style="text-align:left"><code>ls -R</code>
      </td>
      <td style="text-align:left">List files in current folder and all subfolders (Recursive)</td>
    </tr>
    <tr>
      <td style="text-align:left"><code>find -L /          -samefile $file</code>
      </td>
      <td style="text-align:left">Locate all files that symlink to a file</td>
    </tr>
    <tr>
      <td style="text-align:left"><code>df</code>
      </td>
      <td style="text-align:left">List the size, used space, and available space on the mounted filesystems
        of your computer</td>
    </tr>
    <tr>
      <td style="text-align:left"><code>cat $file</code>
      </td>
      <td style="text-align:left">Print the contents of a file to the command line</td>
    </tr>
    <tr>
      <td style="text-align:left"><code>cat $file1 $file2 &gt; $newfile</code>
      </td>
      <td style="text-align:left">Combine the contents of two text files</td>
    </tr>
    <tr>
      <td style="text-align:left"><code>diff</code>
      </td>
      <td style="text-align:left">Compare two files and show differences</td>
    </tr>
    <tr>
      <td style="text-align:left">Search for string inside a file</td>
      <td style="text-align:left"><code>grep $string $file</code>
      </td>
    </tr>
  </tbody>
</table>

### File and Directory Creation, Modification, and Deletion

| Command | Description |
| :--- | :--- |
|  |  |

To create a new file `touch <filename>` or

```text
cat > $fileName
 [Type your file contents]
 [Press `Ctrl+d` to return to your terminal]
```

Create a new directory: `mkdir [/path/to/]<dirname>`

Remove a file from the filesystem: `rm <filename>`

Remove a directory from the filesystem: `rmdir <dirname>`

Remove all instances of a certain file. `sudo rm --force $(which <file_name>)` \(Could be used with `find` or `locate` instead of `which`. Dangerous with --force!!\)

Copy a file/directory to another location \(or name\): `cp <file> [/path/to/]<filename>`

Move a file/directory to another location \(or rename\): `mv <file> [/path/to/]<filename>`

### File Permissions

TODO: Add more here...include descriptions and examples

`chmod -ugo -rwx -7777 5KFB6`

`chown $user $group $file`

## System Information

| Command | Description |
| :--- | :--- |
| `uname -a` | List OS, hostname, kernel build number, CPU architecture |
| `ps` | List running processes \(current user\) |
| `ps aux` | List running processes for all users \(if permitted\) |
| `top` | Similar to Windows Task Manager, lists running processes with details of hardware usage |

## Networking

| Command | Description |
| :--- | :--- |
| `ifconfig` | Get networking information \(IP, Subnet mask, MAC, etc.\); On some systems may require **`sudo`** rights |
| `ip a` | Get networking information \(IP, Subnet mask, MAC, etc.\); No **`sudo`** required. Newer |
| `ifconfig $interface $ip/$CIDR` | Set IP address for an interface |
| `ifconfig $interface mtu $size` | Change MTU size for an interface |
| `ifconfig $interface hw ether $new_MAC` | Change MAC address \(or use `macchanger`\) |

### Managing connections

TODO: add more, include description and examples

| Command | Description |
| :--- | :--- |
|  |  |

nc

nc listener: `nc -lvnp <port>`

curl

wget

list open network connections: `lsof -i`

`ss`

`netstat`

### Shared folders

| Command | Description |
| :--- | :--- |
| `showmount -e $ip` | Show available shares to mount |
| `smb://$ip/$share_name` | Connect to Windows SMB share folder |

TODO: pull more from [HTB Writeups](https://zweilosec.gitbook.io/htb-writeups/)

### DNS

| Command | Description |
| :--- | :--- |
| `dig @$server $domain_or_ip $record_type` | Look up DNS information for a site |
| `dig -x $ip` | Reverse look up a domain from an IP |

## Installing and Managing Programs

| Command | Description |
| :--- | :--- |
| `sudo apt update` | Update repository database |
| `sudo apt upgrade` | Update installed programs and packages \(must update repository database first\) |
| `apt search $keyword` | Search for packages \(unknown name\) to install from repositories |
| `alien $file.rpm` | Convert rpm to Debian packages |

## Users and Groups

TODO: add descriptions and examples

| Command | Description |
| :--- | :--- |
|  |  |

`groups`

Add a new user: `adduser`

`addgroup`

`id`

`w`

`last -a`

### User Privileges

| Command | Description |
| :--- | :--- |
| `sudo $command` | Execute commands with elevated privileges |
| `sudo -u $username $command` | Execute `sudo` command using another user's privileges |
| `sudo -l` | List `sudo` privileges for current user with |
| `/etc/sudoers` | Configuration file for `sudo` |

## $PATH

Add new $PATHs to `.profile` rather than `.bashrc`, then `source ~/.profile` to use new PATHs

Makes `pwd` part of path so don't need `./` _NOT RECOMMENDED for home/production use!_ `export PATH='pwd':$PATH`

The bulletproof way to add a path \(e.g., ~/opt/bin\) to the PATH environment variable is: 

```bash
PATH="${PATH:+${PATH}:}~/opt/bin"
#for appending (instead of PATH="$PATH:~/opt/bin")

PATH="~/opt/bin${PATH:+:${PATH}}"
#for prepending (instead of PATH="~/opt/bin:$PATH")
```

\(from [https://unix.stackexchange.com/questions/26047/how-to-correctly-add-a-path-to-path](https://unix.stackexchange.com/questions/26047/how-to-correctly-add-a-path-to-path)\)

## Startup Scripts

Add script to run at startup: `update-rc.d </path/to/the/script> defaults` \(needs 755 permissions\)

Delete script from default autorun: `update-rc.d -f </path/to/the/script> remove`

## Make a Linux live boot USB

On Windows \(easiest way!\):

1. Download and run [Rufus](https://rufus.ie/). 
2. Select the USB device and ISO you want to use, giving the volume a name if you wish.
3. If you want to use persistence, 
   1. Click "Show advanced drive options".
   2. Select the amount of storage to use for persistence.
4. Click "Start" and wait for it to finish.

For Kali live persistent boot USBs you will need the additional step of adding a `persistence.conf` by following the instructions below.

1. Verify your USB devices persistent storage partition with the command `fdisk -l`.
2. After locating your partition \(in this example it is `/dev/sdb3`\), label it `persistence`.

   ```text
   e2label /dev/sdb3 persistence
   ```

3. Create a mount point, mount the new partition there, and then create the configuration file to enable persistence. Finally, unmount the partition.

   ```text
   mkdir -p /mnt/my_usb
   mount /dev/sdb3 /mnt/my_usb
   echo "/ union" > /mnt/my_usb/persistence.conf
   umount /dev/sdb3
   ```

## Fork Bomb

A fork bomb is a type of denial-of-service attack against Unix-based systems, which makes use of the fork operation \(or equivalent functionality\) whereby a running process spawns another running process indefinitely. This attack works by creating a large number of processes very quickly in order to saturate the available resources of the operating system.

Once this code is executed, within seconds the target system will freeze and will have to hard rebooted. 

A common succinct bash fork bomb looks like:

```text
:(){:|:&};:
```

Which can be explained as:

| Function | Description |
| :--- | :--- |
| `:()` | define a function named `:` . Whenever we call `:`, execute the commands inside the `{ }` |
| `:|:` | load a copy of the **`:`** function into memory and pipe its output to another copy of the **`:`** function, which has to also be loaded into memory separately. |
| `&` | Disowns the other functions. If the first **`:`** is killed, all of the functions that it started should NOT also be killed. |
| `;` | Ends the function definition and tells the interpreter to run what is next as a command |
| `:` | Call function `:` initiating a chain-reaction: each call of `:` will start two more |

It can also be written as:

```text
forkbomb() { forkbomb | forkbomb & } ; forkbomb
```

## Fixing `command-not-found` errors

[https://stackoverflow.com/questions/19873430/command-not-found-message-when-i-try-to-add-command-in-bashrc/26976325](https://stackoverflow.com/questions/19873430/command-not-found-message-when-i-try-to-add-command-in-bashrc/26976325)

If you encounter errors on your system when you mistype a command or try to run a program that is not installed try these steps to fix the `command-not-found` command. 

TODO: screenshot or type out example so people know what I am referring to...

```bash
sudo apt purge command-not-found #uninstall
sudo apt install command-not-found #reinstall
sudo update-command-not-found #rebuild the database
sudo chmod ugo+r /var/lib/command-not-found/commands.db* #fix database permissions
```

 [https://bugs.launchpad.net/command-not-found/+bug/1824000](https://bugs.launchpad.net/command-not-found/+bug/1824000)

## References

* [https://www.kali.org/docs/usb/kali-linux-live-usb-persistence/](https://www.kali.org/docs/usb/kali-linux-live-usb-persistence/)
* [https://linuxconfig.org/linux-tutorials](https://linuxconfig.org/linux-tutorials)
* [https://explainshell.com/](https://explainshell.com/)
* [https://unix.stackexchange.com/questions/26047/how-to-correctly-add-a-path-to-path](https://unix.stackexchange.com/questions/26047/how-to-correctly-add-a-path-to-path)

