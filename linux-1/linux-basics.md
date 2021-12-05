---
description: Commands and programs that all Linux users need to know (but many don't!)
---

# Linux Basics

TODO: Add screenshots/code examples for each command; put commands in tables; clean and organize all (issue [#7](https://github.com/zweilosec/Infosec-Notes/tree/9375dea2ecb0e3feeda3395c360ea20793d94891/issues/7/README.md))

## Command-line Basics

| Command               | Description                                                                                                                                                                                                           |
| --------------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `man $command`        | Get help with a command                                                                                                                                                                                               |
| `history`             | View history of commands that have been typed into the terminal                                                                                                                                                       |
| `!<number>`           | Repeat a specific command from command history                                                                                                                                                                        |
| `Ctrl + r`            | Search through command history: then cycle with Up or Down arrows. (Do not need to type `history` command first)                                                                                                      |
| `alt + .`             | Cycle through previously used command arguments                                                                                                                                                                       |
| `ctrl + [arrow_keys]` | Move between "words" on a command line                                                                                                                                                                                |
| `clear`               | Clear all text off the terminal window                                                                                                                                                                                |
| `echo $text`          | <p>Print string to terminal.</p><ul><li>Most useful when piped into other commands.</li><li>Can be used to display environment variables such as <code>$USER</code>, <code>$HOME</code>, <code>$PATH</code></li></ul> |
| `Ctrl + Shift + c`    | Copy selected text                                                                                                                                                                                                    |
| `Ctrl + Shift + v`    | Paste clipboard contents                                                                                                                                                                                              |
| `lp $filename`        | Print from file to printer                                                                                                                                                                                            |
| `cd $directory`       | Change directories                                                                                                                                                                                                    |
| `cd ..`               | Move up one directory                                                                                                                                                                                                 |
| `cd ~`                | Change directory to current user's home directory                                                                                                                                                                     |
| `cd -`                | Return to previous directory                                                                                                                                                                                          |
| `exit`                | Exit terminal session                                                                                                                                                                                                 |

### Special Symbols

| `Symbol` | Purpose                                                                             |
| -------- | ----------------------------------------------------------------------------------- |
| `\|`     | Send the output of one command to another.                                          |
| `>`      | Redirect output to a file.                                                          |
| `<`      | Redirect input from a file.                                                         |
| `>>`     | Append output to an existing file.                                                  |
| `/`      | Separator used in path names.                                                       |
| `\`      | Used to escape characters and to send multi-line commands.                          |
| `.`      | Current directory.                                                                  |
| `..`     | Parent directory.                                                                   |
| `$$`     | displays the process ID of the current shell instance.                              |
| `&`      | Process command in the background (and give control of the terminal back).          |
| `&&`     | Run the next command only if the previous completed successfully.                   |
| `*`      | Match any number of characters in file name.                                        |
| `?`      | Match any single character in file name.                                            |
| `[ ]`    | Match any one of the enclosed characters in file name.                              |
| `;`      | Run commands in sequence, regardless if the previous succeeded.                     |
| `( )`    | Group commands.                                                                     |
| `{ }`    | Used to feed multiple parameters to a single command.  Separate parameters by `,`   |
| `!`      | Followed by a digit will repeat the command from the history file that corresponds. |
| `!!`     | Repeat the previous command.                                                        |
| `0`      | Shortcut that stands for Standard Input (STDIN)                                     |
| `1`      | Shortcut that stands for Standard Output (STDOUT)                                   |
| `2`      | Shortcut that stands for Standard Error (STDERR)                                    |

## Filesystem Basics

![Standard Linux Directories and Files](../.gitbook/assets/0\_roztlgbulghhs2p\_.png)

Everything in Linux is a file, even directories and devices. Directories have some special restrictions, but for the most part can be treated like files.

### Listing and viewing Directories and Files

| Command                        | Description                                                                                                                                                                                                                                                |
| ------------------------------ | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `ls -a`                        | <p>List files in a folder, to include hidden files:</p><ul><li>Hidden files in Linux begin with a <strong><code>.</code></strong> these files can still be accessed normally, but the <strong><code>.</code></strong> must be added to the name.</li></ul> |
| `ls -la`                       | List files with attributes (filesize, permissions, etc.)                                                                                                                                                                                                   |
| `ls -lS`                       | List files, sorted by Size                                                                                                                                                                                                                                 |
| `ls -R`                        | List files in current folder and all subfolders (Recursive)                                                                                                                                                                                                |
| `find -L / -samefile $file`    | Locate all files that symlink to a file                                                                                                                                                                                                                    |
| `which $file`                  | Searches for files in a `$PATH` directory only.                                                                                                                                                                                                            |
| `locate $file`                 | Uses a database to search for files. Update the database with **`sudo updatedb`**                                                                                                                                                                          |
| `df`                           | List the size, used space, and available space on the mounted filesystems of your computer                                                                                                                                                                 |
| `cat $file`                    | Print the contents of a file to the command line                                                                                                                                                                                                           |
| `cat $file1 $file2 > $newfile` | Combine the contents of two text files                                                                                                                                                                                                                     |
| `diff $file1 $file2`           | Compare two files and show differences (Only for text-based files)                                                                                                                                                                                         |
| `grep $string $file`           | Search for string inside a file                                                                                                                                                                                                                            |
| `head $file`                   | Displays the first 10 lines of a file. Specify the number of lines with `-#`                                                                                                                                                                               |
| `tail $file`                   | Displays the last 10 lines of a file. Specify the number of lines with `-#`                                                                                                                                                                                |
| `file $file`                   | Displays the filetype of a file, determined by the hexadecimal " [magic bytes](https://blog.netspi.com/magic-bytes-identifying-common-file-formats-at-a-glance/)".                                                                                         |

### File and directory creation and deletion

| Command                          | Description                                                                                                                                                                                                 |
| -------------------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `touch $fileName`                | Create a new blank file with this name                                                                                                                                                                      |
| `cp $file [/path/to/]$newFile`   | Copy file from one location to another.  If no location is specified, creates the copy in the same directory.                                                                                               |
| `mv $file [/path/to/]$newFile`   | Move file from one location to another.  If no location is specified, renames the file in same directory (removes the old file).                                                                            |
| `rm $file`                       | Removes (deletes) a file.                                                                                                                                                                                   |
| `rm *`                           | Removes (deletes) all files in the directory.                                                                                                                                                               |
| `rm -rf *`                       | Recursively deletes all files in the directory and all subdirectories and files.  Will not prompt for approval with `-f`.                                                                                   |
| `mkdir [/path/to/]$dir`          | Makes a new empty directory                                                                                                                                                                                 |
| `mkdir -p test/{test1,test2}`    | The `-p` flag creates multiple directories at once.  In this example we use brace expansion to create `test/` and 2 subdirectories under it.                                                                |
| `rmdir $dir`                     | Deletes an empty directory                                                                                                                                                                                  |
| `sudo rm --force $(which $file)` | Removes all instances of a specified filename.  Only searches PATH directories.  You could also use `find` or `locate` instead of `which` to find more files.  With `--force` will not prompt for approval! |

### File & text manipulation

| Command                 | Description                                                                                                                                                                                                                                                                                                                                                                                                                                         |
| ----------------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `cat $file1 $file2`     | Concatenates the contents of two files                                                                                                                                                                                                                                                                                                                                                                                                              |
| `wc`                    | Counts the lines, words, and bytes in a file.  `-l` will count only lines, `-m` will count only characters, `-c` will count only bytes,  `-w` will count only words                                                                                                                                                                                                                                                                                 |
| `awk`                   | A programming language for text processing. Can do many many things.                                                                                                                                                                                                                                                                                                                                                                                |
| `sed`                   | Performs text editing on a stream of text. Useful for replacing text in a file and much more                                                                                                                                                                                                                                                                                                                                                        |
| `cut`                   | Extract a section of text.  **`-f`** selects the field, **`-d`** sets the delimiter.                                                                                                                                                                                                                                                                                                                                                                |
| `sort`                  |                                                                                                                                                                                                                                                                                                                                                                                                                                                     |
| `uniq`                  |                                                                                                                                                                                                                                                                                                                                                                                                                                                     |
| `comm $file1 $file2`    | <p>Compare two files and show differences.  Output is in three columns:</p><ul><li>Lines that are unique to the first file </li><li>Lines that are unique to the second file </li><li>Lines that are shared by both files.</li></ul>                                                                                                                                                                                                                |
| `diff $file1 $file2`    | <p>Compare two files and show differences. Has two modes: </p><ul><li><code>-c</code> Context format</li><li><code>-u</code> Unified Format</li></ul>                                                                                                                                                                                                                                                                                               |
| `vimdiff $file1 $file2` | <p>Opens two files in Vim side-by-side and highlight the differences. Some shortcuts:</p><ul><li><code>[ctrl] w</code> - Switch to the other split window</li><li><code>do</code> - Gets changes from the other window into the current one</li><li><code>dp</code> - Puts the changes from the current window into the other one</li><li><code>]c</code> - Jump to the next change</li><li><code>[c</code> - Jump to the previous change</li></ul> |

```
cat > $fileName
 [Type your file contents]
 [Press `Ctrl+d` to return to your terminal]
```

### File Permissions

The permissions for a file (for example, viewed with the `ls -l` command) are typically written as:&#x20;

```bash
-rwxrwxrwx owner group [metadata] $filename
```

**`r`** = read **`w`** = write **`x`** = execute

Breaking down this format gives us four parts:&#x20;

1. The first character tells if it is a file or a directory.  if it is a **`-`** (hyphen) then it is a file. However if the first character is a **`d`**, then the file is a directory.  (Remember, technically everything in Linux is a file, even directories).
2. The next three characters specify the permissions of the owner of the file.
3. The following three characters specify the permissions of the group that owns the file.
4. The final three characters specify the permissions of all other users.

The permissions `-rwxrwxrwx` mean that the anyone can read, write and execute the file.&#x20;

In the above example, the owner, group, and everyone permissions are all `rwx`; hence anyone can read, write, and execute this file.

#### The chmod command

The `chmod` command is used to set the permissions on a file.  This is usually expressed in one of two different formats, ugoa+rwx and octal notation.  The command is used as follows:

```bash
chmod [permissions] $file
```

#### Octal notation

In octal notation, the permissions are assigned using triple octal (base8) digits.  The first digit is the cumulative permissions for the owner, the second for the group, and the third for everyone else.

| Permissions | Binary notation | Octal notation | Description                 |
| ----------- | --------------- | -------------- | --------------------------- |
| `---`       | 000             | 0              | No permissions              |
| `--x`       | 001             | 1              | Execute permission only     |
| `-w-`       | 010             | 2              | Write permission only       |
| `-wx`       | 011             | 3              | Write and execute           |
| `r--`       | 100             | 4              | Read permission only        |
| `r-x`       | 101             | 5              | Read and execute permission |
| `rw-`       | 110             | 6              | Read and write permission   |
| `rwx`       | 111             | 7              | Read, write and execute     |

From the above table we can easily derive :

```bash
Read = 4    Write = 2     Execute = 1
```

Therefore, if you want to give only the owner read and write permissions, they would be assigned `600` (4+2=6). &#x20;

Taking the same example from above, to assign the permissions `-rwxrwxrwx` the command would be:&#x20;

```bash
chmod 777 $file
```

That is: read (4), write (2), and execute (1) permissions for the owner, group, and all others.

#### ugoa+rwx notation

In this notation format, there are three main components:

1. _Who._ The users to modify permissions for: `u` = user (owner), `g` = group, `o` = others, and finally  `a` = u+g+o (all).
2. _What._ The modifier: `=` to set permissions, `+` for adding permissions, `-` for removing permissions.
3. _Which._ The permissions to set, add, or remove: one or more of `rwx` as above.

As you can see, this notations allows for easier and more explicit control over exactly which permissions are given to whom.

Examples:&#x20;

To give all users the write permission:

```bash
chmod a+w $file
```

To remove write and execute permissions from the 'other' group:

```bash
chmod o-wx $file
```

These permission changes can also be chained by adding a comma between the permission changes. &#x20;

To add read/write permissions for the file owner and group, while making it read only for everyone else:

```bash
chmod ug+rw,o=r $file
```

#### Advanced permissions (TODO: Finish cleaning this up.  Add descriptions of SUID/GUID)

Other than just read and write, you can also set some other permissions like SUID and GUID.

`chmod 4000 file`

`chmod +s file`

Both the above examples would add the `setuid` bit to the file.

`chmod 2000 file`

`chmod +g file`

Both the above examples would add the `getuid` bit to the file.

#### The sticky bit

[https://en.wikipedia.org/wiki/Sticky\_bit](https://en.wikipedia.org/wiki/Sticky\_bit) <- pull more information from here and add

The "sticky bit" is added to folders in order to prevent anyone else from deleting the folder or any of its contents. It is represented by a `t` at the end of the permissions `d--r--r--rt`. When a sticky bit is set, nobody other than the owner or the root can delete the folder or the file.

`chmod 1000 folder`

`chmod +t folder`

Both the above examples set the sticky bit to the folders

Examples: `chmod 1744 file`

This would set the sticky bit, give all permissions to the owner and only read permission to the group and others

`chmod 0600 file`

This would only give the owner read and write permission, but not execute permission.

#### The chown command

The `chown` command can be used to change the owner of a file or a directory.

```bash
chown $user $group $file
```

The above command would change the owner of the file to `$user` and also the group to `$group`.

### File compression and encryption

| Command | Description |
| ------- | ----------- |
| unzip   |             |
| gunzip  |             |
| tar     |             |

## System Information

| Command                     | Description                                                                             |
| --------------------------- | --------------------------------------------------------------------------------------- |
| `uname -a`                  | List OS, hostname, kernel build number, CPU architecture                                |
| `ps`                        | List running processes (current user)                                                   |
| `ps aux`                    | List running processes for all users (if permitted)                                     |
| `top`                       | Similar to Windows Task Manager, lists running processes with details of hardware usage |
| `systemctl list-unit-files` | Show list of all services installed with status                                         |

## Networking

| Command                                 | Description                                                                                            |
| --------------------------------------- | ------------------------------------------------------------------------------------------------------ |
| `ifconfig`                              | Get networking information (IP, Subnet mask, MAC, etc.); On some systems may require **`sudo`** rights |
| `ip a`                                  | Get networking information (IP, Subnet mask, MAC, etc.); No **`sudo`** required. Newer                 |
| `ifconfig $interface $ip/$CIDR`         | Set IP address for an interface                                                                        |
| `ifconfig $interface mtu $size`         | Change MTU size for an interface                                                                       |
| `ifconfig $interface hw ether $new_MAC` | Change MAC address (or use `macchanger`)                                                               |

### Managing connections

TODO: add more information about Managing connections in Linux (Issue [#9](https://github.com/zweilosec/Infosec-Notes/issues/9))

* Add commands such as telnet, SSH, nc, curl, wget
* Add commands for listing information about open network connections: lsof -i, ss, netstat
* include description and examples

| Command  | Description |
| -------- | ----------- |
| `telnet` |             |
| `SSH`    |             |
| `nc`     |             |
| `curl`   |             |
| `wget`   |             |

nc listener: `nc -lvnp <port>`

#### list open network connections

| Command    | Description                                                                            |
| ---------- | -------------------------------------------------------------------------------------- |
| `lsof -i`  |                                                                                        |
| `ss`       | Shows State, data sent/recieved, local process:port, remote address:port               |
| `ss -anlp` | Get all connections that are listening, do not resolve names, show process information |
| `netstat`  |                                                                                        |

### Shared folders

| Command                 | Description                         |
| ----------------------- | ----------------------------------- |
| `showmount -e $ip`      | Show available shares to mount      |
| `smb://$ip/$share_name` | Connect to Windows SMB share folder |

TODO: add more information on mounting and using network shares (issue [#10](https://github.com/zweilosec/Infosec-Notes/issues/10))

* Add information on creating, mounting, and connecting to network shares (Samba, SMB, etc.)
* pull more information from HTB Writeups ([Resolute](https://github.com/zweilosec/htb-writeups/blob/f1424824de53334bfff1a62ace34f6d23e77cfef/windows-machines/medium/resolute-write-up.md), [Remote](https://github.com/zweilosec/htb-writeups/blob/da514f8ff85dfaf164f78e776b8b987e6e346f14/windows-machines/easy/remote-write-up.md), and [Fuse](https://github.com/zweilosec/htb-writeups/blob/f1424824de53334bfff1a62ace34f6d23e77cfef/windows-machines/medium/fuse-write-up.md) for example, as well as outside sources)
* Add commands such as `smbclient`, `smbpass`, `showmount`, `mount`, [Downloading Files](https://github.com/zweilosec/htb-writeups/blob/f1424824de53334bfff1a62ace34f6d23e77cfef/windows-machines/medium/nest-write-up.md#copying-an-entire-smb-folder-recursively-using-smbclient), [Detecting ADS](https://github.com/zweilosec/htb-writeups/blob/f1424824de53334bfff1a62ace34f6d23e77cfef/windows-machines/medium/nest-write-up.md#useful-skills-and-tools), [`smbmap`](https://github.com/zweilosec/htb-writeups/blob/f1424824de53334bfff1a62ace34f6d23e77cfef/windows-machines/medium/cascade-write-up.md#useful-skills-and-tools),

### DNS

| Command                                   | Description                         |
| ----------------------------------------- | ----------------------------------- |
| `dig @$server $domain_or_ip $record_type` | Look up DNS information for a site  |
| `dig -x $ip`                              | Reverse look up a domain from an IP |

## Installing and Managing Programs

| Command                            | Description                                                                                                                                                                                                                |
| ---------------------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `sudo apt update`                  | Update repository database                                                                                                                                                                                                 |
| `sudo apt upgrade`                 | Update installed programs and packages (must update repository database first).  Adding `-y` will accept all prompts and install automatically.  Specifying a package name after "upgrade" will upgrade only that package. |
| `sudo apt dist-upgrade`            |                                                                                                                                                                                                                            |
| `sudo apt full-upgrade`            |                                                                                                                                                                                                                            |
| `apt search $keyword`              | Search for packages (unknown name) to install from repositories                                                                                                                                                            |
| `apt-cache search $keyword`        | Search for package in repositories                                                                                                                                                                                         |
| `apt show $package`                | Show details about the specified package                                                                                                                                                                                   |
| `sudo apt install $package`        | Installs the specified package (and any dependencies).                                                                                                                                                                     |
| `sudo apt remove --purge $package` | Uninstalls the specified package                                                                                                                                                                                           |
| `dpkg -i $deb_file`                | Installs the specified `.deb` package file (Does not install dependencies).                                                                                                                                                |
| `alien $file.rpm`                  | Convert rpm to Debian packages                                                                                                                                                                                             |

## Users and Groups

TODO: Add information about Linux Users and Groups (issue [#11](https://github.com/zweilosec/Infosec-Notes/issues/11))

* Add information about creating, modifying, and deleting users and passwords
* Add information about use, creation, modification, and deletion of groups
* Add commands such as `adduser`, `groups`, `passwd`, etc.
* Add commands related to listing users, seeing who is logged in, etc. (`id`, `w`, `last -a`)
* add descriptions and examples

| Command | Description                                                 |
| ------- | ----------------------------------------------------------- |
|         |                                                             |
| `env`   | Displays all environment variables for the current context. |

`groups`

Add a new user: `adduser`

`addgroup`

`id`

`w`

`last -a`

### User Privileges

| Command                      | Description                                             |
| ---------------------------- | ------------------------------------------------------- |
| `sudo $command`              | Execute commands with elevated privileges               |
| `sudo -u $username $command` | Execute `sudo` command using another user's privileges  |
| `sudo -l`                    | List `sudo` privileges for current user with            |
| `sudo -k`                    | Stop remembering credentials and re-prompt for password |
| `/etc/sudoers`               | Configuration file for `sudo`                           |

## Environment Variables

| Command                  | Action                                                                                                                                                                    |
| ------------------------ | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `env`                    | List all current environment variables and their values.                                                                                                                  |
| `export [variable_name]` | <p>Define the value of an environment variable. Can be a new or existing variable.  </p><p><em>Exported variables only work in the context of the current shell.</em></p> |
| `echo $PATH`             | List the values in the PATH environment variable.                                                                                                                         |
| `echo $USER`             | Show the current username.                                                                                                                                                |
| `echo $PWD`              | Show the current working directory.                                                                                                                                       |
| `echo $HOME`             | Show the current user's home directory                                                                                                                                    |
| `echo "$$"`              | Show the process ID of the current shell.                                                                                                                                 |
| `stty size`              | Show number of rows and columns in the current shell.                                                                                                                     |

### $PATH

* To make `$PWD` part of path so you don't need `./` when running commands/scripts: (_NOT RECOMMENDED for home/production use!)_ `export PATH='pwd':$PATH`
* Add new $PATHs to the `.profile` file rather than `.bashrc.` Then, use the command `source ~/.profile` to use the newly added PATHs.
* The best way to add a path (e.g., \~/opt/bin) to the PATH environment variable is:

```bash
export PATH="${PATH:+${PATH}:}~/opt/bin"
#for appending (instead of PATH="$PATH:~/opt/bin")

export PATH="~/opt/bin${PATH:+:${PATH}}"
#for prepending (instead of PATH="~/opt/bin:$PATH")
```

(from [https://unix.stackexchange.com/questions/26047/how-to-correctly-add-a-path-to-path](https://unix.stackexchange.com/questions/26047/how-to-correctly-add-a-path-to-path))

## Startup Scripts

Add script to run at startup: `update-rc.d </path/to/the/script> defaults` (needs 755 permissions)

Delete script from default autorun: `update-rc.d -f </path/to/the/script> remove`

## Make a Linux live boot USB

On Windows (easiest way!):

1. Download and run [Rufus](https://rufus.ie).
2. Select the USB device and ISO you want to use, giving the volume a name if you wish.
3. If you want to use persistence,
   1. Click "Show advanced drive options".
   2. Select the amount of storage to use for persistence.
4. Click "Start" and wait for it to finish.

For Kali live persistent boot USBs you will need the additional step of adding a `persistence.conf` by following the instructions below.

1. Verify your USB devices persistent storage partition with the command `fdisk -l`.
2.  After locating your partition (in this example it is `/dev/sdb3`), label it `persistence`.

    ```
    e2label /dev/sdb3 persistence
    ```
3.  Create a mount point, mount the new partition there, and then create the configuration file to enable persistence. Finally, unmount the partition.

    ```
    mkdir -p /mnt/my_usb
    mount /dev/sdb3 /mnt/my_usb
    echo "/ union" > /mnt/my_usb/persistence.conf
    umount /dev/sdb3
    ```

## Recover an unresponsive terminal

1.  Press the **RETURN/ENTER** key.

    You may have typed a command but forgotten to press **RETURN** to tell the shell that you’re done typing and it should now interpret the command.
2. If you can type commands, but nothing happens when you press **RETURN**, try typing **CTRL-J**. If this works, your terminal needs to be reset to fix the **RETURN** key. Some systems have a **reset** command that you can run by typing **CTRL-J** **reset** **CTRL-J**. If this doesn’t work, you may need to log out and log back in or turn your terminal off and on again.
3.  If your shell has job control type **CTRL-Z**.

    This suspends a program that may be running and gives you another shell prompt. Now you can enter the **jobs** command to find the program’s name, then restart the program with **fg** or terminate it with **kill**.
4.  Use your interrupt key (typically **DELETE** or **CTRL-C)**.

    This interrupts a program that may be running. (Unless a program is run in the background as the shell will wait for it to finish before giving a new prompt. A long-running program may thus appear to hang the terminal.) If this doesn’t work the first time, try it once more, though doing it more than twice usually won’t help.
5.  Type **CTRL-Q**.

    If output has been stopped with **CTRL-S**, this will restart it. (Note that some systems will automatically issue **CTRL-S** if they need to pause output; this character may not have been typed by the user from the keyboard.)
6.  Check that the **SCROLL LOCK** key is not toggled on.

    This key stops the screen display from scrolling upward. If pressing it once does not work, make sure you’ve pressed it an even number of times as this leaves the key in the same state it was when you started.
7.  Type **CTRL-D** at the beginning of a new line.

    Some programs (like **mail**) expect text from the user. A program may be waiting for an end-of-input character from you to tell it that you’ve finished entering text. However, typing **CTRL-D** may cause you to log out, so you should only try this as a last resort.
8. If you’re using a windowing system, close (or terminate) the terminal window and open a new one.

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

## Fork Bomb

A fork bomb is a type of denial-of-service attack against Unix-based systems, which makes use of the fork operation (or equivalent functionality) whereby a running process spawns another running process indefinitely. This attack works by creating a large number of processes very quickly in order to saturate the available resources of the operating system.

Once this code is executed, within seconds the target system will freeze and will have to hard rebooted.

A common succinct bash fork bomb looks like:

```
:(){:|:&};:
```

Which can be explained as:

| Function | Description                                                                                                                  |                                                                                                                                                                  |
| -------- | ---------------------------------------------------------------------------------------------------------------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `:()`    | define a function named `:` . Whenever we call `:`, execute the commands inside the `{ }`                                    |                                                                                                                                                                  |
| \`:      | :\`                                                                                                                          | load a copy of the **`:`** function into memory and pipe its output to another copy of the **`:`** function, which has to also be loaded into memory separately. |
| `&`      | Disowns the other functions. If the first **`:`** is killed, all of the functions that it started should NOT also be killed. |                                                                                                                                                                  |
| `;`      | Ends the function definition and tells the interpreter to run what is next as a command                                      |                                                                                                                                                                  |
| `:`      | Call function `:` initiating a chain-reaction: each call of `:` will start two more                                          |                                                                                                                                                                  |

It can also be written as:

```
forkbomb() { forkbomb | forkbomb & } ; forkbomb
```

## References

* [https://www.kali.org/docs/usb/kali-linux-live-usb-persistence/](https://www.kali.org/docs/usb/kali-linux-live-usb-persistence/)
* [https://linuxconfig.org/linux-tutorials](https://linuxconfig.org/linux-tutorials)
* [https://explainshell.com/](https://explainshell.com)
* [https://unix.stackexchange.com/questions/26047/how-to-correctly-add-a-path-to-path](https://unix.stackexchange.com/questions/26047/how-to-correctly-add-a-path-to-path)

If you like this content and would like to see more, please consider [buying me a coffee](https://www.buymeacoffee.com/zweilosec)!
