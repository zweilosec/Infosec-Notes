---
description: Commands and programs that all Linux users need to know (but many don't!)
---

# Linux Basics

TODO: Add screenshots/code examples for each command

## Command-line Basics

Get help with a command: `man <command>`

View history of commands that have been typed into the terminal: `history`

Repeat a specific command from history command: `!<number>`

Search through command history: `Ctrl + r` then cycle with Up or Down arrows. \(Do not need to type `history` command first\)

Cycle through previously used command arguments: `alt + .`

Move between "words" on a command line: `ctrl + [arrow_keys]`

Clear all text off the terminal window: `clear`

Print string to terminal: `echo <text_to_show>`

* Can be used to display environment variables such as `$USER`, `$HOME`, `$PATH`

Copy text: Select with mouse then `Ctrl + Shift + c`

Paste text: `Ctrl + Shift + v`

Print text from file to printer: `lp <filename>`

Change directories: `cd <directory>`

Move up one directory: `cd ..`

Change directory to current user's home directory: `cd ~`

Exit terminal session: `exit`

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

List hidden files: `ls -a`

* Hidden files in Linux begin with a `.` these files can still be accessed normally, but the `.` must be added to the name.

List files with attributes \(filesize, permissions, etc.\): `ls -la`

List files, sorted by Size: `ls -lS`

List files in current folder and subfolders \(Recursive\) - `ls -R`

Locate all files that symlink to a file: `find -L / -samefile </path/to/file>`

List the size, used space, and available space on the mounted filesystems of your computer: `df`

Print the contents of a file to the command line: `cat <file>`

Combine the contents of two text files: `cat <file1> <file2> > <newfilename>`

Compare two files and show differences: `diff`

Search for string inside a file: `grep <string> <file>`

### File and Directory Creation, Modification, and Deletion

To create a new file `touch <filename>` or

```text
cat > <filename>
 Type your file contents
Press `Ctrl+d` to return to your terminal.
```

Create a new directory: `mkdir [/path/to/]<dirname>`

Remove a file from the filesystem: `rm <filename>`

Remove a directory from the filesystem: `rmdir <dirname>`

Remove all instances of a certain file. `sudo rm --force $(which <file_name>)` \(Could be used with `find` or `locate` instead of `which`. Dangerous with --force!!\)

Copy a file/directory to another location \(or name\): `cp <file> [/path/to/]<filename>`

Move a file/directory to another location \(or rename\): `mv <file> [/path/to/]<filename>`

### File Permissions

`chmod -ugo -rwx -7777 5KFB6`

chown

## System Information

List OS, hostname, kernel build number, CPU architecture: `uname -a`

List running processes \(current user\): `ps`

Similar to Windows Task Manager, lists running processes with details of hardware usage: `top`

## Networking

Get networking information \(IP, Subnet mask, MAC, etc.\) `ip a` or `sudo ifconfig` \(like `ipconfig` on windows\)

Set IP address: `ifconfig <interface> <ip>/<CIDR>`

Change MTU size: `ifconfig <interface> mtu <size>`

Change MAC address: `ifconfig <interface> hw ether <new_MAC>`

### Managing connections

nc

nc listener: `nc -lvnp <port>`

curl

wget

list open network connections: `lsof -i`

### Shared folders

Connect to Windows SMB share folder: `smb://<ip>/<share_name>`

### DNS

Look up DNS information for a website: `dig @<server> <name> <type>`

Reverse look up a domain from an IP: `dig -x <IP>`

## Installing and Managing Programs

Update repository database: `sudo apt update`

Update installed programs and packages: `sudo apt upgrade` \(must update repository database first\)

Search for packages \(unknown name\) to install from repositories: `apt-file search <binary name>` or `apt search <keyword>`

Convert rpm to Debian packages: `alien <file.rpm>`

## Users and Groups

groups

Add a new user: `adduser`

addgroup

id

w

last -a

### User Privileges

Execute commands with elevated privileges `sudo`

Execute `sudo` command using another user's privileges: `sudo -u <username> [command]`

## $PATH

Add new $PATHs to `.profile` rather than `.bashrc`, then `source ~/.profile` to use new PATHs

Makes `pwd` part of path so dont need `./` _NOT RECOMMENDED for home use!_ `export PATH='pwd':$PATH`

The bullet-proof way to add a path \(e.g., ~/opt/bin\) to the PATH environment variable is: \(from [https://unix.stackexchange.com/questions/26047/how-to-correctly-add-a-path-to-path](https://unix.stackexchange.com/questions/26047/how-to-correctly-add-a-path-to-path)\)

```text
PATH="${PATH:+${PATH}:}~/opt/bin"
for appending (instead of PATH="$PATH:~/opt/bin") and

PATH="~/opt/bin${PATH:+:${PATH}}"
for prepending (instead of PATH="~/opt/bin:$PATH")
```

## Startup Scripts

Add script to run at startup: `update-rc.d </path/to/the/script> defaults` \(needs 755 permissions\)

Delete script from default autorun: `update-rc.d -f </path/to/the/script> remove`

