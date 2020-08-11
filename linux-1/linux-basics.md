---
description: Commands and programs that all Linux users need to know (but many don't!)
---

# Linux Basics

TODO: Add screenshots/code examples for each command

## Command-line Basics

Get help with a command: `man <command>`

View history of commands that have been typed into the terminal: `history`

Repeat a specific command from history command: `!<number>`

Search through command history: `Ctrl + r` then cycle with Up or Down arrows. (Do not need to type `history` command first)

Cycle through previously used command arguments: `alt + .`

Move between "words" on a command line: `ctrl + [arrow_keys]`

Clear all text off the terminal window: `clear`

Print string to terminal: `echo <text_to_show>`
- Can be used to display environment variables such as `$USER`, `$HOME`, `$PATH`

Copy text: Select with mouse then `Ctrl + Shift + c`

Paste text: `Ctrl + Shift + v`

Print text from file to printer: `lp <filename>`

Change directories: `cd <directory>`

Move up one directory: `cd ..`

Change directory to current user's home directory: `cd ~`

Exit terminal session: `exit`

## Filesystem Basics

Everything in Linux is a file, even directories.  Directories have some special restrictions, but for the most part can be treated like files.

### Listing and viewing Directories and Files

List hidden files: `ls -a`
- Hidden files in Linux begin with a `.` these files can still be accessed normally, but the `.` must be added to the name.

List files with attributes \(filesize, permissions, etc.\): `ls -la`

List files, sorted by Size: `ls -lS`

List files in current folder and subfolders (Recursive) - `ls -R`

Locate all files that symlink to a file: `find -L / -samefile </path/to/file>`

List the size, used space, and available space on the mounted filesystems of your computer: `df`

Print the contents of a file to the command line: `cat <file>`

Combine the contents of two text files: `cat <file1> <file2> > <newfilename>`

Compare two files and show differences: `diff`

Search for string inside a file: `grep <string> <file>`

### File and Directory Creation, Modification, and Deletion

To create a new file `touch <filename>`
or
```
cat > <filename>
 Type your file contents
Press `Ctrl+d` to return to your terminal.
```
Create a new directory: `mkdir [/path/to/]<dirname>`



Remove a file from the filesystem: `rm <filename>`

Remove a directory from the filesystem: `rmdir <dirname>`

Remove all instances of a certain file. `sudo rm --force $(which <file_name>)` (Could be used with `find` or `locate` instead of `which`. Dangerous with --force!!)

Copy a file/directory to another location (or name): `cp <file> [/path/to/]<filename>`

Move a file/directory to another location (or rename): `mv <file> [/path/to/]<filename>`

### File Permissions

chmod
-ugo
-rwx
-7777

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

Makes `pwd` part of path so dont need `./`  _NOT RECOMMENDED for home use!_  `export PATH='pwd':$PATH`

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

