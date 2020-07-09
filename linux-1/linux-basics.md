---
description: Commands and programs that all Linux users need to know (but many don't!)
---

# Linux Basics

## Command-line Basics

Search through command history: `ctrl + r`

Cycle through previously used arguments: `alt + .`

Move between "words" on a command line: `ctrl + [arrow_keys]`

## Filesystem Basics

List hidden files: `ls -a`

List files with attributes \(filesize, permissions, etc.\): `ls -la`

List files, sorted by Size: `ls -lS`

`sudo rm --force $(which <file_name>)` Remove all instances of a certain file. Could be used with `find` instead of `which`. dangerous with --force!!

Locate all files that symlink to a file: `find -L / -samefile </path/to/file>`

## Networking

Get networking information \(IP, Subnet mask, MAC, etc.\) `ip a` or `sudo ifconfig` \(like `ipconfig` on windows\)

nc listener: `nc -lvnp <port>`

## Installing and Managing Programs

Update repository database: `sudo apt update`

Update installed programs and packages: `sudo apt upgrade` \(must update repository database first\)

Search for packages \(unknown name\) to install from repositories: `apt-file search <binary name>` or `apt search <keyword>`

Convert rpm to Debian packages: `alien <file.rpm>`

## User Privileges

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

