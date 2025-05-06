---
description: Commands and programs that all Linux users need to know (but many don't!)
---

# Unix Fundamentals

TODO: Consider Adding screenshots/code examples for each command; finish putting commands in tables; clean and organize all (issue [#7](https://github.com/zweilosec/Infosec-Notes/tree/9375dea2ecb0e3feeda3395c360ea20793d94891/issues/7/README.md))

## Shell Basics

The shell is a command-line interface that allows users to interact with the operating system by executing commands. It acts as an intermediary between the user and the kernel, interpreting user inputs and executing programs. Below are some key concepts and details about UNIX shells:

### Terminals and Pseudo-Terminals

Terminals and pseudo-terminals are essential components of UNIX systems, providing interfaces for user interaction and process communication. A terminal allows access to the shell that a user interacts with. By understanding terminals and pseudo-terminals, users can better manage sessions, troubleshoot issues, and utilize advanced tools like multiplexers and remote access utilities.

#### **Terminals (TTY)**
- **Definition**: A terminal, or TTY (short for "teletype"), is a physical or virtual device that provides a text-based interface for user interaction with the operating system.
- **Types**:
  - **Physical Terminals**: Hardware devices like keyboards and monitors connected directly to a system.
  - **Virtual Terminals**: Software-based terminals that emulate physical terminals, often accessed through terminal emulators like `xterm`, `gnome-terminal`, or `konsole`.

#### **Pseudo-Terminals (PTY)**
- **Definition**: A pseudo-terminal is a pair of virtual devices that emulate a terminal. It allows processes to communicate as if they were interacting with a physical terminal.
- **Use Cases**:
  - Remote login sessions (e.g., `ssh`).
  - Terminal multiplexers (e.g., `tmux`, `screen`).
  - GUI-based terminal emulators.

#### **TTY vs PTY**
| **Feature**               | **TTY (Terminal)**                          | **PTY (Pseudo-Terminal)**                     |
|---------------------------|---------------------------------------------|-----------------------------------------------|
| **Type**                  | Physical or virtual terminal device.        | Virtual device pair (master and slave).       |
| **Interaction**           | Direct user interaction via keyboard/screen.| Process-to-process communication.            |
| **Examples**              | `/dev/tty1`, `/dev/tty2`                    | `/dev/pts/0`, `/dev/pts/1`                    |
| **Primary Use**           | Local user sessions.                        | Remote sessions, terminal emulators.         |
| **Limitations**           | Requires physical or virtual terminal access.| No direct user interaction; relies on software. |

#### **Key Commands**
- **List Active Terminals**:  
  ```bash
  who
  ```
- **Check Current Terminal**:  
  ```bash
  tty
  ```
- **List Pseudo-Terminals**:  
  ```bash
  ls /dev/pts
  ```

#### **Advanced Terminal Concepts**
- **Terminal Multiplexers**: Tools like `tmux` and `screen` allow users to manage multiple terminal sessions within a single terminal window.
- **TTY Devices**: Physical terminals are represented as `/dev/ttyX`, where `X` is the terminal number.
- **PTY Devices**: Pseudo-terminals are represented as `/dev/pts/X`, where `X` is the pseudo-terminal number.
- **Terminal Modes**:
  - **Canonical Mode**: Input is processed line-by-line.
  - **Non-Canonical Mode**: Input is processed immediately without waiting for a newline.

### Common Shell Types in UNIX

1. **sh (Bourne Shell)**:  
    - The original UNIX shell, known for its simplicity and scripting capabilities.  
    - It is lightweight and often used for scripting in UNIX environments.
    
2. **bash (Bourne Again Shell)**:  
    - The most widely used shell in UNIX/Linux systems.  
    - It is an enhanced version of the original Bourne shell (`sh`) with additional features like command history, tab completion, and scripting capabilities.  
    - Default shell on most Linux distributions.

3. **csh (C Shell)**:  
    - Syntax resembles the C programming language.  
    - Includes features like job control and history substitution.  

4. **ksh (Korn Shell)**:  
    - Combines features of the Bourne shell and the C shell.  
    - Known for its scripting enhancements and performance improvements.  

5. **zsh (Z Shell)**:  
    - A powerful and highly customizable shell with features like improved auto-completion, spell correction, and plugin support. The default in some distros such as Kali Linux.

#### Locating Known Shells

The list of available shells on a UNIX system can be found in the `/etc/shells` file.  
  Example:  
  ```bash
  cat /etc/shells
  ```

#### Default Shells

The default shell for most UNIX/Linux systems is `bash`, though it is always important to understand what shell you are currently operating in, as they all have different behaviors.

To determine the shell you are currently using, run:  
  ```bash
  echo $SHELL
  ```

#### Switching Shells

To fully switch to a new shell and load its environment, simply type the shell name. This will load the shell's startup files (e.g., `.bashrc`, `.zshrc`).  
  ```bash
  tcsh
  ```
This approach is useful when you want to use the shell with all its custom configurations and environment variables.

##### Switching Shells Without Loading a New Environment

If you want to switch to a different shell without loading a new environment, use the `--norc` or `--noprofile` options (depending on the shell). This prevents the shell from reading its startup files, allowing you to test or use the shell in a minimal state.  
Example:  
  ```bash
  bash --norc
  ```

##### Interactive Mode

The `-i` argument of many shells starts the shell in **interactive mode**. This is useful when you want to ensure the shell behaves as if it were started interactively, even if it is being invoked from a script or another non-interactive context.  
Example:  
  ```bash
  bash -i
  ```

This ensures that the shell reads its interactive startup files and allows user interaction.

#### Configuring the Default Shell

A user's default shell is configured in the `/etc/passwd` file.  
  Example entry:  
  ```bash
  username:x:1000:1000:User Name:/home/username:/bin/bash
  ```

The user's default login shell is the last entry in each line of `/etc/passwd`. In this case it is `/bin/bash`. The full path to the shell executable must be specified for the user to be able to login! 

#### Privileged User Indicator

In a UNIX terminal, the prompt changes to indicate whether you are a regular user or a privileged user:  
  - `$`: Regular user.  
  - `#`: Root or privileged user.

### Variables

**Shell variables** are local to the current shell session.  

Example of setting a shell variable:  
  ```bash
  VARIABLE="value"
  ```

**Environment variables** are still limited within the same process, but also inherited by child processes.  To make a shell variable an environment variable, use the `export` command:  
  ```bash
  export VARIABLE
  ```

**Limitations**:
  - Environment variables are scoped to the process and its child processes. They are not shared across unrelated processes.
  - Changes to environment variables in a shell session do not persist after the session ends unless explicitly added to configuration files like `.bashrc` or `.profile`.
  - Overuse of environment variables can lead to conflicts or unintended behavior, especially if variable names are not unique.

#### Making Environment Variables Permanent

To make environment variables persistent across sessions, add them to the appropriate configuration file:  
  - For a single user: `~/.bashrc` or `~/.profile`.  
  - For all users: `/etc/profile`.

Note: `.bashrc` is the configuration file for the `bash` shell.  Other shells have similar files (e.g. `.zshrc` for `zsh`).

#### Useful Environment Variable Commands

| Command                  | Action                                                                                                                                                                  |
| ------------------------ | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `env`                    | List all current environment variables and their values.                                                                                                                |
| `export [variable_name]` | <p>Define the value of an environment variable. Can be a new or existing variable.</p><p><em>Exported variables only work in the context of the current shell.</em></p> |
| `echo $PATH`             | List the values in the PATH environment variable.                                                                                                                       |
| `echo $USER`             | Show the current username.                                                                                                                                              |
| `echo $PWD`              | Show the current working directory.                                                                                                                                     |
| `echo $HOME`             | Show the current user's home directory                                                                                                                                  |
| `echo "$$"`              | Show the process ID of the current shell.                                                                                                                               |
| `stty size`              | Show number of rows and columns in the current shell.                                                                                                                   |

#### Common Environment Variables

##### $PATH

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

##### $HISTCONTROL

The HISTCONTROL environment variable can be used to control whether the bash history removes duplicate commands, commands that start with a space, or both. The default behavior is to remove both.

```bash
export HISTCONTROL=ignoredups
```

`ignoredups` - Ignore Duplicates

##### $HISTIGNORE

The HISTIGNORE environment variable can be used to filter commands so they do not appear in the history.

```bash
export HISTIGNORE="ls:[bf]g:exit:history"
```

This example causes the history command to not log common commands such as `ls`,`bg`,`fg`,`exit`,and `history`. Uses standard bash text shortcuts such as \[ ] to indicate options.

##### $HISTTIMEFORMAT

The HISTTIMEFORMAT environment variable controls date/time stamps in the output of the history command.

```bash
export HISTTIMEFORMAT='%F %T '
#show date and time before each command in history
```

### Special Characters and Shell Features

#### Escape Character
- The backslash (`\`) is used as an escape character to interpret special characters literally.  
  Example:  
  ```bash
  echo "This is a \$variable"
  ```

### Shell Globbing and Expansion

Shell globbing and expansion are two distinct mechanisms used by the shell to interpret and process patterns or variables in commands. While they may seem similar, they serve different purposes:

- **Shell Globbing**: Refers to the use of wildcard patterns to match filenames or directories. It is primarily used for file and directory name matching.
- **Shell Expansion**: Refers to the process of replacing variables, commands, or patterns with their corresponding values or results before executing the command.

Below are detailed tables explaining the examples of each:

#### **Shell Globbing Examples**

| **Pattern**              | **Description**                                                                 | **Example**                                                                 |
|--------------------------|---------------------------------------------------------------------------------|-----------------------------------------------------------------------------|
| `*`                      | Matches zero or more characters.                                               | `ls *.txt` lists all files ending with `.txt`.                             |
| `?`                      | Matches exactly one character.                                                 | `ls file?.txt` matches `file1.txt` but not `file10.txt`.                   |
| `[abc]`                  | Matches any one of the characters inside the brackets.                         | `ls file[abc].txt` matches `filea.txt`, `fileb.txt`, or `filec.txt`.       |
| `[a-z]`                  | Matches any character in the specified range.                                  | `ls file[a-z].txt` matches `filea.txt`, `fileb.txt`, etc., but not `file1.txt`. |
| `[!abc]`                 | Matches any character not inside the brackets.                                 | `ls file[!abc].txt` matches files like `filed.txt` but not `filea.txt`.    |
| `{pattern1,pattern2}`    | Matches either pattern1 or pattern2.                                           | `ls {file1,file2}.txt` matches `file1.txt` and `file2.txt`.                |
| `**`                     | Matches directories recursively (requires `shopt -s globstar` in Bash).        | `ls **/*.txt` lists all `.txt` files in the current directory and subdirectories. |
| `[[:class:]]`            | Matches characters in a character class.                                       | `ls *[[:digit:]].txt` matches files ending with a digit, like `file1.txt`. |
|                          | **Common Character Classes**                                                   |                                                                             |
|                          | `[:alnum:]`: Alphanumeric characters.                                          |                                                                             |
|                          | `[:alpha:]`: Alphabetic characters.                                            |                                                                             |
|                          | `[:digit:]`: Digits.                                                           |                                                                             |
|                          | `[:lower:]`: Lowercase letters.                                                |                                                                             |
|                          | `[:upper:]`: Uppercase letters.                                                |                                                                             |
|                          | `[:space:]`: Whitespace characters.                                            |                                                                             |

#### **Shell Expansion Examples**

| **Type**                 | **Description**                                                                 | **Example**                                                                 |
|--------------------------|---------------------------------------------------------------------------------|-----------------------------------------------------------------------------|
| **Tilde Expansion**      | Expands `~` to the home directory.                                              | `ls ~/Documents` lists files in the `Documents` directory of the home folder. |
| **Variable Expansion**   | Replaces variables with their values.                                           | `echo $HOME` outputs the home directory path.                              |
| **Command Substitution** | Replaces a command with its output.                                             | `echo $(date)` outputs the current date and time.                          |
| **Arithmetic Expansion** | Evaluates arithmetic expressions.                                               | `echo $((2 + 3))` outputs `5`.                                             |
| **Brace Expansion**      | Expands patterns enclosed in curly braces `{}`.                                 | `echo {a,b,c}` outputs `a b c`.                                            |
| **Filename Expansion**   | Matches filenames using wildcards (similar to globbing).                        | `ls *.txt` lists all `.txt` files.                                         |
| **Process Substitution** | Allows a process's output to be used as input for another command.               | `diff <(ls dir1) <(ls dir2)` compares the contents of two directories.     |
| **Pathname Expansion**   | Expands patterns to match existing file paths.                                  | `echo /usr/*` lists all files and directories in `/usr`.                   |

By understanding the differences between shell globbing and expansion, you can effectively use these features to simplify and automate tasks in the shell.

#### PATH Variable

The `PATH` variable defines the directories the shell searches for executable files.  
  - View the current `PATH`:  
   ```bash
   echo $PATH
   ```
  - Add a directory to the `PATH`:  
   ```bash
   export PATH=$PATH:/new/directory
   ```

### Input/Output Streams and Redirection

File descriptors are integer handles used by Unix-like operating systems to represent open files or I/O streams. They act as an abstraction layer between the operating system and the program, allowing programs to read from or write to files, devices, or other data streams without needing to know the underlying details. This system allows Unix shells to flexibly manage input and output, making it easier to chain commands, log errors, or process data streams.

How Unix Shells Use File Descriptors:

#### Standard I/O Streams

| **Action**                     | **Command**                          | **Description**                                                                 |
|--------------------------------|--------------------------------------|---------------------------------------------------------------------------------|
| Redirecting output             | `command > file`                    | Sends STDOUT to a file.                                                        |
| Redirecting errors             | `command 2> error.log`              | Sends STDERR to a file.                                                        |
| Combining output and errors    | `command > output.log 2>&1`         | Sends both STDOUT and STDERR to the same file.                                 |
| Redirecting input              | `command < input.txt`               | Reads input from a file instead of the keyboard.                               |

#### Additional File Descriptors

Beyond `0`, `1`, and `2`, programs can open additional files or streams, which are assigned higher file descriptor numbers (e.g., 3, 4, etc.). These are used for custom I/O operations.

#### Piping

Use the pipe (`|`) to pass the output of one command as input to another:  
  ```bash
  command1 | command2
  ```

### Process Control

#### Running Commands in the Background

Add an ampersand (`&`) at the end of a command to run it in the background. This is particularly useful when running GUI programs from the commandline such as launching wireshark to open a pcap:
  ```bash
  wireshark /extract/forensic/pcaps/http.pcap &
  ```

When launching GUI (Graphical User Interface) programs from the command line, the terminal typically waits for the program to finish running before returning control to the user. This behavior is known as "blocking." In other words, the terminal session is "held up" by the program until it exits, meaning you can't use the terminal for other commands during this time.

To prevent this blocking behavior, you can append an `&` at the end of the command. This tells the shell to run the program in the background as a separate process. By doing so, the terminal immediately becomes available for further commands, even while the GUI program is still running.

How It Works:
* Foreground Process: Without the `&,` the program runs in the foreground, and the terminal is tied to its execution.
* Background Process: With the `&,` the program runs in the background, and the shell assigns it a process ID (PID). You can still interact with the process if needed (e.g., bringing it back to the foreground using fg).

Practical Use Cases:
* Running Multiple Programs: You can launch multiple GUI programs without waiting for each to finish.
* Long-Running Tasks: If a program takes a long time to complete, running it in the background allows you to continue using the terminal.

{% hint style="info" %}
**Note**: The program's output (if any) might still appear in the terminal unless redirected.
{% endhint %}

To fully detach the program from the terminal, you can use tools like nohup or redirect output to /dev/null:
  ```bash
  nohup gedit myfile.txt &> /dev/null &
  ```
This ensures the program continues running even if the terminal is closed.

#### Bringing a Process to the Foreground

Use the `fg` command to bring a background process to the foreground:  
  ```bash
  fg <job_id>
  ```

#### Running Multiple Commands

Use a semicolon (`;`) to run multiple commands sequentially, regardless of exit status:  
  ```bash
  command1 ; command2
  ```

Run a second command only if the first command succeeds (generally defined as returns an exit code of 0):  
  ```bash
  command1 && command2
  ```
Run a second command only if the first command fails (usually any exit code other than 0):  
  ```bash
  command1 || command2
  ```

### Useful Basic Commands

| Command               | Description                                                                                                                                                                                                           |
| --------------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `man $command`        | Get help with a command                                                                                                                                                                                               |
| `history`             | View history of commands that have been typed into the terminal                                                                                                                                                       |
| `!<number>`           | Repeat a specific command from command history                                                                                                                                                                        |
| `[up_down_arrow_keys]` | Use up/down arrow keys to cycle through previously used commands                                                                                                                                                                                |
| `Ctrl + r`            | Search through command history: type search term, then cycle with Up or Down arrows. (Do not need to type `history` command first)                                                                                                      |
| `alt + .`             | Cycle through previously used command arguments                                                                                                                                                                       |
| `ctrl + [arrow_keys]` | Use CTRL plus left/right arrow keys to move between "words" on a command line                                                                                                                                                                                |
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
| `{ }`    | Used to feed multiple parameters to a single command. Separate parameters by `,`    |
| `!`      | Followed by a digit will repeat the command from the history file that corresponds. |
| `!!`     | Repeat the previous command.                                                        |
| `0`      | Shortcut that stands for Standard Input (STDIN)                                     |
| `1`      | Shortcut that stands for Standard Output (STDOUT)                                   |
| `2`      | Shortcut that stands for Standard Error (STDERR)                                    |

## Filesystem Basics

Everything in Linux is a file, even directories and devices. This means that Linux treats hardware devices, sockets, pipes, and even processes as files, allowing for a unified interface for interacting with system resources. 

### Directories as Files
Directories in Linux are special types of files that contain references (or pointers) to other files and directories. They serve as organizational structures for the filesystem. While directories can be treated like files in many ways, they have some unique restrictions:
- **Cannot be directly edited**: Unlike regular files, directories cannot be opened and edited with a text editor.
- **Require special commands**: Operations like creating, deleting, or listing directories require commands such as `mkdir`, `rmdir`, or `ls`.

### Devices as Files
Linux represents hardware devices as files located in the `/dev` directory. These device files allow user-space programs to interact with hardware through standard file operations like reading and writing. Device files are categorized into:
- **Character devices**: Represent devices that handle data as a stream of bytes (e.g., `/dev/tty` for terminals).
- **Block devices**: Represent devices that handle data in fixed-size blocks (e.g., `/dev/sda` for hard drives).

### Implications of "Everything is a File"
1. **Unified Interface**: Applications can interact with hardware and system resources using the same file I/O operations (`open`, `read`, `write`, `close`).
2. **Flexibility**: Pipes, sockets, and other inter-process communication mechanisms are treated as files, simplifying their usage.
3. **Permissions**: The same permission model (read, write, execute) applies to all files, including directories and devices, ensuring consistent security management.

This design philosophy is a cornerstone of Linux and Unix-like operating systems, making them powerful and versatile for developers and system administrators.

### Directory structure

Below is an example of a typical directory structure found on the most common Linux distributions.

![Standard Linux Directories and Files](../.gitbook/assets/0\_roztlgbulghhs2p\_.png)

| **Directory** | **Description**                                                                 | **Example Files** |
|---------------|---------------------------------------------------------------------------------|-------------------------------------------------------------------------------------------------|
| `/bin`        | Common programs shared by the system, the system administrator, and users.      | `ls`, `cp`, `mv`, `bash` |
| `/boot`       | Startup files and the kernel.                                                   | `/boot/vmlinuz`, `/boot/grub/grub.cfg` |
| `/dev`        | References to all CPU peripheral hardware, represented as special files.        | `/dev/sda`, `/dev/null`, `/dev/tty` |
| `/etc`        | Most important system configuration files.                                       | `/etc/passwd`, `/etc/fstab`, `/etc/hosts` |
| `/home`       | Home directories of the common users.                                            | `/home/user1`, `/home/user2` |
| `/initrd`     | Contains information for booting (on some distributions).                       | Files related to initial RAM disk, e.g., `/initrd.img` |
| `/lib`        | Library files for programs needed by the system and users.                      | `/lib/libc.so.6`, `/lib/modules` |
| `/lost+found` | Contains files recovered during failures.                                       | Files with random names recovered after a crash, e.g., `#12345` |
| `/misc`       | For miscellaneous purposes.                                                     | Varies by system, often empty or used for custom mounts. |
| `/mnt`        | Standard mount point for external file systems.                                 | `/mnt/cdrom`, `/mnt/usb` |
| `/net`        | Standard mount point for entire remote file systems.                            | Varies by system, often used for network mounts. |
| `/opt`        | Typically contains third-party software files.                              | `/opt/google/chrome`, `/opt/vmware` |
| `/proc`       | A virtual file system containing information about system resources.            | `/proc/cpuinfo`, `/proc/meminfo`, `/proc/uptime` |
| `/root`       | The administrative user's home directory.                                       | `/root/.bashrc`, `/root/.ssh/authorized_keys` |
| `/sbin`       | Programs for use by the system and the system administrator.                    | `fsck`, `reboot`, `shutdown` |
| `/tmp`        | Temporary space for use by the system, cleaned upon reboot.                     | World-writeable, contains temporary files created by applications |
| `/usr`        | Programs, libraries, documentation, etc., for all user-related programs. /bin and /sbin folders live in here as well       | `/usr/bin/python3`, `/usr/lib/libc.so`, `/usr/share/man` |
| `/var`        | Storage for variable files and temporary files created by users.                | `/var/log/syslog`, `/var/mail`, `/var/spool` |

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
| `tail $file`                   | <p>Displays the last 10 lines of a file. Specify the number of lines with <code>-#</code></p><p><code>-f</code> - Update the output continuously.</p>                                                                                                      |
| `file $file`                   | Displays the filetype of a file, determined by the hexadecimal " [magic bytes](https://blog.netspi.com/magic-bytes-identifying-common-file-formats-at-a-glance/)".                                                                                         |

### File and directory creation and deletion

| Command                          | Description                                                                                                                                                                                              |
| -------------------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `touch $fileName`                | Create a new blank file with this name                                                                                                                                                                   |
| `cp $file [/path/to/]$newFile`   | Copy file from one location to another. If no location is specified, creates the copy in the same directory. \[Path optional]                                                                            |
| `mv $file [/path/to/]$newFile`   | Move file from one location to another. If no location is specified, renames the file in same directory (removes the old file).                                                                          |
| `rm $file`                       | Removes (deletes) a file.                                                                                                                                                                                |
| `rm *`                           | Removes (deletes) all files in the directory.                                                                                                                                                            |
| `rm -rf *`                       | Recursively deletes all files in the directory and all subdirectories and files. Will not prompt for approval with `-f`.                                                                                 |
| `mkdir [/path/to/]$dir`          | Makes a new empty directory                                                                                                                                                                              |
| `mkdir -p test/{test1,test2}`    | The `-p` flag creates multiple directories at once. In this example we use brace expansion to create `test/` and two subdirectories under it simultaneously.                                             |
| `rmdir $dir`                     | Deletes an (empty) directory                                                                                                                                                                             |
| `sudo rm --force $(which $file)` | Removes all instances of a specified filename. Only searches PATH directories. You could also use `find` or `locate` instead of `which` to find more files. With `--force` will not prompt for approval! |

### File & text manipulation

| Command                 | Description                                                                                                                                                                                                                                                                                                                                                                                                                                         |
| ----------------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `cat $file1 $file2`     | Concatenates the contents of two files                                                                                                                                                                                                                                                                                                                                                                                                              |
| `wc`                    | Counts the lines, words, and bytes in a file. `-l` will count only lines, `-m` will count only characters, `-c` will count only bytes, `-w` will count only words                                                                                                                                                                                                                                                                                   |
| `awk`                   | A programming language for text processing. Can do many many things.                                                                                                                                                                                                                                                                                                                                                                                |
| `sed`                   | <p>Performs text editing on a stream of text. Useful for replacing text in a file and much more. Example:</p><p>Replace all occurrences of 1001 with 0 in /etc/passwd.</p><p><code>sed -i -e 's/1001/0/g' /etc/passwd</code></p>                                                                                                                                                                                                                    |
| `cut`                   | Extract a section of text. **`-f`** selects the field, **`-d`** sets the delimiter.                                                                                                                                                                                                                                                                                                                                                                 |
| `sort`                  |                                                                                                                                                                                                                                                                                                                                                                                                                                                     |
| `uniq`                  |                                                                                                                                                                                                                                                                                                                                                                                                                                                     |
| `comm $file1 $file2`    | <p>Compare two files and show differences. Output is in three columns:</p><ul><li>Lines that are unique to the first file</li><li>Lines that are unique to the second file</li><li>Lines that are shared by both files.</li></ul>                                                                                                                                                                                                                   |
| `diff $file1 $file2`    | <p>Compare two files and show differences. Has two modes:</p><ul><li><code>-c</code> Context format</li><li><code>-u</code> Unified Format</li></ul>                                                                                                                                                                                                                                                                                                |
| `vimdiff $file1 $file2` | <p>Opens two files in Vim side-by-side and highlight the differences. Some shortcuts:</p><ul><li><code>[ctrl] w</code> - Switch to the other split window</li><li><code>do</code> - Gets changes from the other window into the current one</li><li><code>dp</code> - Puts the changes from the current window into the other one</li><li><code>]c</code> - Jump to the next change</li><li><code>[c</code> - Jump to the previous change</li></ul> |

#### Write to a file without opening a text editor

The `cat` command can be used to write text to a file without opening it in a text editor.  This can be very useful in times when you do not have a full TTY/PTY shell.

```bash
cat > $fileName
 [Type your file contents]
 [Press `Ctrl+d` to return to your terminal]
```

### File Permissions

The permissions for a file (for example, viewed with the `ls -l` command) are typically written as:

```bash
-rwxrwxrwx owner group [metadata] $filename
```

* **`r`** = read
* **`w`** = write
* **`x`** = execute

Breaking down this format gives us four parts:

1. The first character tells if it is a file or a directory. if it is a **`-`** (hyphen) then it is a file. However if the first character is a **`d`**, then the file is a directory. (Remember, technically everything in Linux is a file, even directories).
2. The next three characters specify the permissions of the owner of the file.
3. The following three characters specify the permissions of the group that owns the file.
4. The final three characters specify the permissions of all other users.

The permissions set is followed by the name of the file's owning user and then group. After that the file's metadata is displayed (typically filesize, modified date/time, inode number, etc.).  The filename is displayed last.

In the above example (`-rwxrwxrwx`), the owner, group, and everyone permissions are all `rwx`; hence anyone can read, write, and execute this file.

#### The chmod command

The `chmod` command is used to set the permissions on a file. This is usually expressed in one of two different formats, ugoa+rwx and octal notation. The command is used as follows:

```bash
chmod [permissions] $file
```

#### Octal notation

In octal notation, the permissions are assigned using triple octal (base8) digits. The first digit is the cumulative permissions for the owner, the second for the group, and the third for everyone else.

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

Therefore, if you want to give only the owner read and write permissions, they would be assigned `600` (4+2=6).

Taking the same example from above, to assign the permissions `-rwxrwxrwx` the command would be:

```bash
chmod 777 $file
```

That is: read (4), write (2), and execute (1) permissions for the owner, group, and all others.

#### ugoa+rwx notation

In this notation format, there are three main components:

1. _Who._ The users to modify permissions for: `u` = user (owner), `g` = group, `o` = others, and finally `a` = u+g+o (all).
2. _What._ The modifier: `=` to set permissions, `+` for adding permissions, `-` for removing permissions.
3. _Which._ The permissions to set, add, or remove: one or more of `rwx` as above.

As you can see, this notations allows for easier and more explicit control over exactly which permissions are given to whom.

Examples:

To give all users the write permission:

```bash
chmod a+w $file
```

To remove write and execute permissions from the 'other' group:

```bash
chmod o-wx $file
```

These permission changes can also be chained by adding a comma between the permission changes.

To add read/write permissions for the file owner and group, while making it read only for everyone else:

```bash
chmod ug+rw,o=r $file
```

### **Advanced Permissions in Linux**

Beyond standard read, write, and execute permissions, Linux offers **special permissions** like **SUID (Set User ID)** and **GUID (Set Group ID)**, which allow files and executables to run with elevated privileges.

#### **Set User ID (SUID)**

The **SUID** (Set User ID) permission allows a file to execute with the privileges of its **owner**, rather than the user running it. This is commonly used in programs that require elevated privileges (e.g., `passwd` for changing passwords).

##### **How to Set SUID**

To add the **SUID** bit to a file:
```sh
chmod 4000 file
chmod +s file
```
##### **Verifying SUID**
Run:
```sh
ls -l file
```
If SUID is set, the output will show:
```
-rwsr-xr-x 1 root root 12345 Apr 21 12:00 file
```

Note the **`s`** in the **owner’s execute permission** (`rws`), indicating that SUID is active.

##### **Example: SUID in Action**

The `passwd` command runs with **root privileges** via SUID:
```sh
ls -l /usr/bin/passwd
```

Output:

```
-rwsr-xr-x 1 root root 52724 Apr 21 12:00 /usr/bin/passwd
```

When a regular user runs `passwd`, it executes as **root** to modify the password database.

---

#### **Set Group ID (GUID)**

Similar to SUID, the **GUID (Set Group ID)** permission allows files to execute with the **group’s privileges** instead of the user’s privileges. This is useful in shared directories where multiple users need access.

##### **How to Set GUID**

To set GUID on a file:

```sh
chmod 2000 file
chmod +g file
```
##### **Verifying GUID**

To verify permissions on a file, run:

```sh
ls -l file
```

If GUID is set, you will see:

```
-rwxr-sr-x 1 user group 12345 Apr 21 12:00 file
```

The **`s`** in the **group execute permission** (`r-s`) confirms that GUID is active.

##### **Example: GUID in Action**

When set on a **directory**, GUID ensures that all files created within inherit the same group ownership.

Set GUID on a shared directory:

```sh
chmod 2775 /shared
```

Now, any files created inside `/shared` will belong to the directory’s group.

---

#### **Security Considerations**

- **SUID/GUID can be risky**: If improperly set on sensitive binaries, they can be exploited for privilege escalation.
- **Audit SUID/GUID files regularly**:
  ```sh
  find / -perm -4000 -type f 2>/dev/null   # Find SUID files
  find / -perm -2000 -type f 2>/dev/null   # Find GUID files
  ```
- **Restrict executable SUID/GUID binaries** in critical environments (especially on shared or multi-user systems).

#### The sticky bit

The **sticky bit** is a special permission that prevents users from deleting files **they don’t own** within a shared directory, even if they have write access. This is commonly used in directories like `/tmp`, where multiple users store temporary files.

##### **Setting the Sticky Bit**

To set the **sticky bit** on a directory, use:

```sh
chmod +t /shared_directory
```

Or, using octal notation:

```sh
chmod 1000 /shared_directory
```

##### **Verifying Sticky Bit**

Run:

```sh
ls -ld /shared_directory
```

Output:

```
drwxrwxrwt 2 user group 4096 Apr 21 12:00 /shared_directory
```

Note the **"t"** at the end of the permissions, indicating the sticky bit is active.

##### **How Sticky Bits Work**

- If a directory **does not have a sticky bit**, any user with **write access** can delete any file inside.
- When the **sticky bit is set**, only:
  - The **file’s owner** can delete their file.
  - The **root user** can remove any file.

##### **Common Usage Example**

The `/tmp` directory is a well-known example:

```sh
ls -ld /tmp
```

Output:

```
drwxrwxrwt 10 root root 4096 Apr 21 12:00 /tmp
```

Since `/tmp` is shared among all users, the sticky bit prevents users from deleting files that aren’t theirs.

##### **Best Practices**

- Use sticky bits on **shared directories** (e.g., `/tmp`, project collaboration folders).
- Regularly **audit permissions** using:
  ```sh
  find / -perm -1000 -type d 2>/dev/null
  ```
- This lists all directories where sticky bits are set.

#### The chown command

The `chown` command can be used to change the owner of a file or a directory.

```bash
chown $user $group $file
```

The above command would change the owner of the file to `$user` and also the group to `$group`.

### File Attributes

#### Read attributes of files on Linux with lsattr

`lsattr` lists the file attributes on a second extended file system. See `chattr` below for a description of each attribute.

Useful options:

| Argument | Description                                                                        |
| -------- | ---------------------------------------------------------------------------------- |
| `-R`     | Recursively list attributes of directories and their contents.                     |
| `-a`     | List all files in directories, including files that start with `.` (hidden files). |
| `-d`     | List directories like other files, rather than listing their contents.             |
| `-l`     | Print the options using long names instead of single character abbreviations.      |

You can chain together these options to recursively list the attributes of all files and folders in a directory with long names:

```bash
lsattr -Ral /home/
```

#### Change attributes of files on Linux with chattr

`chattr` changes the file attributes on a Linux file system.

> The format of a symbolic mode is `+-=[aAcCdDeFijmPsStTux]`.

| Symbol | Meaning                                                      |
| ------ | ------------------------------------------------------------ |
| `+`    | Add the following attributes the to specified file           |
| `-`    | Remove the following attributes from the specified file      |
| `=`    | Set the attributes of the specified file to be the following |

The letters `aAcCdDeFijmPsStTux` select the new attributes for the specified files:

| Attribute | Description                        |
| --------- | ---------------------------------- |
| `a`       | append only                        |
| `A`       | no atime updates                   |
| `c`       | compressed                         |
| `C`       | no copy on write                   |
| `d`       | no dump                            |
| `D`       | synchronous directory updates      |
| `e`       | extent format                      |
| `F`       | case-insensitive directory lookups |
| `i`       | immutable                          |
| `j`       | data journaling                    |
| `m`       | don't compress                     |
| `P`       | project hierarchy                  |
| `s`       | secure deletion                    |
| `S`       | synchronous updates                |
| `t`       | tail-merging                       |
| `T`       | top of directory hierarchy         |
| `u`       | undeletable                        |
| `x`       | direct access for files            |

The following attributes are read-only and may be listed by `lsattr` but not modified by `chattr`:

| Attribute | Description       |
| --------- | ----------------- |
| `E`       | encrypted         |
| `I`       | indexed directory |
| `N`       | inline data       |
| `V`       | verity            |

See the [chattr manpage](https://www.man7.org/linux/man-pages/man1/chattr.1.html) for more detailed descriptions of each attribute.

### **File Compression Tools**

| Command       | Description | Example |
|--------------|-------------|-----------|
| **unzip**    | Extracts files from a `.zip` archive. | `unzip file.zip` |
| **zip**      | Compresses files into a `.zip` archive. | `zip archive.zip file1 file2` |
| **gunzip**   | Decompresses `.gz` files created by `gzip`. | `gunzip file.gz` |
| **gzip**     | Compresses files using GNU Zip, reducing size efficiently. | `gzip file.txt` → Produces `file.txt.gz` |
| **tar**      | Archives files and directories without compression. | `tar -cvf archive.tar folder/` |
| **tar + gzip** | Creates a compressed archive using gzip. | `tar -czvf archive.tar.gz folder/` |
| **tar + bzip2** | Uses **bzip2** for higher compression. | `tar -cjvf archive.tar.bz2 folder/` |
| **tar + xz** | Compresses with **xz**, producing very small files. | `tar -cJvf archive.tar.xz folder/` |
| **xz**       | Compresses files using the **xz** algorithm. | `xz file.txt` |
| **bzip2**    | Compresses files with higher efficiency than gzip. | `bzip2 file.txt` |
| **7z**       | Compresses files using the **7z** format. | `7z a archive.7z file1 file2` |
| **rar**      | Compresses files into `.rar` archives (requires `rar` package). | `rar a archive.rar file1 file2` |
| **tar -xf**  | Extracts files from a `.tar` archive. | `tar -xf archive.tar` |

### **Encryption Tools**

| Command       | Description | Example |
|--------------|-------------|-----------|
| **gpg (GnuPG)** | Encrypts files securely using password-based encryption. | `gpg -c file.txt` |
| **gpg --decrypt** | Decrypts a file previously encrypted with `gpg`. | `gpg file.txt.gpg` |
| **openssl**  | Encrypts files using OpenSSL encryption. | `openssl enc -aes-256-cbc -salt -in file.txt -out file.enc` |
| **aespipe**  | Encrypts files and data streams using AES encryption. | `cat file.txt \| aespipe -e > file.enc` |
| **dm-crypt/LUKS** | Full-disk encryption tool built into Linux, commonly used for encrypting partitions. | `cryptsetup luksFormat /dev/sdX` |
| **EncFS**    | Encrypts individual files and directories dynamically without requiring a full disk encryption setup. | `encfs ~/encrypted ~/decrypted` |
| **eCryptfs** | Stackable cryptographic filesystem, often used for encrypting home directories. | `mount -t ecryptfs /home/user /home/user` |
| **VeraCrypt** | Cross-platform encryption tool for encrypting entire disks or partitions. | `veracrypt -c` |
| **bcrypt**   | Encrypts files using the Blowfish cipher. | `bcrypt file.txt` |
| **CryFS**    | Encrypts files for cloud storage, ensuring metadata and filenames remain encrypted. | `cryfs ~/encrypted ~/decrypted` |
| **Tomb**     | Creates encrypted storage containers using LUKS. | `tomb create secure.tomb` |
| **Cryptmount** | Allows non-root users to mount encrypted filesystems. | `cryptmount -m secure` |

## System Information

### **System Information**

| Command             | Description |
|---------------------|-------------|
| `uname -a`         | Shows OS details, hostname, kernel version, and architecture. |
| `lsb_release -a`   | Displays Linux distribution information (Debian-based distros). |
| `cat /etc/os-release` | Shows distribution details (works on most distros). |
| `hostnamectl`      | Provides details on hostname, kernel, and architecture. |
| `df -h`           | Displays disk space usage in a human-readable format. |
| `free -h`         | Shows memory usage including swap space. |
| `uptime`          | Displays system uptime and load average. |
| `who -b`          | Shows last system boot time. |
| `dmesg \| head`    | Displays system log messages (hardware boot events). |
| `lsblk`           | Lists block devices (disks and partitions). |
| `mount \| column -t` | Shows mounted file systems. |
| `env`             | Prints system environment variables. |

### **Processes**

| Command          | Description |
|-----------------|-------------|
| `ps`           | Lists running processes for the current user only. |
| `ps aux`       | Shows all running processes with details for all users. |
| `top`          | Provides a real-time view of system resource usage and processes. |
| `htop`         | Enhanced version of `top` with an interactive UI (install with `sudo apt install htop`). |
| `pgrep process_name` | Finds processes by name and returns their process IDs. |
| `pidof process_name` | Returns the process ID of a running program. |
| `kill PID`     | Terminates a process by its PID. |
| `kill -9 PID`  | Forcefully terminates a process. |
| `pkill process_name` | Kills processes by name. |
| `nice -n priority command` | Adjusts process priority when executing a command. |
| `renice priority -p PID` | Changes priority of a running process. |
| `strace -p PID` | Debugs a running process by tracing system calls. |

### **The `/proc` Directory**

The `/proc` directory is a **virtual filesystem** in Linux that provides runtime system information in a structured, readable format. Unlike traditional directories, `/proc` doesn’t store actual files; instead, it generates dynamic data about system processes and hardware on the fly.

#### **Why `/proc` Matters**

- It allows users and administrators to **monitor system performance**.
- It provides detailed insights into **running processes, memory usage, hardware configurations**, and more.
- Many Linux tools like `top`, `ps`, and `htop` rely on `/proc` for retrieving system statistics.

#### **Key Files & Directories**

- `/proc/cpuinfo` → Displays information about the CPU.
- `/proc/meminfo` → Shows detailed memory usage.
- `/proc/uptime` → Indicates how long the system has been running.
- `/proc/loadavg` → Displays system load averages.
- `/proc/swaps` → Lists active swap partitions.
- `/proc/[PID]` → Contains details for each running process (where `[PID]` is the process ID).

#### **Exploring `/proc` for System Insights**

Here are some key files inside `/proc` that can provide valuable system data:

| File | Purpose | Example Usage |
|------|---------|--------------|
| `/proc/cpuinfo` | Displays CPU details (cores, vendor, speed). | `cat /proc/cpuinfo` |
| `/proc/meminfo` | Shows memory statistics (RAM usage, swap, buffers). | `cat /proc/meminfo \| grep MemTotal` |
| `/proc/uptime` | Indicates how long the system has been running. | `cat /proc/uptime` |
| `/proc/loadavg` | Displays system load averages over 1, 5, and 15 minutes. | `cat /proc/loadavg` |
| `/proc/swaps` | Lists active swap partitions. | `cat /proc/swaps` |
| `/proc/filesystems` | Shows supported filesystems by the kernel. | `cat /proc/filesystems` |

---

### **Monitoring Running Processes via `/proc`**

Each process running on the system has a **dedicated directory** under `/proc`, named by its **Process ID (PID)**. Example: `/proc/1234` corresponds to process ID `1234`.

| File | Description | Example Usage |
|------|-------------|--------------|
| `/proc/[PID]/cmdline` | Displays the exact command used to start the process. | `cat /proc/1234/cmdline` |
| `/proc/[PID]/status` | Provides detailed status info, including memory and CPU usage. | `cat /proc/1234/status \| grep VmRSS` |
| `/proc/[PID]/fd/` | Lists open file descriptors of the process. | `ls -l /proc/1234/fd/` |
| `/proc/[PID]/environ` | Displays environment variables for the process. | `cat /proc/1234/environ` |

**Security Warning:** `/proc/[PID]/environ` may expose sensitive environment variables, such as **API keys and passwords** used by the process.

---

### **Changing Kernel Parameters Using `/proc/sys`**

The `/proc/sys` directory allows **on-the-fly tuning of system behavior**. Instead of permanently modifying system configs, administrators can dynamically adjust performance-related settings.

| File | Purpose | Example Usage |
|------|---------|--------------|
| `/proc/sys/kernel/hostname` | Displays or modifies the system hostname. | `echo "NewHost" > /proc/sys/kernel/hostname` |
| `/proc/sys/net/ipv4/ip_forward` | Enables/disables IP forwarding (useful for setting up a router). | `echo 1 > /proc/sys/net/ipv4/ip_forward` |
| `/proc/sys/vm/swappiness` | Controls how aggressively the system swaps memory. | `echo 10 > /proc/sys/vm/swappiness` |
| `/proc/sys/kernel/panic` | Sets the timeout before the system reboots after a kernel panic. | `echo 30 > /proc/sys/kernel/panic` |

For persistent changes across reboots, update `/etc/sysctl.conf`:

```sh
echo "net.ipv4.ip_forward = 1" >> /etc/sysctl.conf
sysctl -p  # Apply changes
```

---

### **Finding System Limits via `/proc`**

Linux enforces resource limits to **prevent system overuse**. The `/proc` directory contains relevant limit files.

| File | Purpose | Example Usage |
|------|---------|--------------|
| `/proc/sys/fs/file-max` | Maximum number of open files allowed. | `cat /proc/sys/fs/file-max` |
| `/proc/sys/kernel/threads-max` | Max number of threads that can be created. | `cat /proc/sys/kernel/threads-max` |
| `/proc/sys/net/core/somaxconn` | Maximum queue length for incoming connections. | `cat /proc/sys/net/core/somaxconn` |

If you need to **increase the maximum number of open files**, adjust:

```sh
echo "100000" > /proc/sys/fs/file-max
```

---

### **Debugging with `/proc`**

Developers and system administrators use `/proc` for **troubleshooting performance issues**:

- **Check network connections:**  
  ```sh
  cat /proc/net/tcp | grep :80  # Find all active TCP connections on port 80
  ```
- **Monitor kernel events:**  
  ```sh
  dmesg | tail -20  # Shows the latest 20 kernel log messages
  ```
- **Analyze running processes:**  
  ```sh
  ps -eo pid,comm | grep firefox  # Find Firefox’s process ID
  cat /proc/$(pgrep firefox)/status  # Get its resource usage details
  ```

### **Services**

Services in Linux are **background processes** that provide various system functions, such as networking, logging, or application hosting. These services can be started, stopped, restarted, or configured to start at boot. Linux uses **init systems** to manage these services, with **Systemd** and **SysVinit (System V)** being the two major methods.

Most **modern Linux distributions** (Ubuntu, Fedora, RHEL) use **Systemd** due to its speed and flexibility. **SysVinit** is mostly found on **legacy systems**, but some lightweight distros (like Alpine Linux) still use it.

---

### **How Services Work in Linux**  

Linux services function as **daemon processes**, meaning they run in the background without direct user interaction. These services are controlled through a process management system known as an **init system**—responsible for **starting, stopping, and managing processes** during system boot and runtime.

Some common services include:

- **Network services** (`NetworkManager`, `sshd`, `apache2`)
- **Logging services** (`rsyslog`, `journalctl`)
- **Cron jobs** (`cron`, `anacron`)
- **Database services** (`mysqld`, `postgresql`)

---

### **Systemd vs. SysVinit (System V)**  

Here are some of the differences between the two main service management systems in Linux:

| Feature | **Systemd** | **SysVinit (System V)** |
|---------|------------|-------------------|
| **Service Management** | Uses `systemctl` to start, stop, restart, and enable services. | Uses `service` and `chkconfig` for service control. |
| **Startup Speed** | **Parallel** service startup for fast boot times. | Services start **sequentially**, leading to slower boot times. |
| **Logging** | Uses `journalctl` for advanced logging and debugging. | Relies on traditional log files (`/var/log`). |
| **Dependency Handling** | Automatically manages dependencies between services. | Manual dependency management required. |
| **Configuration** | Centralized unit files (`/etc/systemd/system/`). | Uses shell scripts in `/etc/init.d/`. |
| **Modern Adoption** | Used in **most** modern Linux distributions (Ubuntu, CentOS, Fedora, Arch). | Found in **older** distros (Debian, Slackware, older CentOS versions). |

---

### **Managing Services in Systemd**

With **Systemd**, services are managed using the `systemctl` command:

```sh
systemctl start apache2    # Start a service
systemctl stop apache2     # Stop a service
systemctl restart apache2  # Restart a service
systemctl enable apache2   # Enable service at boot
systemctl disable apache2  # Disable service at boot
systemctl status apache2   # Check service status
```

To view all active services:

```sh
systemctl list-units --type=service
```

---

### **Managing Services in SysVinit**

Older **SysVinit** systems use the `service` command and scripts in `/etc/init.d/`: 

```sh
service apache2 start    # Start a service
service apache2 stop     # Stop a service
service apache2 restart  # Restart a service
chkconfig apache2 on     # Enable service at boot
chkconfig apache2 off    # Disable service at boot
```

View all active services:

```sh
service --status-all
```

In modern Linux systems, both set of commands are generally available for use, and are often mapped to do the same thing as many system admins have built the habit of using one set of commands over the other.

#### Other service command examples:

| Command                     | Description |
|-----------------------------|-------------|
| `systemctl list-unit-files` | Shows all installed services with their status. |
| `systemctl list-units --type=service` | Lists all **active** services. |
| `systemctl status service_name` | Displays detailed status of a specific service. |
| `systemctl start service_name` | Starts a service. |
| `systemctl stop service_name` | Stops a service. |
| `systemctl restart service_name` | Restarts a service. |
| `systemctl enable service_name` | Enables a service to start on boot. |
| `systemctl disable service_name` | Disables a service from starting at boot. |
| `journalctl -u service_name` | Shows logs for a specific service. |
| `service --status-all` | Lists all services (SysV init-based systems). |
| `chkconfig --list` | Lists services and their startup status (RHEL-based systems). |
| `netstat -tulnp` | Shows network services and ports currently in use. |


## Networking

Networking in Linux is built on a flexible and robust system that enables communication between devices over different protocols, such as TCP/IP. Linux provides various commands and configuration files for managing network interfaces, routing, services, and troubleshooting connectivity issues.

Linux networking consists of several key components:  

- **Network Interfaces** (`eth0`, `wlan0`, `lo`) – physical or virtual devices connecting to networks.  
- **IP Addressing** – static or dynamic (DHCP) assignments to interfaces.  
- **Routing** – directing traffic between networks using `ip route` or `route`.  
- **Firewalls & Security** – managed using tools like `iptables` and `firewalld`.  
- **Network Monitoring** – troubleshooting connectivity with tools such as `ping`, `netstat`, and `tcpdump`.  

---

### **Basic Networking Commands**  

These Linux networking commands help manage interfaces, connections, and troubleshooting:

| Command | Description | Example Usage |
|---------|-------------|--------------|
| `ip a` | Displays network interfaces and IP addresses. | `ip a show eth0` |
| `ifconfig` | Shows or configures network interfaces (deprecated, replaced by `ip`). | `ifconfig eth0` |
| `nmcli dev status` | Lists network devices and their status using NetworkManager. | `nmcli dev status` |
| `dhclient` | Requests a new IP address via DHCP. | `dhclient eth0` |
| `ping` | Tests network connectivity to a target IP or domain. | `ping google.com` |
| `traceroute` | Displays the route packets take to a destination. | `traceroute 8.8.8.8` |
| `netstat -tulnp` | Lists active network connections and listening services. | `netstat -tulnp \| grep :80` |
| `ss -tulnp` | Modern replacement for `netstat`, shows listening ports and active connections. | `ss -tulnp` |
| `tcpdump` | Captures and analyzes network packets. | `tcpdump -i eth0 port 443` |
| `iptables -L` | Lists firewall rules set by `iptables`. | `iptables -L INPUT` |
| `ufw status` | Displays firewall rules with **Uncomplicated Firewall** (UFW). | `ufw status` |
| `ip route` | Shows or modifies IP routing tables. | `ip route add 192.168.1.0/24 via 192.168.1.1` |
| `hostname -I` | Shows the current IP address of the system. | `hostname -I` |
| `curl -I` | Fetches HTTP headers from a website to test connectivity. | `curl -I example.com` |

---

### **Network Configuration**

#### **Common Network Configuration Files in Linux**  

Linux relies on several key files to store and manage **network settings, services, and tasks**.

| File | Purpose | Example Usage |
|------|---------|--------------|
| `/etc/network/interfaces` | Defines network configurations (Debian-based systems). | Configure static IP: `auto eth0` + `iface eth0 inet static` |
| `/etc/sysconfig/network-scripts/ifcfg-eth0` | Network configuration for RHEL-based systems. | Set DHCP: `BOOTPROTO=dhcp` |
| `/etc/resolv.conf` | Stores DNS server settings for name resolution. | `nameserver 8.8.8.8` |
| `/etc/hosts` | Defines local hostname resolutions without DNS. | `127.0.0.1 localhost` |
| `/etc/nsswitch.conf` | Configures lookup order for hostname resolution. | `hosts: files dns` |
| `/etc/hostname` | Contains the system hostname. | Change hostname: `echo "NewHost" > /etc/hostname` |
| `/etc/iptables/rules.v4` | Persistent firewall rules for `iptables`. | `iptables-save > /etc/iptables/rules.v4` |
| `/var/log/syslog` | Logs general system and network-related events. | `tail -f /var/log/syslog` |

---

#### **Managing Network Interfaces**

| Command | Description | Example Usage |
|---------|-------------|--------------|
| `ip link show` | Displays the status of all network interfaces. | `ip link show eth0` |
| `ip link set eth0 up` | Activates a network interface. | `ip link set eth0 up` |
| `ip link set eth0 down` | Disables a network interface. | `ip link set eth0 down` |
| `ifconfig eth0 up` | Starts the interface (deprecated). | `ifconfig eth0 up` |
| `ifconfig eth0 down` | Shuts down the interface (deprecated). | `ifconfig eth0 down` |

---

#### **Configuring IP Addresses**

| Command | Description | Example Usage |
|---------|-------------|--------------|
| `ip addr show` | Lists all interfaces and assigned IPs. | `ip addr show eth0` |
| `ip addr add 192.168.1.100/24 dev eth0` | Assigns a new static IP to an interface. | `ip addr add 10.0.0.50/24 dev wlan0` |
| `ip addr del 192.168.1.100/24 dev eth0` | Removes an assigned IP from an interface. | `ip addr del 192.168.1.50/24 dev eth0` |
| `ifconfig eth0 192.168.1.100 netmask 255.255.255.0` | Configures a static IP (deprecated). | `ifconfig eth0 10.0.0.50 netmask 255.255.255.0` |

---

#### **Managing Routes**

| Command | Description | Example Usage |
|---------|-------------|--------------|
| `ip route show` | Displays the current routing table. | `ip route show` |
| `ip route add 192.168.10.0/24 via 192.168.1.1 dev eth0` | Adds a route to a network via a gateway. | `ip route add 10.0.0.0/16 via 10.0.0.1 dev eth0` |
| `ip route del 192.168.10.0/24` | Deletes a specific route. | `ip route del 10.0.0.0/16` |
| `route -n` | Displays routing table using legacy command (deprecated). | `route -n` |
| `route add default gw 192.168.1.1 eth0` | Sets a default gateway (deprecated). | `route add default gw 10.0.0.1 eth0` |

### **Wireless Network commands**

| Command | Description | Example Usage |
|---------|-------------|--------------|
| `iwconfig` | Shows wireless network details (SSID, signal strength, mode). | `iwconfig wlan0` |
| `iwlist scan` | Scans for available Wi-Fi networks. | `iwlist wlan0 scan` |
| `nmcli device status` | Shows network interfaces and their state. | `nmcli device status` |
| `nmcli device wifi list` | Lists available Wi-Fi networks. | `nmcli device wifi list` |
| `nmcli device wifi connect "NetworkSSID" --ask` | Connects to a Wi-Fi network (prompts for password). | `nmcli device wifi connect "HomeWiFi" --ask` |
| `nmcli device wifi connect "NetworkSSID" password "YourPassword"` | Connects to Wi-Fi without interactive input. | `nmcli device wifi connect "OfficeNet" password "SecurePass123"` |
| `nmcli connection show` | Displays saved network connections. | `nmcli connection show` |
| `nmcli connection down "NetworkSSID"` | Disconnects from a Wi-Fi network. | `nmcli connection down "HomeWiFi"` |
| `nmcli connection modify "NetworkSSID" ipv4.addresses 192.168.1.50/24` | Assigns a static IP to a wireless connection. | `nmcli connection modify "OfficeNet" ipv4.addresses 10.0.0.100/24` |
| `nmcli radio wifi off` | Turns off Wi-Fi completely. | `nmcli radio wifi off` |

---

### **Additional Network Troubleshooting Commands**

| Command | Description | Example Usage |
|---------|-------------|--------------|
| `ip addr show` | Shows all network interfaces and IP addresses. | `ip addr show eth0` |
| `ip link show` | Displays the status of network interfaces. | `ip link show wlan0` |
| `ip route show` | Displays the routing table and default gateway. | `ip route` |
| `ethtool eth0` | Provides details about a network interface (speed, duplex, link status). | `ethtool eth0` |
| `mtr google.com` | Continuous traceroute to analyze network stability. | `mtr -rw google.com` |
| `dig example.com` | Performs DNS lookups and queries nameservers. | `dig example.com` |
| `nslookup example.com` | Legacy DNS lookup tool to resolve domain names. | `nslookup example.com` |
| `host example.com` | Another alternative to `nslookup` for resolving DNS. | `host example.com` |
| `arp -a` | Displays the ARP cache to see connected devices. | `arp -a` |
| `nc -zv target.com 80` | Tests if a remote port is open (Netcat). | `nc -zv 8.8.8.8 53` |
| `tcpdump -i eth0` | Captures network packets for analysis. | `tcpdump -i eth0 port 443` |
| `nmap -sP 192.168.1.0/24` | Scans the network for active hosts. | `nmap -sP 192.168.1.0/24` |
| `netstat -i` | Lists network interfaces along with statistics. | `netstat -i` |
| `ss -tln` | Displays listening TCP ports and services. | `ss -tln` |
| `lsof -i` | Shows all processes using network connections. | `lsof -i :22` |
| `systemctl status network.service` | Checks if the network service is running. | `systemctl status NetworkManager.service` |

---

### **Firewall Configuration**  

Firewalls are essential for securing a Linux system by controlling incoming and outgoing network traffic based on predefined rules. Linux offers multiple firewall management tools, each with different capabilities and use cases.


#### **Which Firewall Should You Use?**

- Use **iptables** for **fine-grained control** in security-critical environments.
- Use **UFW** for **easy firewall management** on personal or desktop systems.
- Use **firewalld** if you need **dynamic zones** for managing multiple services efficiently.

---

#### **Kernel Modules for Firewall Configuration**  

Linux firewalls rely on kernel modules that provide packet filtering capabilities:

| Kernel Module | Description |
|--------------|-------------|
| `nf_tables`  | The successor to iptables, used by **nftables** for efficient packet filtering. |
| `iptables`   | Traditional firewall framework for packet filtering, NAT, and security policies. |
| `xtables`    | Used by iptables and nftables to define advanced filtering options. |
| `netfilter`  | Core Linux kernel framework for managing network packets and filtering. |
| `conntrack`  | Tracks connections for stateful firewall rules (used in iptables and firewalld). |
| `xt_tcpudp`  | Provides additional filtering options for TCP/UDP packets. |

You can check if these modules are loaded using `lsmod`:

```sh
lsmod | grep netfilter
```

---

#### **Comparison of Firewall Management Tools**  

Linux provides multiple tools for firewall management, each with unique strengths:

| Feature       | **iptables** | **UFW (Uncomplicated Firewall)** | **firewalld** |
|--------------|-------------|----------------------------------|--------------|
| **Complexity** | Advanced | Simple | Moderate |
| **Stateful Rules** | Yes | Yes | Yes |
| **Interface** | Command-line | User-friendly CLI | Dynamic Zone-based |
| **Logging Support** | Yes | Limited | Yes |
| **IPv6 Support** | Yes | Yes | Yes |
| **Firewall Zones** | No | No | Yes |
| **Best Use Case** | Fine-grained rule customization | User-friendly firewall for desktops | Managing multiple interfaces and services dynamically |

#### **iptables - Advanced Firewall Control**

`iptables` provides full control over packet filtering and NAT.  

Example:

```sh
iptables -A INPUT -p tcp --dport 22 -j ACCEPT   # Allow SSH connections
iptables -A INPUT -p icmp -j DROP               # Block ping requests
iptables -L                                     # List current rules
```

#### **UFW - Simplified Firewall for Users**

`UFW` is a more user-friendly wrapper for iptables.  

Example:

```sh
ufw enable                       # Enable firewall
ufw allow 22/tcp                 # Allow SSH
ufw deny 80/tcp                  # Block HTTP traffic
ufw status                       # Show active rules
```

#### **firewalld - Dynamic Firewall with Zones**

`firewalld` manages firewall rules dynamically with predefined zones.  

Example:

```sh
firewall-cmd --permanent --add-service=http  # Allow HTTP traffic
firewall-cmd --remove-service=ftp            # Block FTP traffic
firewall-cmd --list-all                      # Show rules in a zone
```

---

### Managing connections

TODO: add more information about Managing connections in Linux (Issue [#9](https://github.com/zweilosec/Infosec-Notes/issues/9))

* Add commands such as telnet, SSH, nc, curl, wget
* Add commands for listing information about open network connections: lsof -i, ss, netstat
* include description and examples

| Command  | Description                                                                                                                                                                                                                       |
| -------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `telnet` |                                                                                                                                                                                                                                   |
| `ssh`    |                                                                                                                                                                                                                                   |
| `nc`     |                                                                                                                                                                                                                                   |
| `curl`   | Transfer data to or from a server using a variety of protocols including IMAP/S, POP3/S, SCP, SFTP, SMB/S, SMTP/S, TELNET, TFTP, and others.                                                                                      |
| `wget`   | Downloads files using the HTTP,HTTPS, or FTP protocols.                                                                                                                                                                           |
| `axel`   | <p>Download files using concurrent connections</p><ul><li><code>-a</code> - Show progress indicator</li><li><code>-n #</code> - # number of connections to use</li><li><code>-o</code> - Specify the output file's name</li></ul> |

nc listener: `nc -lvnp <port>`

#### list open network connections

| Command    | Description                                                                            |
| ---------- | -------------------------------------------------------------------------------------- |
| `lsof -i`  |                                                                                        |
| `ss`       | Shows State, data sent/recieved, local process:port, remote address:port               |
| `ss -anlp` | Get all connections that are listening, do not resolve names, show process information |
| `netstat`  |                                                                                        |

### Shared folders

| Command                 | Description                                                                 |
|----------------------- |---------------------------------------------------------------------------|
| `showmount -e $ip`      | Show available shares to mount                                              |
| `smb://$ip/$share_name` | Connect to Windows SMB share folder                                        |
| `smbclient -L //server_ip -U username` | List available shares on a server                                         |
| `smbclient //server_ip/share_name -U username` | Connect to a share using smbclient                                      |
| `smbclient //server_ip/share_name -U username -c "prompt OFF; recurse ON; mget *"` | Recursively download files from a share using smbclient |
| `smbmap -H server_ip`   | Enumerate SMB shares and permissions                                       |
| `sudo mount -t cifs -o username=your_username,password=your_password //server_ip/share_name /mnt/shared` | Mount a CIFS/SMB share manually                          |
| `sudo mount server_ip:/share_name /mnt/shared` | Mount an NFS share manually                                              |

### Mounting and Using Network Shares

Network shares allow multiple users or systems to access shared files and directories over a network. Below are some common tools and commands for working with network shares, particularly Samba (SMB) shares.

#### Creating a Network Share (Samba)

1. Install Samba:
   ```bash
   sudo apt update
   sudo apt install samba
   ```

2. Edit the Samba configuration file:
   ```bash
   sudo vim /etc/samba/smb.conf
   ```

   Add a section for the shared folder:
   ```
   [shared_folder_name]
   path = /path/to/shared/folder
   browseable = yes
   read only = no
   writable = yes
   ```

3. Restart the Samba service:
   ```bash
   sudo systemctl restart smbd
   ```

4. Set permissions for the shared folder:
   ```bash
   sudo chmod 777 /path/to/shared/folder
   ```

#### Mounting a Network Share

1. Install the required tools:
   ```bash
   sudo apt install cifs-utils
   ```

2. Create a mount point:
   ```bash
   sudo mkdir /mnt/shared
   ```

3. Mount the share:
   ```bash
   sudo mount -t cifs -o username=your_username,password=your_password //server_ip/share_name /mnt/shared
   ```

   Replace `server_ip`, `share_name`, `your_username`, and `your_password` with the appropriate values.

4. To make the mount persistent, add an entry to `/etc/fstab`:
   ```
   //server_ip/share_name /mnt/shared cifs username=your_username,password=your_password 0 0
   ```

#### Useful Commands for Network Shares

- **List available shares on a server:**
  ```bash
  smbclient -L //server_ip -U username
  ```

- **Connect to a share using smbclient:**
  ```bash
  smbclient //server_ip/share_name -U username
  ```

- **Recursively download files from a share:**
  ```bash
  smbclient //server_ip/share_name -U username -c "prompt OFF; recurse ON; mget *"
  ```

#### Additional Tools

- **smbmap:** Enumerate SMB shares and permissions.
  ```bash
  smbmap -H server_ip
  ```

- **showmount:** List NFS shares:
  ```bash
  showmount -e server_ip
  ```

- **mount:** Mount NFS shares:
  ```bash
  sudo mount server_ip:/share_name /mnt/shared
  ```

#### Identifying Mounted Shared Folders/Drives

Linux provides built-in tools to identify and manage mounted shared folders or drives. Below are some commonly used commands:

- **`mount`**: Displays all currently mounted filesystems, including network shares.
  ```bash
  mount
  ```
  Look for entries with `cifs` or `nfs` to identify SMB or NFS shares.

- **`df`**: Reports disk space usage for mounted filesystems.
  ```bash
  df -h
  ```
  Use the `-h` flag for human-readable output. Network shares will typically appear with their mount points and remote server paths.

- **`findmnt`**: Provides a tree view of mounted filesystems.
  ```bash
  findmnt
  ```
  This command is particularly useful for visualizing the hierarchy of mounted filesystems.

- **`lsblk`**: Lists information about block devices, including mounted filesystems.
  ```bash
  lsblk
  ```
  Use this to identify devices and their mount points.

These tools are essential for troubleshooting and verifying the status of mounted shared folders or drives.

### DNS

| Command                                   | Description                                        |
| ----------------------------------------- | -------------------------------------------------- |
| `dig @$server $domain_or_ip $record_type` | Look up DNS information for a site                 |
| `dig -x $ip`                              | Reverse look up a domain from an IP                |
| `host $hostname`                          | Look up the IP address for a host- or domain-name. |

## Installing and Managing Programs

| Command                            | Description                                                                                                                                                                                                              |
| ---------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| `sudo apt update`                  | Update repository database                                                                                                                                                                                               |
| `sudo apt upgrade`                 | Update installed programs and packages (must update repository database first). Adding `-y` will accept all prompts and install automatically. Specifying a package name after "upgrade" will upgrade only that package. |
| `sudo apt dist-upgrade`            |                                                                                                                                                                                                                          |
| `sudo apt full-upgrade`            |                                                                                                                                                                                                                          |
| `apt search $keyword`              | Search for packages (unknown name) to install from repositories                                                                                                                                                          |
| `apt-cache search $keyword`        | Search for package in repositories                                                                                                                                                                                       |
| `apt show $package`                | Show details about the specified package                                                                                                                                                                                 |
| `sudo apt install $package`        | Installs the specified package (and any dependencies).                                                                                                                                                                   |
| `sudo apt remove --purge $package` | Uninstalls the specified package                                                                                                                                                                                         |
| `dpkg -i $deb_file`                | Installs the specified `.deb` package file (Does not install dependencies).                                                                                                                                              |
| `alien $file.rpm`                  | Convert rpm to Debian packages                                                                                                                                                                                           |

## Users and Groups

Linux provides robust tools for managing users and groups. Below are commands and examples for creating, modifying, and deleting users and groups, as well as managing passwords and viewing user-related information.

### Managing Users

| Command                          | Description                                                                 |
|----------------------------------|-----------------------------------------------------------------------------|
| `adduser $username`              | Add a new user with a home directory and default settings.                  |
| `userdel $username`              | Delete a user. Use `-r` to remove the user's home directory as well.        |
| `usermod -l $newname $oldname`   | Rename a user.                                                              |
| `passwd $username`               | Set or change the password for a user.                                      |

**Examples:**
```bash
# Add a new user named 'john'
sudo adduser john

# Delete the user 'john' and their home directory
sudo userdel -r john

# Change the password for 'john'
sudo passwd john
```

### Managing Groups

| Command                          | Description                                                                 |
|----------------------------------|-----------------------------------------------------------------------------|
| `addgroup $groupname`            | Create a new group.                                                         |
| `groupdel $groupname`            | Delete a group.                                                             |
| `usermod -aG $groupname $username`| Add a user to a group.                                                      |
| `gpasswd -d $username $groupname`| Remove a user from a group.                                                 |

**Examples:**
```bash
# Create a new group named 'developers'
sudo addgroup developers

# Add 'john' to the 'developers' group
sudo usermod -aG developers john

# Remove 'john' from the 'developers' group
sudo gpasswd -d john developers
```

### Viewing User and Group Information

| Command         | Description                                                                 |
|-----------------|-----------------------------------------------------------------------------|
| `id $username`  | Display user ID (UID), group ID (GID), and group memberships.              |
| `groups $username` | Show groups a user belongs to.                                           |
| `who`           | Show who is currently logged in.                                           |
| `w`             | Display who is logged in and what they are doing.                         |
| `last -a`       | Show the login history of users.                                           |

**Examples:**
```bash
# Display information about the current user
id

# Show groups for 'john'
groups john

# See who is logged in
who

# View login history
last -a
```

### User Privileges

| Command                      | Description                                             |
|------------------------------|---------------------------------------------------------|
| `sudo $command`              | Execute commands with elevated privileges.             |
| `sudo -u $username $command` | Execute a command as another user.                     |
| `sudo -l`                    | List `sudo` privileges for the current user.           |
| `sudo -k`                    | Stop remembering credentials and re-prompt for password.|

**Examples:**
```bash
# Run a command as another user
sudo -u john whoami

# List sudo privileges for the current user
sudo -l
```

## Using `getent`

The `getent` command is a versatile tool for querying entries from the system's databases, such as users, groups, and more. It is particularly useful for retrieving information about users and groups from `/etc/passwd`, `/etc/group`, or even network-based databases like LDAP or NIS.

| Command                     | Description                                                                 |
|-----------------------------|-----------------------------------------------------------------------------|
| `getent passwd $username`   | Retrieve information about a specific user from the passwd database.        |
| `getent group $groupname`   | Retrieve information about a specific group from the group database.        |
| `getent passwd`             | List all users in the passwd database.                                     |
| `getent group`              | List all groups in the group database.                                     |
| `getent hosts $hostname`    | Query the hosts database for a specific hostname.                          |
| `getent services $service`  | Query the services database for a specific service.                        |
| `getent protocols $protocol`| Query the protocols database for a specific protocol.                      |

**Examples:**
```bash
# Retrieve information about the user 'john'
getent passwd john

# Retrieve information about the group 'developers'
getent group developers

# List all users
getent passwd

# List all groups
getent group

# Query the hosts database for 'example.com'
getent hosts example.com

# Query the services database for 'http'
getent services http

# Query the protocols database for 'tcp'
getent protocols tcp
```

### Querying LDAP or NIS Databases

When configured, `getent` can also query network-based databases like LDAP or NIS. This is particularly useful in enterprise environments where user and group information is managed centrally.

**Examples:**
```bash
# Query LDAP for a specific user
getent passwd john

# Query LDAP for all users
getent passwd

# Query NIS for a specific group
getent group developers

# Query NIS for all groups
getent group
```

> **Note:** To enable LDAP or NIS queries, ensure that the appropriate Name Service Switch (NSS) modules are configured in `/etc/nsswitch.conf`. For example:
> ```
> passwd: files ldap
> group: files ldap
> hosts: files dns nis
> ```

The `getent` command is particularly useful in environments where user and group information is managed centrally, as it queries the system's Name Service Switch (NSS) configuration.


## Startup Scripts

Add script to run at startup: `update-rc.d </path/to/the/script> defaults` (needs 755 permissions)

Delete script from default autorun: `update-rc.d -f </path/to/the/script> remove`

## Make a Linux live boot USB

On Windows (easiest way!):

1. Download and run [Rufus](https://rufus.ie/).
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

## Troublshooting 

### Recover an unresponsive terminal

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

### Fixing `command-not-found` errors

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
* [https://explainshell.com/](https://explainshell.com/)
* [https://unix.stackexchange.com/questions/26047/how-to-correctly-add-a-path-to-path](https://unix.stackexchange.com/questions/26047/how-to-correctly-add-a-path-to-path)

If you like this content and would like to see more, please consider [buying me a coffee](https://www.buymeacoffee.com/zweilosec)!
