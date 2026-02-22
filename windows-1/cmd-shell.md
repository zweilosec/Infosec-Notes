---
description: Introduction to the Windows cmd.exe shell
---

# CMD.EXE

The **Windows Command Prompt (`cmd.exe`)** is an essential interface for executing text-based commands that control the operating system, automate tasks, and troubleshoot system issues. Unlike a graphical user interface (GUI), `cmd.exe` provides direct access to system functionalities through typed commands, making it a powerful tool for administrators, developers, and security professionals.

## **Use Cases for `cmd.exe`**

- **System Administration:** Modify system settings, manage processes, and configure user accounts.
- **Networking:** Troubleshoot connectivity, scan ports, and manage network shares.
- **Security & Forensics:** Analyze logs, check permissions, and identify suspicious activities.
- **Scripting & Automation:** Write batch scripts for repetitive tasks and scheduled jobs.
- **File & Directory Management:** Copy, move, delete, and modify file attributes efficiently.

## Shell Functionality

The shell in `cmd.exe` serves as a command-line interpreter that allows users to interact with the operating system by executing commands, running scripts, and managing system resources. It provides a text-based interface for performing a wide range of tasks, from basic file operations to advanced system configurations.

### Key Features of the `cmd.exe` Shell

- **Command Execution**:
  - The shell processes both built-in commands and external executables.
  - Commands can be executed interactively or through batch scripts (`.bat` or `.cmd` files).
  - See the [Windows Utilities](utilities.md) page for a reference of built-in commands and executables.

- **Batch Scripting**:
  - Automate repetitive tasks using batch scripts.
  - Supports control structures like loops (`for`), conditionals (`if`), and error handling (`goto` and `errorlevel`).
  - See my [scripting reference](../os-agnostic/scripting/script-language-comparison.md) for more information.

- **Environment Variable Management**:
  - Access and modify environment variables using the `set` command.
  - Use variables like `%PATH%`, `%USERNAME%`, and `%TEMP%` to customize the shell environment.

- **Redirection and Piping**:
  - Redirect input and output using operators like `>`, `>>`, and `<`.
  - Chain commands using pipes (`|`) to pass output from one command as input to another.

- **Error Handling**:
  - Use `errorlevel` to check the exit status of commands and handle errors in scripts.
  - Combine with conditional statements to create robust automation workflows.

- **Customization**:
  - Customize the shell prompt using the `prompt` command.
  - Change the appearance of the shell window (e.g., title, colors) using commands like `title` and `color`.

### Advanced Shell Features

#### **Command Chaining**

Command chaining allows you to execute multiple commands in sequence, controlling the flow based on the success or failure of each command.

| Operator / Syntax                  | Description                                                                                         | Example                                                                                          | Behavior / Output                                                                                  |
|------------------------------------|-----------------------------------------------------------------------------------------------------|--------------------------------------------------------------------------------------------------|----------------------------------------------------------------------------------------------------|
| `&&` (AND operator)                | Executes the next command only if the previous command succeeds (`ERRORLEVEL` 0).                   | `mkdir new_folder && echo Folder created`                                                        | Echoes "Folder created" only if the folder was created successfully.                               |
| `\|\|` (OR operator)                 | Executes the next command only if the previous command fails (nonzero `ERRORLEVEL`).                | `mkdir new_folder \|\| echo Failed to create folder`                                               | Echoes "Failed to create folder" only if folder creation fails.                                    |
| Combining `&&` and `\|\|`            | Handles both success and failure cases in a single line.                                            | `mkdir new_folder && echo Folder created \|\| echo Failed to create folder`                      | Echoes "Folder created" if successful, or "Failed to create folder" if not.                        |
| `&` (Sequential operator)          | Runs commands sequentially, regardless of success or failure.                                       | `echo First & echo Second`                                                                       | Both commands run one after the other, outputting "First" then "Second".                           |
| Parentheses `( )` for grouping           | Groups commands to control execution order and logic.                                               | `(echo Start && dir) \|\| echo Directory listing failed`                                           | Runs `echo Start` and `dir`; if either fails, echoes "Directory listing failed".                   |

**Usage Tips:**
- Use `&&` and `||` to create simple if-then-else logic in batch scripts.
- Combine multiple operators for more complex flows, e.g., `command1 && command2 || command3`.
- Parentheses can group multiple commands as a single unit, especially in scripts.
- Useful for error handling, such as running cleanup commands only if a previous step fails.

**Limitations:**
- `&&` and `||` evaluate only the immediate preceding command's exit code (`ERRORLEVEL`).
- Chaining does not replace full conditional logic; for complex scenarios, use `if` statements.
- Parentheses require careful quoting and spacing, especially in batch files.
- Some commands may not set `ERRORLEVEL` as expected; always test your chains for reliability.

- **Wildcards and Pattern Matching**: Wildcards are special characters used in `cmd.exe` to match multiple files or directories based on patterns. They are essential for batch operations and flexible file management.

  - `*` (asterisk): Matches zero or more characters in a file or directory name.
    - Example: `del *.txt` deletes all files ending with `.txt` in the current directory.
    - Example: `copy project*.* D:\Backup\` copies all files starting with "project" to the backup folder.
  - `?` (question mark): Matches exactly one character in a file or directory name.
    - Example: `dir file?.log` lists files like `file1.log`, `fileA.log`, but not `file10.log`.
    - Example: `del report??.docx` deletes files like `report01.docx`, `reportAB.docx`, but not `report1.docx`.

  **Usage Tips:**
  - Wildcards can be used with most file management commands: `dir`, `del`, `copy`, `move`, `ren`, etc.
  - You can combine wildcards for more complex patterns, e.g., `*.b??` matches files with a `.b` extension followed by any two characters.
  - Wildcards do not match directory separators (`\`), so patterns only apply within a single directory level.
  - In batch scripts, wildcards can be used with `for` loops:
    ```bat
    for %f in (*.log) do echo %f
    ```
    This echoes the name of each `.log` file in the current directory.

  **Limitations:**
  - Wildcards do not match hidden or system files unless the command explicitly includes them (e.g., `dir /a`).
  - Pattern matching is case-insensitive by default in Windows.

  For more advanced pattern matching (including regular expressions), use the `findstr` command.

##### **Input/Output Streams and Redirection**

Input/output (I/O) streams in `cmd.exe` allow you to control how commands receive input and where their output goes. This is essential for automation, scripting, and error handling.

**Key Streams:**
- **Standard Input (`stdin`, stream 0)**: Receives input from the keyboard or another command.
- **Standard Output (`stdout`, stream 1)**: Displays normal command output (default: console).
- **Standard Error (`stderr`, stream 2)**: Displays error messages (default: console).

**Redirection Operators:**
| Operator | Description                                      | Example                                      | Result/Notes                                                      |
|----------|--------------------------------------------------|----------------------------------------------|-------------------------------------------------------------------|
| `>`      | Redirects `stdout` to a file (overwrites).       | `dir > files.txt`                            | Saves output of `dir` to `files.txt`, replacing its contents.     |
| `>>`     | Redirects `stdout` to a file (appends).          | `echo Hello >> log.txt`                      | Adds "Hello" to the end of `log.txt`.                            |
| `<`      | Redirects `stdin` from a file.                   | `sort < names.txt`                           | Sorts the contents of `names.txt`.                               |
| `2>`     | Redirects `stderr` to a file.                    | `command 2> errors.txt`                      | Saves error messages to `errors.txt`.                            |
| `2>>`    | Appends `stderr` to a file.                      | `command 2>> errors.txt`                     | Appends error messages to `errors.txt`.                          |
| `1>`     | Explicitly redirects `stdout` (same as `>`).     | `command 1> output.txt`                      | Saves standard output to `output.txt`.                           |
| `&>`     | Redirects both `stdout` and `stderr` (Win 10+).  | `command &> all_output.txt`                  | Saves all output and errors to `all_output.txt`.                 |
| `\|`      | Pipes `stdout` to another command as `stdin`.    | `dir \| find "txt"`                           | Passes output of `dir` to `find`.                                |

**Usage Tips:**
- Combine redirections for advanced scenarios:
  ```bat
  myapp.exe > out.txt 2> err.txt
  ```
  Separates normal output and errors.
- Merge `stderr` into `stdout`:
  ```bat
  myapp.exe > all.txt 2>&1
  ```
  Both outputs go to `all.txt`.
- Use pipes to chain commands for filtering or processing.

**Limitations:**
- Redirection applies only to the current command or script line.
- Some legacy commands may not support all redirection features.
- `&>` is available only in newer Windows versions (Windows 10+).

**Common Use Cases:**
- Logging output and errors for troubleshooting.
- Automating input to commands using files.
- Filtering and processing command output with pipes.

For more details, see the Microsoft Docs on [Redirecting command input and output (cmd.exe)](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/redirection).

#### **Environment Variables**

Environment variables in `cmd.exe` are dynamic values that store information about the system environment, user settings, and configuration paths. They are referenced using the `%VARNAME%` syntax and are essential for scripting, automation, and customizing the shell environment.

**Key Features:**
- **Scope:** Variables can be system-wide, user-specific, or session-specific.
- **Usage:** Used to store paths, configuration values, and user information.
- **Modification:** Can be set, changed, or deleted within a session or script.

**Common Built-in Variables:**
| Variable           | Description                                 | Example Value                |
|--------------------|---------------------------------------------|------------------------------|
| `%USERNAME%`       | Current logged-in user                      | `tester`                       |
| `%USERPROFILE%`    | Path to the user's home directory           | `C:\Users\tester`              |
| `%COMPUTERNAME%`   | Name of the computer                        | `DESKTOP-1234`               |
| `%TEMP%`, `%TMP%`  | Temporary files directory                   | `C:\Users\tester\AppData\Local\Temp` |
| `%PATH%`           | Directories searched for executables        | `C:\Windows\System32;...`    |
| `%SystemRoot%`     | Windows installation directory              | `C:\Windows`                 |
| `%APPDATA%`        | Roaming application data folder             | `C:\Users\tester\AppData\Roaming` |

**Working with Variables:**
| Command / Syntax                | Description                                      | Example / Output                                  |
|---------------------------------|--------------------------------------------------|---------------------------------------------------|
| `echo %VARNAME%`                | Display the value of a variable                  | `echo %USERNAME%` → `tester`                        |
| `set VARNAME=value`             | Set or change a variable for the session         | `set MYVAR=hello`                                 |
| `set`                           | List all environment variables                   | `set`                                             |
| `setlocal` / `endlocal`         | Limit variable scope to a batch script section   | Variables set within `setlocal` are discarded after `endlocal` |
| `set /p VARNAME=Prompt:`        | Prompt user for input and store in variable      | `set /p NAME=Enter your name: `                   |
| `set VARNAME=`                  | Delete a variable from the environment           | `set MYVAR=`                                      |

**Variable Expansion in Scripts:**
- Use `%VARNAME%` for normal expansion.
- Use `!VARNAME!` for delayed expansion (requires `setlocal enabledelayedexpansion`).

**Examples:**
```bat
:: Display the current user and computer name
echo User: %USERNAME%
echo Computer: %COMPUTERNAME%

:: Set and use a custom variable
set GREETING=Hello
echo %GREETING%, %USERNAME%!

:: Prompt for input
set /p COLOR=Enter your favorite color: 
echo You chose %COLOR%
```

**Limitations:**
- Variable changes with `set` are local to the current session or script.
- For permanent changes, use the System Properties GUI or `setx` command (note: `setx` changes are not available in the current session).

**Advanced:**
- Use variables in loops and conditional statements for dynamic scripting.
- Combine with redirection and piping for powerful automation.

{% hint style="warning" %}
**Batch Scripting Variables**: When writing batch scripts (`.bat` or `.cmd` files), **use double percent signs (`%%`) for variables inside `for` loops**. For example, use `%%f` instead of `%f`.

- In the command prompt (interactive), use a single `%` (e.g., `for %f in (*) do echo %f`).
- In batch files, use double `%%` (e.g., `for %%f in (*) do echo %%f`).

If you forget the extra `%`, your script may not work as expected!
{% endhint %}

For more details, see the Microsoft Docs on the [set command](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/set).

#### **Background Task Execution**

Background task execution in `cmd.exe` allows you to launch programs or scripts without blocking the current shell session. This is useful for running multiple processes simultaneously or starting long-running tasks while continuing to use the command prompt.

**Key Syntax and Options:**

| Command / Syntax                | Description                                                      | Example / Output                                      |
|---------------------------------|------------------------------------------------------------------|-------------------------------------------------------|
| `start <program>`               | Launches a program or command in a new window.                   | `start notepad.exe` - Opens Notepad in a new window.  |
| `start /b <command>`            | Runs the command in the background (no new window).              | `start /b ping 127.0.0.1 -t` - Pings in background.   |
| `start "" <command>`            | Use empty quotes to avoid issues with commands containing spaces. | `start "" "C:\My Folder\app.exe"`                     |
| `start /min <command>`          | Starts the window minimized.                                     | `start /min calc.exe`                                 |
| `start /max <command>`          | Starts the window maximized.                                     | `start /max cmd.exe`                                  |
| `start /wait <command>`         | Waits for the started process to finish before continuing.        | `start /wait notepad.exe`                             |

**Usage Tips:**
- `start` is especially useful in batch scripts to parallelize tasks or prevent blocking.
- Use `/b` to keep output in the same window (no new console).
- Always quote the title argument (even if empty) when the command or path contains spaces.
- Combine with redirection or piping for advanced workflows.

**Limitations:**
- `start /b` does not create a new window, but output may still appear in the current console.
- Background processes started with `start` are not true Unix-style background jobs; they are separate processes.
- Use `tasklist` and `taskkill` to monitor or terminate background processes if needed.

**Examples:**
```bat
:: Start Notepad in a new window
start notepad.exe

:: Run a script in the background (no new window)
start /b myscript.bat

:: Start multiple background pings
start /b ping 8.8.8.8
start /b ping 1.1.1.1

:: Start a program with a custom window title
start "My Custom Title" calc.exe

:: Wait for a process to finish before continuing
start /wait notepad.exe
echo Notepad closed, continuing script...
```

#### **String Manipulation**

String manipulation in `cmd.exe` allows you to perform operations such as variable assignment, substring extraction, replacement, concatenation, and numeric calculations. These features are essential for scripting, automation, and dynamic command construction.

**Key Features and Syntax:**

| Feature / Syntax                       | Description                                                      | Example / Output                                         |
|----------------------------------------|------------------------------------------------------------------|----------------------------------------------------------|
| `set VAR=value`                        | Assigns a string value to a variable.                            | `set NAME=Alice`<br>`echo %NAME%` → `Alice`              |
| `set /a VAR=expression`                | Performs arithmetic operations and assigns the result.           | `set /a sum=5+10`<br>`echo %sum%` → `15`                 |
| `set /p VAR=Prompt:`                   | Prompts user for input and stores it in a variable.              | `set /p COLOR=Enter color: `<br>`echo %COLOR%`           |
| `%VAR:old=new%`                        | Replaces all occurrences of `old` with `new` in a variable.      | `set STR=abc123abc`<br>`echo %STR:abc=XYZ%` → `XYZ123XYZ`|
| `%VAR:~start,length%`                  | Extracts a substring from a variable.                            | `set STR=abcdef`<br>`echo %STR:~2,3%` → `cde`            |
| `%VAR:~start%`                         | Extracts substring from position `start` to end.                 | `set STR=abcdef`<br>`echo %STR:~3%` → `def`              |
| `%VAR:~0,-N%`                          | Removes last `N` characters from a variable.                     | `set STR=abcdef`<br>`echo %STR:~0,-2%` → `abcd`          |
| `%VAR: =_%`                            | Replaces spaces with underscores.                                | `set STR=hello world`<br>`echo %STR: =_%` → `hello_world`|
| Concatenation                          | Combine variables and strings directly.                          | `set A=foo`<br>`set B=bar`<br>`echo %A%%B%` → `foobar`   |

**Usage Tips:**
- Use `setlocal enabledelayedexpansion` and `!VAR!` syntax for advanced scenarios, such as inside loops, to update and access variables dynamically.
- String replacement and substring extraction are case-sensitive.
- For splitting strings, use `for` loops with delimiters:
  ```bat
  set STR=apple,banana,cherry
  for %%A in (%STR:,= %) do echo %%A
  ```
  This outputs each fruit on a separate line.

**Limitations:**
- No built-in support for regular expressions (use `findstr` for pattern matching).
- String operations are limited compared to PowerShell or Unix shells.

**Examples:**
```bat
:: Arithmetic calculation
set /a total=7*8
echo %total%  :: Outputs 56

:: Substring extraction
set VAR=WindowsFundamentals
echo %VAR:~7,4%  :: Outputs "Fund"

:: Replace substring
set FILE=report 2024.txt
echo %FILE: =_%  :: Outputs "report_2024.txt"

:: Prompt for input and manipulate
set /p NAME=Enter your name: 
echo Hello, %NAME:~0,1%.  :: Outputs first letter of name
```

For more details, see the Microsoft Docs on [set](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/set) and [batch string manipulation](https://ss64.com/nt/syntax-substring.html).

### **Types of Commands in `cmd.exe`**

There are two primary types of commands that can be executed in `cmd.exe`:

- **Built-in Commands**:  
   - These commands are **directly processed** within the `cmd.exe` shell, meaning they do **not** rely on external programs to execute.
   - Built-ins provide essential functionality such as **file manipulation, directory navigation, and environment management**.
   - **Examples:** `cd` (change directory), `dir` (list files), `echo` (display text), `set` (manage environment variables), and `exit` (close command prompt).

- **External Executables**:  
   - These commands **call separate `.exe` files**, typically stored in **system directories** like `C:\Windows\System32\`.
   - External commands extend the shell’s capabilities by invoking system utilities and tools.
   - **Examples:** `ping.exe` (network testing), `ipconfig.exe` (network configuration), `tasklist.exe` (list running processes), and `robocopy.exe` (advanced file copy operations).

For example:
- `cd`, `dir`, `echo`, `set`, `exit` **are all built-ins** handled directly by `cmd.exe`.
- **Commands like** `ping`, `ipconfig`, `tasklist`, and `robocopy` are external, i.e. they invoke separate `.exe` files located in system directories (e.g. `C:\Windows\System32\`).

### **Windows CMD built-in commands**

Windows **cmd.exe built-in commands** provide essential functionality for managing files, processes, networking, and system settings directly from the command line. **Built-in commands** are **internal functions** of `cmd.exe`, meaning they run within the shell itself rather than calling external binaries.

| Command | Description | Example Use Case |
|---------|------------|------------------|
| **cd** | Changes the current directory. | `cd C:\Users\tester\Documents` – Navigate to the Documents folder for user `tester`. |
| **dir** | Lists files and directories in the current folder. | `dir /s /b` – List all files in the current directory and subdirectories. |
| **echo** | Displays text or variables in the command prompt. | `echo Hello, World!` – Print "Hello, World!" to the screen. |
| **set** | Sets or displays environment variables. | `set PATH` – Show the current PATH variable. |
| **exit** | Closes the command prompt. | `exit` – Close the terminal session. |
| **cls** | Clears the command prompt screen. | `cls` – Wipe the screen clean. |
| **ver** | Displays the Windows version. | `ver` – Show the OS version number. |
| **help** | Displays help information for CMD commands. | `help dir` – Show details on how to use the `dir` command. |
| **copy** | Copies files from one location to another. | `copy file.txt D:\Backup\` – Copy `file.txt` to the `Backup` folder. |
| **move** | Moves files from one location to another. | `move file.txt D:\Backup\` – Move `file.txt` to the `Backup` folder. |
| **del** | Deletes files. | `del /F /Q file.txt` – Force delete `file.txt` without confirmation. |
| **ren** | Renames a file or folder. | `ren oldname.txt newname.txt` – Rename `oldname.txt` to `newname.txt`. |
| **mkdir** | Creates a new directory. | `mkdir C:\NewFolder` – Create a folder named `NewFolder`. |
| **rmdir** | Deletes a directory. | `rmdir /s /q C:\OldFolder` – Remove `OldFolder` and its contents. |
| **attrib** | Changes file attributes (hidden, read-only, etc.). | `attrib +H file.txt` – Hide `file.txt`. |
| **title** | Changes the title of the command prompt window. | `title Custom CMD Window` – Set the window title to "Custom CMD Window". |
| **prompt** | Changes the command prompt display style. | `prompt $P$G` – Set prompt to display the current path followed by `>`. |

### Getting Help With Commands

Unlike Unix-based systems, Windows `cmd.exe` does not have traditional **`man` pages** for commands. Instead, Windows provides several methods to get help with command-line tools.

1. **Using the `help` command**  
   - Simply type `help` in the Command Prompt to see a **list of built-in commands**.  
   - To get help on a specific command:  
     ```bat
     help dir
     ```
     This will display basic information about the `dir` command.

2. **Using `command /?` for detailed help**  
   - Many commands support the `/?` flag, which provides more detailed usage instructions and available options.  
     ```bat
     dir /?
     ```
     This will list **all available parameters** for the `dir` command.
   - Some commands will even support this with `-?` in addition.  Windows commands do not all follow POSIX standardization.

3. **Checking Microsoft Docs (Online Documentation)**  
   - Microsoft provides extensive official documentation on Windows commands via **Microsoft Learn**.  
   - For example, the `dir` command documentation can be found at:  
     [https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/dir](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/dir)
