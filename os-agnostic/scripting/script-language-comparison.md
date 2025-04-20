# Script Language Syntax

TODO: need syntax examples for Bash and Windows Batch scripting (issue [#22](https://github.com/zweilosec/Infosec-Notes/issues/22))

* Add syntax examples for Bash and Windows Batch scripting
* Add example output for all

Basic syntax examples for Python, PowerShell, Bash, and Windows cmd.exe batch scripting languages.

## Variables

Variables in scripting languages are used to **store and manipulate data** dynamically. They act as placeholders for values such as numbers, text, arrays, or objects. They simplify data handling and improve code readability, making scripting more efficient for automation and processing tasks.

#### **Key Features of Variables**

- **Assignment:** Variables are assigned values that can be updated or referenced.
- **Data Storage:** They hold different types of data, including strings, numbers, and lists.
- **Scope:** Variables can have a **global** (accessible throughout the script) or **local** (restricted to a specific function or block) scope.
- **Type Handling:** Some scripting languages require explicit type declaration, while others dynamically assign types based on the assigned value.

#### **Common Uses**

* Storing user input  
* Performing calculations  
* Managing lists and structured data  
* Controlling flow with conditional logic  

{% tabs %}
{% tab title="Python" %}

### Basic Variable Operations

| Activity      | Code Examples |
|--------------|--------------|
| Declare Variable | `x = 10` (Integer) <br> `name = "Alice"` (String) |
| Assign Multiple Variables | `a, b, c = 1, 2, 3` |
| Check Variable Type | `type(x)` |
| String Formatting | `f"Hello, {name}!"` |
| List Variables | `my_list = [1, 2, 3]` |
| Dictionary Variables | `my_dict = {"key": "value"}` |
| Boolean Variables | `is_active = True` |
| Constants (Convention) | `PI = 3.14159` (Uppercase naming for constants) |

Python variables are dynamic, meaning their type can change based on assignment. You can find more details on Python variables [here](https://pythonguides.com/python-variables/) and [here](https://www.w3schools.com/python/python_variables.asp). 

### Python variable scope

Python follows the **LEGB rule** (Local, Enclosing, Global, Built-in) to determine variable scope. 

| Scope Type      | Description | Code Example |
|---------------|-------------|--------------|
| **Local Scope** | Variables declared inside a function, accessible only within that function. | ```python def my_function(): x = 10  # Local variable print(x) my_function() print(x)  # Error: x is not defined outside the function ``` |
| **Global Scope** | Variables declared outside any function, accessible throughout the script. | ```python x = 10  # Global variable def my_function(): print(x)  # Accessible inside function my_function() print(x)  # Accessible outside function too ``` |
| **Enclosing Scope** | Variables in an outer function, accessible by inner functions (nested functions). | ```python def outer_function(): x = 10  # Enclosing variable def inner_function(): print(x)  # Accessible from outer function inner_function() outer_function() ``` |
| **Built-in Scope** | Variables and functions built into Python, available everywhere. | ```python print(len([1, 2, 3]))  # 'len' is a built-in function ``` |
| **Using `global` Keyword** | Allows modification of a global variable inside a function. | ```python x = 10 def my_function(): global x x = 20  # Modifies global variable my_function() print(x)  # Output: 20 ``` |
| **Using `nonlocal` Keyword** | Allows modification of an enclosing variable inside a nested function. | ```python def outer_function(): x = 10 def inner_function(): nonlocal x x = 20  # Modifies enclosing variable inner_function() print(x)  # Output: 20 outer_function() ``` |

You can find more details on Python variable scopes [here](https://www.w3schools.com/PYTHON/python_scope.asp) and [here](https://pythongeeks.org/python-variable-scope/).


{% endtab %}

{% tab title="PowerShell" %}

### **Basic Variable Operations**

| Activity      | Code Examples |
|--------------|--------------|
| Declare Variable | `$x = 10` (Integer) <br> `$name = "Alice"` (String) |
| Assign Multiple Variables | `$a, $b, $c = 1, 2, 3` |
| Change Variable Type | `$x = "Hello"` (Changes `x` from int to str) |
| Check Variable Type | `$x.GetType()` |
| String Formatting | `"Hello, $name!"` |
| List Variables | `Get-Variable` |
| Dictionary Variables | `$myDict = @{"key" = "value"}` |
| Boolean Variables | `$isActive = $true` |
| Constants (Convention) | `$PI = 3.14159` (Uppercase naming for constants) |

### **Variable Scopes in PowerShell**

PowerShell follows a **hierarchical scope system**, allowing fine control over variable accessibility. 

| Scope Type      | Description | Code Example |
|---------------|-------------|--------------|
| **Local Scope** | Variables declared inside a function, accessible only within that function. | ```powershell function MyFunction { $x = 10  # Local variable Write-Output $x } MyFunction Write-Output $x  # Error: x is not defined outside the function ``` |
| **Global Scope** | Variables declared outside any function, accessible throughout the script. | ```powershell $x = 10  # Global variable function MyFunction { Write-Output $x } MyFunction Write-Output $x  # Accessible outside function too ``` |
| **Script Scope** | Variables accessible only within a script file. | ```powershell $script:x = 10 function MyFunction { Write-Output $script:x } MyFunction ``` |
| **Using `global` Keyword** | Allows modification of a global variable inside a function. | ```powershell $global:x = 10 function MyFunction { $global:x = 20 } MyFunction Write-Output $global:x  # Output: 20 ``` |
| **Using `private` Keyword** | Restricts variable access to the current scope only. | ```powershell private $x = 10 Write-Output $x  # Works here, but not outside ``` |

You can find more details on PowerShell variable scopes [here](https://lazyadmin.nl/powershell/powershell-variables/) and [here](https://powershellfaqs.com/powershell-local-variables/). 

### **Automatic Variables**

**Automatic variables** are predefined by PowerShell and store state information about the session. They are created and maintained by PowerShell itself. Some key examples include:

| Variable | Description | Example |
|----------|-------------|---------|
| `$?` | Stores the success (`True`) or failure (`False`) of the last command. | `Write-Output "Hello"; $?` |
| `$Error` | Contains an array of error objects from the session. | `$Error[0]` (Gets the most recent error) |
| `$PID` | Stores the process ID of the current PowerShell session. | `Write-Output $PID` |
| `$PSVersionTable` | Displays PowerShell version details. | `Write-Output $PSVersionTable` |
| `$HOME` | Stores the path to the user's home directory. | `Write-Output $HOME` |

You can find a full list of automatic variables [here](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.core/about/about_automatic_variables?view=powershell-7.5).

### **Preference Variables**

**Preference variables** control PowerShell’s behavior and allow customization of how commands execute. Some key examples include:

| Variable | Description | Default Value |
|----------|-------------|--------------|
| `$ErrorActionPreference` | Controls how PowerShell handles errors (`Continue`, `Stop`, `SilentlyContinue`, `Ignore`). | `Continue` |
| `$ConfirmPreference` | Determines when PowerShell prompts for confirmation. | `High` |
| `$VerbosePreference` | Controls verbosity of output (`SilentlyContinue`, `Continue`). | `SilentlyContinue` |
| `$ProgressPreference` | Controls whether progress bars are displayed. | `Continue` |
| `$PSModuleAutoLoadingPreference` | Determines whether PowerShell automatically loads modules. | `All` |

You can find more details on preference variables [here](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.core/about/about_preference_variables?view=powershell-7.5).

{% endtab %}

{% tab title="Bash" %}

Bash variables are **untyped**, meaning they can store any value without explicit type declaration. 

### **Basic Variable Operations**

| Activity      | Code Examples |
|--------------|--------------|
| Declare Variable | `x=10` (Integer) <br> `name="Alice"` (String) |
| Assign Multiple Variables | `a=1; b=2; c=3` |
| Change Variable Type | `x="Hello"` (Changes `x` from int to str) |
| Check Variable Type | `echo $((x+0))` (Checks if `x` is numeric) |
| String Formatting | `echo "Hello, $name!"` |
| List Variables | `declare -p` (Lists all declared variables) |
| Dictionary Variables | `declare -A myDict; myDict[key]="value"` |
| Boolean Variables | `isActive=true` (Bash treats non-empty values as `true`) |
| Constants (Convention) | `readonly PI=3.14159` (Prevents modification) |

### **Variable Scopes in Bash**

| Scope Type      | Description | Code Example |
|---------------|-------------|--------------|
| **Local Scope** | Variables declared inside a function, accessible only within that function. | ```bash function my_function { local x=10  # Local variable echo $x } my_function echo $x  # Error: x is not defined outside the function ``` |
| **Global Scope** | Variables declared outside any function, accessible throughout the script. | ```bash x=10  # Global variable function my_function { echo $x } my_function echo $x  # Accessible outside function too ``` |
| **Using `export` Keyword** | Allows a variable to be accessible by child processes. | ```bash export x=10 bash -c 'echo $x'  # Output: 10 ``` |

### **Special Variables in Bash**

| Variable | Description | Example |
|----------|-------------|---------|
| `$?` | Stores the exit status of the last command. | `echo $?` |
| `$0` | Stores the name of the script. | `echo $0` |
| `$1, $2, ...` | Stores positional arguments passed to the script. | `echo $1` (First argument) |
| `$#` | Stores the number of arguments passed to the script. | `echo $#` |
| `$@` | Expands to all arguments as separate words. | `echo $@` |
| `$*` | Expands to all arguments as a single word. | `echo $*` |

You can find more details on Bash variables [here](https://tecadmin.net/bash-scripting-examples/) and [here](https://ryanstutorials.net/bash-scripting-tutorial/bash-variables.php). 

### **Environment Variables in Bash**

Environment variables are **global variables** that affect the behavior of processes and scripts. They can be set, modified, and accessed within Bash.

| Activity      | Code Examples |
|--------------|--------------|
| Set Environment Variable | `export MY_VAR="Hello"` |
| Access Environment Variable | `echo $MY_VAR` |
| List All Environment Variables | `printenv` or `env` |
| Remove Environment Variable | `unset MY_VAR` |
| Persist Environment Variable | Add `export MY_VAR="Hello"` to `~/.bashrc` or `~/.profile` |
| Use in a Script | `#!/bin/bash` <br> `echo "The value is $MY_VAR"` |

### **Common Environment Variables**

| Variable | Description |
|----------|-------------|
| `$HOME` | User's home directory |
| `$PATH` | Directories where executables are searched |
| `$USER` | Current username |
| `$PWD` | Current working directory |
| `$SHELL` | Default shell |
| `$LANG` | Language settings |
| `$EDITOR` | Default text editor |

You can find more details on environment variables in Bash [here](https://stackoverflow.com/questions/1464253/global-environment-variables-in-a-shell-script) and [here](https://stackoverflow.com/questions/12351702/how-to-write-a-bash-script-to-set-global-environment-variable). 

{% endtab %}

{% tab title="CMD .bat" %}

Batch scripting has limited variable handling compared to PowerShell or Python, but it remains useful for automation tasks.

| Type                         | Code Examples               |
| ---------------------------- | --------------------------- |
| Standard Variable            | `set var=Hello`             |
| Global Variable              | `set var=Hello` (variables are global by default)  |
| Environment Variables        | `set USERNAME=bob` (These are treated the same as normal variables in batch scripting) |
| Retrieving Variable Contents | `echo %var%`                |
| Boolean Variables | Batch does not have native boolean types, but you can use a normal variable as a hack (e.g. `set isActive=true` and check with `if "%isActive%"=="true" echo Active`) |

You can find more details on Batch scripting variables here and here.

### Set Command

Variables can be initialized via the `set` command.  The `set` command by itself will list all currently set variables.

#### Syntax

```bat
set variable-name=value
```

where,

* **variable-name** is the name of the variable you want to set.
* **value** is the value which needs to be set against the variable.

The following example shows a simple way the set command can be used.

#### Example

```bat
@echo off 
set message=Hello World 
echo %message%
```

### Working with Numeric Values

The `/A` switch specifies that the string to the right of the equal sign is a numerical expression that is evaluated.  The expression evaluator
is pretty simple and supports the following operations, in decreasing order of precedence:

    ()                  - grouping
    ! ~ -               - unary operators
    * / %               - arithmetic operators
    + -                 - arithmetic operators
    << >>               - logical shift
    &                   - bitwise and
    ^                   - bitwise exclusive or
    |                   - bitwise or
    = *= /= %= += -=    - assignment
      &= ^= |= <<= >>=
    ,                   - expression separator

Example:

```bat
@echo off 
SET /A a = 5 
SET /A b = 10 
SET /A c = %a% + %b% 
echo %c%
:: 15
```

### Local vs Global Variables

By default in Windows **Batch scripting**, variables are global to your entire command prompt session.  `SETLOCAL` and `ENDLOCAL` control variable scope, allowing temporary changes to variables within a script.

Use the `SETLOCAL` command to make variables local to the scope of your script. After calling `SETLOCAL`, any variable assignments are cleared upon calling `ENDLOCAL`, calling `EXIT`, or when execution reaches the end of file (EOF) in your script. 

### **Understanding `SETLOCAL` and `ENDLOCAL` in Batch Scripting**

#### **How `SETLOCAL` Works**
- When `SETLOCAL` is used, any changes to variables **inside** that block remain **local** to the script.
- Once the script exits or reaches `ENDLOCAL`, the variables revert to their previous values.
- This helps prevent accidental modifications to global environment variables.

#### **How `ENDLOCAL` Works**
- `ENDLOCAL` **restores** the previous environment state, discarding any changes made after `SETLOCAL`.
- If `ENDLOCAL` is omitted, the local scope still ends when the script exits.

**Key Takeaways**
- `SETLOCAL` creates **temporary** changes that are **discarded** after `ENDLOCAL`.
- Variables declared inside **SETLOCAL** are **not accessible** outside of it.
- Modifications to **global variables inside `SETLOCAL`** are reverted after `ENDLOCAL`.
- This is useful for **avoiding unintended changes** to system environment variables.

#### Example

```
@echo off
REM Define a global variable (note: no spaces around '=')
set globalvar=5

REM Start a local scope
SETLOCAL

REM Define a local variable
set var=13145
set /A var+=5

REM Display local variable
echo Local variable: %var%

REM Display global variable (accessible inside local scope)
echo Global variable: %globalvar%

REM End local scope
ENDLOCAL

REM Calling 'var' outside this scope will result in an error
echo Trying to access local variable: %var%  (This will be empty)
echo Global variable still accessible: %globalvar%
```

### **Using `SETLOCAL ENABLEDELAYEDEXPANSION` in Batch Scripts**

In **Windows Batch scripting**, variable expansion behaves differently in loops. Normally, variables are expanded **before** the loop starts, meaning their values may not update within the loop dynamically. To solve this issue, **delayed expansion** using `SETLOCAL ENABLEDELAYEDEXPANSION` allows real-time updates.

#### **Why is Delayed Expansion Needed?**
Without delayed expansion, a variable inside a loop **does not update** until after the loop completes. Using **`!variable!` instead of `%variable%`** allows the script to expand the variable dynamically.

---

### **Example Without Delayed Expansion (Incorrect Behavior)**

```bat
@echo off
set count=0
for /L %%i in (1,1,5) do (
    set count=%%i
    echo Value inside loop: %count%
)
```
#### **Output:**

```
Value inside loop:
Value inside loop:
Value inside loop:
Value inside loop:
Value inside loop:
```
#### **Why This Fails?**

- `%count%` gets expanded **before the loop starts**, meaning it remains **empty** throughout execution.

---

### **Example With `SETLOCAL ENABLEDELAYEDEXPANSION` (Correct Behavior)**

```bat
@echo off
SETLOCAL ENABLEDELAYEDEXPANSION
set count=0
for /L %%i in (1,1,5) do (
    set count=%%i
    echo Value inside loop: !count!
)
ENDLOCAL
```

#### **Expected Output:**

```
Value inside loop: 1
Value inside loop: 2
Value inside loop: 3
Value inside loop: 4
Value inside loop: 5
```
#### **Why This Works?**
- `!count!` is expanded **during** each loop iteration, reflecting the correct values.

---

### **Key Takeaways**

* **Use `SETLOCAL ENABLEDELAYEDEXPANSION`** before loops where variables need real-time updates.  
* **Use `!variable!` instead of `%variable%`** when accessing updated values in loops or conditional blocks.  
* **Avoid delayed expansion for static variables** (values that don't change inside loops).  

This technique is essential for scripts involving **counters**, **user input**, or **dynamic updates**. 

### Working with Environment Variables

If you have variables that you want to use across batch files, then it is always preferable to use environment variables. Once an environment variable is defined, it can be accessed via the % sign like any other variable. 

### Dynamic Environment Variables

If Command Extensions are enabled, then there are several dynamic environment variables that can be expanded but which don't show up in the list of variables displayed by SET.  These variable values are computed dynamically each time the value of the variable is expanded. If the user explicitly defines a variable with one of these names, then that definition will override the dynamic one described below:

| Environment Variable | Description |
|---------------------|--------------|
| `%CD%` | Expands to the current directory string. |
| `%DATE%` | Expands to the current date using the same format as the `DATE` command. |
| `%TIME%` | Expands to the current time using the same format as the `TIME` command. |
| `%RANDOM%` | Expands to a random decimal number between `0` and `32767`. |
| `%ERRORLEVEL%` | Expands to the current `ERRORLEVEL` value. |
| `%CMDEXTVERSION%` | Expands to the current Command Processor Extensions version number. |
| `%CMDCMDLINE%` | Expands to the original command line that invoked the Command Processor. |
| `%HIGHESTNUMANODENUMBER%` | Expands to the highest NUMA node number on this machine. |

### **`SET` vs. `SETX`**

When working with environment variables in **Windows Batch scripting**, two commonly used commands are `SET` and `SETX`. While they may seem similar, they serve **different purposes** and have distinct behaviors.

#### **`SET` – Temporary Variable Assignment**
The `SET` command is used to define **temporary** environment variables that exist **only within the current command prompt session**.

##### **Example: Using `SET`**

```bat
@echo off
set MY_VAR=Hello
echo %MY_VAR%
```

**Output:**

```
Hello
```

* **Changes take effect immediately.**  
* **Only available in the current session.**  
* **Lost when the command prompt is closed.**  

---

#### **`SETX` – Permanent Variable Assignment**

The `SETX` command **persists** environment variables across sessions by storing them in the Windows **registry**.

##### **Example: Using `SETX`**

```bat
setx MY_VAR "Hello"
```

* **Changes persist across command prompt sessions.**  
* **Requires reopening the command prompt to take effect.**  
* **Modifies user or system environment variables.**  

---

#### **Key Differences Between `SET` and `SETX`**

| Feature | `SET` | `SETX` |
|---------|------|------|
| **Scope** | Current session only | Permanent (stored in registry) |
| **Availability** | Lost when CMD closes | Available in new CMD sessions |
| **Immediate Effect** | Yes | No (requires restart of CMD) |
| **Modifies Registry** | No | Yes |
| **System-Level Changes** | No | Yes (with `/m` flag for system-wide variables) |

---

#### **When to Use Each Command**
- **Use `SET`** for **temporary** variables needed only within a script or session.
- **Use `SETX`** when defining **persistent** environment variables that should remain available across system reboots.

For more details, check out [this discussion](https://superuser.com/questions/916649/what-is-the-difference-between-setx-and-set-in-environment-variables-in-windows) on `SET` vs `SETX`.

{% endtab %}
{% endtabs %}

## Strings

{% tabs %}
{% tab title="Python" %}

| Method                            | Code Examples |
|-----------------------------------|--------------|
| **Normal String**                 | `"Hello World"` or `'Hello World'` |
| **Empty String**                  | `""` or `''` |
| **Multiline String**              | `"""Hello\nWorld"""` or `'''Hello\nWorld'''` |
| **Select Character from String**  | `str = "Hello"`<br>`print(str[1])`<br>**Output:** `'e'` |
| **Get Length**                     | `str = "Hello"`<br>`print(len(str))`<br>**Output:** `5` |
| **Remove Whitespace**              | `str = "  Hello World  "`<br>`print(str.strip())`<br>**Output:** `'Hello World'` |
| **To Lowercase**                   | `str = "HELLO WORLD"`<br>`print(str.lower())`<br>**Output:** `'hello world'` |
| **To Uppercase**                   | `str = "hello world"`<br>`print(str.upper())`<br>**Output:** `'HELLO WORLD'` |
| **Replace Characters**             | `str = "Hello"`<br>`print(str.replace("H", "Y"))`<br>**Output:** `'Yello'` |
| **Split String**                   | `str = "Hello, World"`<br>`print(str.split(","))`<br>**Output:** `['Hello', ' World']` |
| **Join List into String**          | `words = ["Hello", "World"]`<br>`print(" ".join(words))`<br>**Output:** `'Hello World'` |
| **String Formatting (`.format()`)** | `price = 42`<br>`txt = "The price is {} dollars".format(price)`<br>`print(txt)`<br>**Output:** `'The price is 42 dollars'` |
| **String Formatting with Index**   | `price = 42`<br>`txt = "The price is {0} dollars".format(price)`<br>`print(txt)`<br>**Output:** `'The price is 42 dollars'` |
| **f-Strings (Modern Formatting)**  | `price = 42`<br>`txt = f"The price is {price} dollars"`<br>`print(txt)`<br>**Output:** `'The price is 42 dollars'` |
| **Check If Substring Exists**      | `str = "Hello World"`<br>`print("Hello" in str)`<br>**Output:** `True` |
| **Reverse String**                 | `str = "Hello"`<br>`print(str[::-1])`<br>**Output:** `'olleH'` |
| **Repeat String**                  | `print("Hello " * 3)`<br>**Output:** `'Hello Hello Hello '` |

### **Advanced String Manipulation in Python**

Python provides powerful tools for **string manipulation**, including **regular expressions**, **string slicing**, and other advanced techniques for text processing.

---

### **Regular Expressions (`re` module)**

Regular expressions (**regex**) allow pattern-based searching and manipulation of strings.

#### **Example: Extracting Email Addresses**

```python
import re

text = "Contact us at support@example.com or sales@example.com"
emails = re.findall(r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}", text)

print(emails)  # Output: ['support@example.com', 'sales@example.com']
```

* **Uses regex to find all email addresses in a string.**  
* **Flexible for extracting structured data from text.**  

---

### **String Slicing**

String slicing allows extracting specific parts of a string using index ranges.

#### **Example: Extracting Substrings**

```python
text = "Python Programming"
print(text[0:6])   # Output: 'Python'
print(text[-11:])  # Output: 'Programming'
print(text[::-1])  # Output: 'gnimmargorP nohtyP' (Reversed)
```

* **Supports positive and negative indexing.**  
* **Allows reversing strings easily.**  

---

### **Advanced String Manipulation Techniques**

Python offers additional methods for **efficient text processing**.

#### **Example: Removing Unwanted Characters**

```python
text = "  Hello, World!  "
cleaned_text = text.strip()  # Removes leading/trailing spaces
print(cleaned_text)  # Output: 'Hello, World!'
```

#### **Example: Replacing Words Using `re.sub()`**

```python
import re

text = "The price is $100."
updated_text = re.sub(r"\$\d+", "affordable", text)
print(updated_text)  # Output: 'The price is affordable.'
```

* **Uses regex for complex replacements.**  
* **Great for cleaning up messy text.**  

---

### **Combining Multiple String Operations**

#### **Example: Extracting and Formatting Data**

```python
import re

text = "User: John Doe, Age: 30, Email: john@example.com"
match = re.search(r"User: (\w+ \w+), Age: (\d+), Email: (\S+)", text)

if match:
    name, age, email = match.groups()
    print(f"Name: {name}, Age: {age}, Email: {email}")
```
* **Extracts structured data using regex.**  
* **Formats extracted values using `f-strings`.**  

---

### **Want More?**

You can explore more **advanced string manipulation techniques** [here](https://tutedude.com/blogs/python-string-manipulation/) and [here](https://boyu374.com/advanced-string-manipulation-in-python-techniques-for-text-processing/).

{% endtab %}

{% tab title="PowerShell" %}

PowerShell provides **robust string manipulation capabilities**, making it easy to process and format text efficiently. 
---

### **Basic String Operations**
| Activity      | Code Examples |
|--------------|--------------|
| Declare String | `$str = "Hello World"` |
| Empty String | `$empty = ""` |
| Multiline String | `$multiline = @"`<br>`Hello`<br>`World`<br>`"@` |
| Select Character | `$str[1]` **Output:** `'e'` |
| Get Length | `$str.Length` **Output:** `11` |
| Remove Whitespace | `$str.Trim()` **Output:** `'Hello World'` |
| Convert to Lowercase | `$str.ToLower()` **Output:** `'hello world'` |
| Convert to Uppercase | `$str.ToUpper()` **Output:** `'HELLO WORLD'` |
| Replace Characters | `$str.Replace("Hello", "Hi")` **Output:** `'Hi World'` |
| Split String | `$str -split " "` **Output:** `@("Hello", "World")` |
| Join Strings | `-join @("Hello", "World")` **Output:** `'HelloWorld'` |
| Formatting | `"The price is {0} dollars" -f 42` **Output:** `'The price is 42 dollars'` |
| f-String Equivalent | `"$($str) is great"` **Output:** `'Hello World is great'` |

---

### **Advanced String Manipulation**
| Activity | Code Examples |
|--------------|--------------|
| Check If Substring Exists | `$str -match "Hello"` **Output:** `$true` |
| Reverse String | `-join ($str.ToCharArray() | Reverse)` **Output:** `'dlroW olleH'` |
| Repeat String | `"$str " * 3` **Output:** `'Hello World Hello World Hello World '` |
| Extract Substring | `$str.Substring(0, 5)` **Output:** `'Hello'` |
| Find Index of Character | `$str.IndexOf("W")` **Output:** `6` |
| Remove Specific Characters | `$str -replace "o", ""` **Output:** `'Hell Wrld'` |

---

### **Regular Expressions (`-match`, `-replace`)**
| Activity | Code Examples |
|--------------|--------------|
| Find Pattern | `$str -match "Hello"` **Output:** `$true` |
| Extract Email | `$text -match "(\w+@\w+\.\w+)"` **Output:** `$matches[0]` |
| Replace Using Regex | `$str -replace "Hello", "Hi"` **Output:** `'Hi World'` |

You can find more details on PowerShell string operations [here](https://devblogs.microsoft.com/powershell/parsing-text-with-powershell-1-3/) and [here](https://4sysops.com/archives/strings-in-powershell-replace-compare-concatenate-split-substring/).

### **PowerShell String Parsing, Special Characters, and JSON/XML Handling**

PowerShell provides robust tools for **string parsing**, **handling special characters**, and **working with JSON/XML data**. 

---

### **String Parsing in PowerShell**

String parsing allows extracting and manipulating text efficiently.

#### **Example: Extracting Substrings**

```powershell
$text = "PowerShell is powerful"
$substring = $text.Substring(0, 10)
Write-Output $substring  # Output: 'PowerShell'
```

* **Extracts a portion of a string using `.Substring()`**  
* **Useful for processing structured text**  

#### **Example: Splitting a String**

```powershell
$text = "apple,banana,grape"
$words = $text -split ","
Write-Output $words  # Output: 'apple', 'banana', 'grape'
```

* **Splits a string into an array using `-split`**  
* **Great for handling CSV-style data**  

---

### **Handling Special Characters**

PowerShell requires escaping certain characters when working with strings.

#### **Example: Escaping Special Characters**

```powershell
$text = "This is a `"$quoted text`""
Write-Output $text  # Output: 'This is a "quoted text"'
```

* **Uses backticks (`) to escape double quotes**  
* **Prevents syntax errors when handling special characters**  

#### **Example: Removing Special Characters**

```powershell
$text = "Hello!@#World"
$cleaned = $text -replace "[^a-zA-Z0-9]", ""
Write-Output $cleaned  # Output: 'HelloWorld'
```

* **Uses regex (`-replace`) to remove non-alphanumeric characters**  
* **Useful for sanitizing user input**  

---

### **Working with JSON in PowerShell**

PowerShell can **convert objects to JSON** and **parse JSON data**.

#### **Example: Convert Object to JSON**

```powershell
$data = @{ Name="Alice"; Age=30 }
$json = $data | ConvertTo-Json
Write-Output $json
```

* **Converts a PowerShell object into a JSON string**  
* **Useful for API interactions**  

#### **Example: Parse JSON Data**

```powershell
$json = '{ "Name": "Alice", "Age": 30 }'
$data = $json | ConvertFrom-Json
Write-Output $data.Name  # Output: 'Alice'
```

* **Parses JSON into a PowerShell object**  
* **Allows easy data extraction**  

---

### **Working with XML in PowerShell**

PowerShell can **parse XML files** and **extract structured data**.

#### **Example: Load and Parse XML**

```powershell
[xml]$xmlData = Get-Content "data.xml"
Write-Output $xmlData.Root.ElementName
```

* **Loads XML content into a PowerShell object**  
* **Allows structured data access**  

#### **Example: Convert Object to XML**

```powershell
$data = @{ Name="Alice"; Age=30 }
$xml = $data | ConvertTo-Xml
Write-Output $xml
```

* **Converts a PowerShell object into XML format**  
* **Useful for configuration files**  

---

You can explore more **advanced PowerShell string manipulation techniques** [here](https://stackoverflow.com/questions/47779157/convertto-json-and-convertfrom-json-with-special-characters) and [here](https://stackoverflow.com/questions/19176024/how-to-escape-special-characters-in-building-a-json-string).

{% endtab %}

{% tab title="Bash" %}

| Method                              | Code Examples               |
| ----------------------------------- | --------------------------- |
| Normal String                       | `str="Hello World"`       |
| Empty String                        | `str=""`                  |
| Multiline String                    | `str="Hello\nWorld"`     |
| Select Character from String        | `echo ${str:1:1}`           |
| Get Length                          | `echo ${#str}`              |
| Remove whitespace at front and back | `echo "  Hello  " | xargs` |
| To Lowercase                        | `echo ${str,,}`             |
| To Uppercase                        | `echo ${str^^}`             |
| Replace                             | `echo ${str/Hello/Hi}`      |
| Split                               | `IFS=","; read -ra arr <<< "$str"` |
| Join                                | `IFS=","; echo "${arr[*]}"` |
| Formatting                          | `printf "Hello %s\n" "$name"` |
| Formatting by Index                 | `printf "Hello %s\n" "$name"` |
| Formatting Strings                  | `name="World"; echo "Hello $name"` |

### Bash String Basics

```
name="John"
echo ${name}
echo ${name/J/j}    #=> "john" (substitution)
echo ${name:0:2}    #=> "Jo" (slicing)
echo ${name::2}     #=> "Jo" (slicing)
echo ${name::-1}    #=> "Joh" (slicing)
echo ${name:(-1)}   #=> "n" (slicing from right)
echo ${name:(-2):1} #=> "h" (slicing from right)
echo ${food:-Cake}  #=> $food or "Cake"
```

```
length=2
echo ${name:0:length}  #=> "Jo"
```

### String quotes

Using double quotes around a string allows for variable and parameter expansion (as well as interpretation of other special bash characters such as `!`).  Use of single quotes around a string treats everything within as a literal string.

```bash
NAME="John"
echo "Hi $NAME"  #=> Hi John
echo 'Hi $NAME'  #=> Hi $NAME
```

### Bash Parameter Expansion

Bash **parameter expansion** allows efficient manipulation of variables without requiring external commands. It enables **default values**, **substring extraction**, **string modifications**, and **indirect expansion**.

- **Default values** ensure variables have fallback values when unset.
- **Substring extraction** allows slicing parts of a string.
- **String modification** enables prefix/suffix removal and replacements.
- **Indirect expansion** retrieves the value of a variable whose name is stored in another variable.

#### **Basic Parameter Expansion**

| Description | Code Examples |
|------------|--------------|
| Retrieve the value of a variable | `${VAR}` |
| Use default value if variable is unset or null | `${VAR:-default}` |
| Assign default value if variable is unset or null | `${VAR:=default}` |
| Return alternate value if variable is set | `${VAR:+alternate}` |
| Display error message if variable is unset or null | `${VAR:?error message}` |

```bash
STR="/path/to/foo.cpp"
echo ${STR%.cpp}    # /path/to/foo
echo ${STR%.cpp}.o  # /path/to/foo.o
echo ${STR%/*}      # /path/to

echo ${STR##*.}     # cpp (extension)
echo ${STR##*/}     # foo.cpp (basepath)

echo ${STR#*/}      # path/to/foo.cpp
echo ${STR##*/}     # foo.cpp

echo ${STR/foo/bar} # /path/to/bar.cpp
```

#### **Default Values in Parameter Expansion**

| Description | Code Examples |
| ----------------- |--------------------------------------------------------|
| Use `$FOO`, or fallback to `val` if unset (or null)         | `${FOO:-val}` |
| Assign `val` to `$FOO` if unset (or null)                 | `${FOO:=val}` |
| Return `val` if `$FOO` is set (and not null)             | `${FOO:+val}` |
| Display error message and exit if `$FOO` is unset (or null) | `${FOO:?message}` |

** Note**

These **parameter expansion** methods in Bash allow conditional substitution based on whether a variable is set or unset. The `:` ensures checks for both **unset and null** values. If omitted (e.g., `${FOO-val}`), the expansion applies only when `$FOO` is completely unset but **not when it is empty (`""`)**.

### **Substitution**

| Description        | Code Examples |
|-------------------|--------------|
| Remove suffix    | `${FOO%suffix}` |
| Remove prefix    | `${FOO#prefix}` |
| Remove long suffix  | `${FOO%%suffix}` |
| Remove long prefix  | `${FOO##prefix}` |
| Replace first match | `${FOO/from/to}` |
| Replace all occurrences | `${FOO//from/to}` |
| Replace suffix    | `${FOO/%from/to}` |
| Replace prefix    | `${FOO/#from/to}` |

### **Substrings**

| Description               | Code Examples |
|--------------------------|--------------|
| Substring _(position, length)_ | `${FOO:0:3}` |
| Substring from the right | `${FOO:(-3):3}` |

#### Accessing Substrings

```bash
STR="Hello world"
echo ${STR:6:5}   # "world"
echo ${STR: -5:5}  # "world"
```

#### **String Modification**

| Description | Code Examples |
|------------|--------------|
| Remove shortest matching prefix | `${VAR#prefix}` |
| Remove longest matching prefix | `${VAR##prefix}` |
| Remove shortest matching suffix | `${VAR%suffix}` |
| Remove longest matching suffix | `${VAR%%suffix}` |
| Replace first occurrence | `${VAR/from/to}` |
| Replace all occurrences | `${VAR//from/to}` |

#### Special Directory Substring Tricks

```bash
SRC="/path/to/foo.cpp"
BASE=${SRC##*/}   #=> "foo.cpp" (basepath)
DIR=${SRC%$BASE}  #=> "/path/to/" (dirpath)
```

#### **Length and Indirection**

| Description | Code Examples |
|------------|--------------|
| Get length of variable | `${#VAR}` |
| Indirect expansion (expand variable name stored in another variable) | `${!VAR}` |

### **Bash String Manipulation Tricks**

#### **Case Manipulation**

| Description | Code Example |
|------------|--------------|
| Lowercase first letter | `echo ${STR,}` → `"hELLO WORLD!"` |
| Lowercase entire string | `echo ${STR,,}` → `"hello world!"` |
| Uppercase first letter | `echo ${STR^}` → `"Hello world!"` |
| Uppercase entire string | `echo ${STR^^}` → `"HELLO WORLD!"` |

#### **String Replacement**

| Description | Code Example |
|------------|--------------|
| Replace first occurrence | `echo ${STR/HELLO/HI}` → `"HI WORLD!"` |
| Replace all occurrences | `echo ${STR//O/A}` → `"HELLA WARLD!"` |
| Remove prefix | `echo ${STR#HELLO }` → `"WORLD!"` |
| Remove suffix | `echo ${STR% WORLD!}` → `"HELLO"` |

#### **Additional Tricks**

- **Reverse String:** `echo $(rev <<< "$STR")` → `"!DLROW OLLEH"`
- **Repeat String:** `echo "$STR " * 3` → `"HELLO WORLD! HELLO WORLD! HELLO WORLD!"`
- **Remove Non-Alphanumeric Characters:** `echo ${STR//[^a-zA-Z0-9]/}` → `"HELLOWORLD"`

### **Advanced String Formatting Using `printf` in Bash**

The `printf` command in Bash provides **precise control** over formatted output, making it more powerful than `echo`. 

---

#### **Basic Formatting**

| Description | Code Example |
|------------|--------------|
| Print a simple string | `printf "Hello, World!\n"` |
| Print a formatted string with placeholders | `printf "Name: %s, Age: %d\n" "Alice" 30` |
| Print multiple values | `printf "%s %s\n" "Hello" "World"` |

---

#### **Format Specifiers**

| Description | Code Example |
|------------|--------------|
| Print a string | `printf "%s\n" "Hello"` |
| Print an integer | `printf "%d\n" 42` |
| Print a floating-point number | `printf "%.2f\n" 3.14159` |
| Print a character | `printf "%c\n" 65` **(Outputs 'A')** |
| Print a percentage symbol | `printf "Discount: %d%%\n" 50` |

---

#### **Alignment and Padding**

| Description | Code Example |
|------------|--------------|
| Left-align text (width 10) | `printf "%-10s\n" "Hello"` |
| Right-align text (width 10) | `printf "%10s\n" "Hello"` |
| Pad numbers with leading zeros | `printf "%05d\n" 42` **(Outputs '00042')** |
| Limit decimal places | `printf "%.2f\n" 3.14159` **(Outputs '3.14')** |

---

#### **Formatting Lists and Tables**

| Description | Code Example |
|------------|--------------|
| Print a table with aligned columns | `printf "%-10s %-10s\n" "Name" "Age"; printf "%-10s %-10d\n" "Alice" 30` |
| Print a list with numbered items | `printf "%d. %s\n" 1 "Apple"; printf "%d. %s\n" 2 "Banana"` |

---

#### **Using `printf` with Variables**

```bash
name="Alice"
age=30
printf "Name: %s, Age: %d\n" "$name" "$age"
```

* **Uses variables inside formatted output.**  
* **Ensures proper spacing and alignment.**  

---

#### **Formatting Output for Logs**

```bash
timestamp=$(date +"%Y-%m-%d %H:%M:%S")
printf "[%s] INFO: %s\n" "$timestamp" "Process started"
```

* **Use to add timestamps to logs dynamically.**  
* **Useful for debugging and monitoring scripts.**  

You can explore more **advanced `printf` formatting techniques** [here](https://linuxsimply.com/bash-scripting-tutorial/string/manipulation/format-string/) and [here](https://linuxhandbook.com/bash-printf/).

{% endtab %}

{% tab title="CMD .bat" %}

| Method                              | Code Examples               |
| ----------------------------------- | --------------------------- |
| Normal String                       | `set str=Hello World`       |
| Empty String                        | `set str=`                  |
| Multiline String                    | `set str=Hello^&echo World` |
| Select Character from String        | `echo %str:~1,1%`           |
| Get Length                          | `echo %str:~0,-1%`          |
| Remove whitespace at front and back | `for /f "tokens=*" %%A in ("%str%") do set str=%%A` |
| To Lowercase                        | `echo %str% | findstr /r "[A-Z]"` |
| To Uppercase                        | `echo %str% | findstr /r "[a-z]"` |
| Replace                             | `set str=%str:Hello=Hi%`    |
| Split                               | `for %%A in (%str%) do echo %%A` |
| Join                                | `set str=%str1% %str2%`     |
| Formatting                          | `set str=Hello %name%`      |
| Formatting by Index                 | `set str=Hello %name%`      |
| Formatting Strings                  | `set name=World & echo Hello %name%` |

#### Creating and displaying the contents of a string

```bat
@echo off 
:: This program just displays Hello World 
set message = Hello World 
echo %message%
```

#### Creating and checking for **empty strings**

An empty string can be created in DOS Scripting by assigning it no value during it's initialization as shown in the following example.

```bat
set a=
```

To check for an existence of an empty string, you need to encompass the variable name in square brackets and also compare it against a value in square brackets as shown in the following example.

```bat
[%a%]==[]
```

##### Empty Strings Example

This example shows how an empty string can be created, and how to check for the existence of an empty string.

```bat
@echo off 
SET a= 
SET b=Hello 
if [%a%]==[] echo "String A is empty" 
if [%b%]==[] echo "String B is empty "
```

This will print `String A is empty`.

{% endtab %}
{% endtabs %}

## Type Casting

Type casting is the process of converting a variable from one data type to another. This ensures compatibility between different types in operations and functions.

#### **Types of Type Casting**
1. **Implicit Casting** (Automatic Conversion)
   - Happens when a smaller or less precise type is converted into a larger or more precise type.
   - No risk of data loss.
   - Example: Converting an integer to a floating-point number.

2. **Explicit Casting** (Manual Conversion)
   - Requires direct conversion using specific functions or operators.
   - May lead to loss of data or precision.
   - Example: Converting a floating-point number to an integer.

#### **Common Use Cases**
- **Mathematical Operations:** Ensuring consistency between integers and floats.
- **User Input Handling:** Converting input into appropriate data types.
- **Data Processing:** Handling different formats across APIs or databases.

#### **Potential Risks**
⚠️ **Data Loss:** Converting complex types to simpler ones can remove details.  
⚠️ **Unexpected Behavior:** Incompatible conversions may lead to errors.  

Type casting is essential for efficient data management in programming, ensuring smooth interactions between different types. 

{% tabs %}
{% tab title="Python" %}

Python's **type casting** allows flexible data manipulation, ensuring compatibility between different types. 

### **Type Casting in Python**

| Type | Code Examples |
|------|--------------|
| **As Integer** | `i = int("10")` → Converts string `"10"` to integer `10` |
| **As Float** | `f = float("10.5")` → Converts string `"10.5"` to float `10.5` |
| **As String** | `s = str(10)` → Converts integer `10` to string `"10"` |
| **As Character** | `c = chr(65)` → Converts ASCII value `65` to character `'A'` |
| **As Boolean** | `b = bool(0)` → Converts `0` to `False`, `bool(1)` → `True` |
| **As List** | `lst = list("hello")` → Converts string `"hello"` to list `['h', 'e', 'l', 'l', 'o']` |
| **As Tuple** | `tpl = tuple([1, 2, 3])` → Converts list `[1, 2, 3]` to tuple `(1, 2, 3)` |
| **As Dictionary** | `d = dict([(1, "one"), (2, "two")])` → Converts list of tuples to dictionary `{1: "one", 2: "two"}` |
| **As Set** | `s = set([1, 2, 2, 3])` → Converts list `[1, 2, 2, 3]` to set `{1, 2, 3}` |

### **Converting Between Types**

```python
x = "42"
y = int(x)  # Converts string to integer
z = float(y)  # Converts integer to float
print(y, z)  # Output: 42 42.0
```

#### **Limitations and Pitfalls of Type Conversion in Python**

Type conversion in Python is useful for handling different data types, but it comes with **potential pitfalls** that can lead to unexpected behavior or errors.

##### **Loss of Precision**

- Converting **floats to integers** removes the decimal portion, potentially altering values.
- Example:
  ```python
  num = int(3.9)
  print(num)  # Output: 3 (decimal truncated)
  ```

##### **Type Errors**

- Some conversions are **not allowed**, leading to `TypeError`.
- Example:
  ```python
  num = int([1, 2, 3])  # Raises TypeError
  ```

##### **Value Errors**

- Converting incompatible strings to numbers results in `ValueError`.
- Example:
  ```python
  num = int("hello")  # Raises ValueError
  ```

##### **Unexpected Boolean Behavior**

- Python treats **non-empty values as `True`** and empty values as `False`, which can cause logic errors.
- Example:
  ```python
  print(bool("False"))  # Output: True (because it's a non-empty string)
  ```

##### **Implicit Conversions Can Lead to Bugs**

- Mixing **integers and floats** in operations can cause unintended type changes.
- Example:
  ```python
  result = 5 + 2.5  # Implicitly converts 5 to float
  print(type(result))  # Output: <class 'float'>
  ```

### **Handling Type Casting Errors**

```python
try:
    num = int("hello")  # Invalid conversion
except ValueError:
    print("Cannot convert 'hello' to an integer.")
```

### **Using `eval()` for Dynamic Type Casting**

```python
value = "3.14"
converted = eval(value)  # Converts string `"3.14"` to float `3.14`
print(type(converted))  # Output: <class 'float'>
```

⚠️ **Caution:** `eval()` can execute arbitrary code, so use it carefully.

{% endtab %}

{% tab title="PowerShell" %}

### **Basic Type Conversion**

| Description | Code Examples |
|------------|--------------|
| Convert string to integer | `[int]"42"` → `42` |
| Convert string to float | `[double]"3.14"` → `3.14` |
| Convert integer to string | `[string]42` → `"42"` |
| Convert ASCII value to character | `[char]65` → `'A'` |
| Convert boolean to integer | `[int]$true` → `1`, `[int]$false` → `0` |

---

### **Collection Type Conversion**

| Description | Code Examples |
|------------|--------------|
| Convert string to array | `@("Hello", "World")` |
| Convert list to hashtable | `@{Key1="Value1"; Key2="Value2"}` |
| Convert array to string | `-join @("Hello", "World")` becomes `"HelloWorld"` |

---

### **Advanced Explicit Type Casting**

| Description | Code Examples |
|------------|--------------|
| Force integer conversion | `[int]"3.9"` (becomes `3` i.e. truncates decimal) |
| Convert object to XML | `[xml]$xmlString` |
| Convert object to JSON | `$object | ConvertTo-Json` |
| Convert JSON to object | `$json | ConvertFrom-Json` |

---

### **Handling Type Conversion Errors**

Use `try-catch` blocks to handle conversion errors gracefully.

```powershell
try {
    $num = [int]"hello"  # Invalid conversion
} catch {
    Write-Output "Error: Cannot convert 'hello' to an integer."
}
```

---

### **Potential Pitfalls**

Similar to Python, there are a number of potential pitfalls to be aware of when comverting between different data types:

* 🚨 **Loss of Precision:** Converting floats to integers removes decimals.  
* 🚨 **Unexpected Boolean Behavior:** Non-empty strings evaluate as `$true`.  
* 🚨 **Implicit Conversions:** Mixing types can lead to unintended results.  

PowerShell’s type conversion system is powerful but requires careful handling to avoid unexpected behavior. 

You can explore more details on PowerShell type conversion [here](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.core/about/about_type_conversion?view=powershell-7.5) and [here](https://adamtheautomator.com/powershell-convert-string-to-int/).

{% endtab %}

{% tab title="Bash" %}

Bash scripting does not have built-in type casting like some other languages, but it provides ways to convert and manipulate data types using arithmetic operations, commands, and built-in functions. Bash’s type conversion typically relies on **workarounds** and external tools like `bc`, `awk`, and `jq`. 

---

### **Basic Type Conversion**

| Description | Code Examples |
|------------|--------------|
| Convert string to integer | `num=$(( "42" ))` → `42` |
| Convert string to float (using `bc`) | `echo "3.14" | bc` → `3.14` |
| Convert integer to string | `str="$num"` → `"42"` |
| Convert ASCII value to character | `printf \\$(printf '%o' 65)` → `'A'` |
| Convert boolean-like values | `[[ -n "$var" ]] && echo "True" || echo "False"` |

---

### **Collection Type Conversion**

| Description | Code Examples |
|------------|--------------|
| Convert string to array | `IFS="," read -ra arr <<< "apple,banana,grape"` |
| Convert array to string | `echo "${arr[*]}"` → `"apple banana grape"` |
| Convert list to associative array | `declare -A myDict; myDict[key]="value"` |
| Convert array to JSON (using `jq`) | `echo '{"name":"Alice","age":30}' | jq` |

---

### **Explicit Type Casting**

| Description | Code Examples |
|------------|--------------|
| Force integer conversion | `num=$(( "3.9" ))` → `3` (truncates decimal) |
| Convert object to JSON (using `jq`) | `echo '{"name":"Alice"}' | jq` |
| Convert JSON to object (using `jq`) | `echo '{"name":"Alice"}' | jq -r '.name'` |

---

### **Handling Type Conversion Errors**

Use regex to validate integer conversions before processing.

```bash
if [[ "$var" =~ ^[0-9]+$ ]]; then
    echo "Valid integer: $var"
else
    echo "Error: Not a number"
fi
```

---

### **Potential Pitfalls**

* 🚨 **Loss of Precision:** Bash does not support floating-point arithmetic natively.  
* 🚨 **Unexpected Boolean Behavior:** Non-empty strings evaluate as `true`.  
* 🚨 **Implicit Conversions:** Mixing types can lead to unintended results.  

You can explore more details on Bash type conversion [here](https://stackoverflow.com/questions/11268437/how-to-convert-string-to-integer-in-unix-shelll) and [here](https://1library.net/article/type-casting-unix-shell-scripting.yex493rq). 

{% endtab %}

{% tab title="CMD .bat" %}

Windows Batch scripting does not have built-in type casting like higher-level languages, but it provides ways to **convert and manipulate data types** using arithmetic operations and string manipulation.

---

### **Basic Type Conversion**

| Description | Code Examples |
|------------|--------------|
| Convert string to integer | `set /A num="42"` → `42` |
| Convert integer to string | `set str=%num%` → `"42"` |
| Convert ASCII value to character | `for /F %%A in ('cmd /c echo 65') do set char=%%A` → `'A'` |
| Convert boolean-like values | `if "%var%"=="" (echo False) else (echo True)` |

---

### **Collection Type Conversion**
| Description | Code Examples |
|------------|--------------|
| Convert comma-separated string to array | `for %%A in (%list%) do echo %%A` |
| Convert array to string | `set str=%array[*]%` |
| Convert list to dictionary-like structure | `set key1=value1 & set key2=value2` |

---

### **Handling Type Conversion Errors**

Uses error redirection (`2>nul`) to handle conversion errors gracefully.

```bat
@echo off
set var=hello
set /A num=%var% 2>nul
if "%num%"=="" echo "Error: Cannot convert '%var%' to an integer."
```

---

### **Potential Pitfalls**

* 🚨 **Loss of Precision:** Batch does not support floating-point arithmetic natively.  
* 🚨 **Unexpected Boolean Behavior:** Non-empty strings evaluate as `true`.  
* 🚨 **Implicit Conversions:** Mixing types can lead to unintended results.  

You can explore more details on Batch type conversion [here](https://stackoverflow.com/questions/25166704/convert-a-string-to-integer-in-a-batch-file) and [here](https://stackoverflow.com/questions/14475829/convert-a-string-to-number). 

{% endtab %}
{% endtabs %}

## Arrays

{% tabs %}
{% tab title="Python" %}

Python does not have built-in support for Arrays as so termed, but Python **Lists** and **Tuples** can be used instead, and work much in the same way.

### **Working with Lists in Python**

| Activity | Code Examples |
|----------|--------------|
| **Define** | `arr = ['Hello', 'World']` |
| **Access Elements** | `arr[0]` → `'Hello'` |
| **Get Length** | `len(arr)` → `2` |
| **Add Elements** | `arr.append('New')` → `['Hello', 'World', 'New']` |
| **Insert at Specific Position** | `arr.insert(1, 'there')` → `['Hello', 'there', 'World']` |
| **Remove Last Element** | `arr.pop()` → `['Hello']` |
| **Remove Specific Index** | `arr.pop(1)` → `['Hello']` |
| **Remove Element by Value** | `arr.remove('Hello')` → `['World']` |
| **Sort Elements** | `arr.sort()` (Alphabetical order) |
| **Reverse Elements** | `arr.reverse()` → `['World', 'Hello']` |
| **Check if Element Exists** | `'Hello' in arr` → `True` |
| **Loop Through Elements** | `for item in arr: print(item)` |
| **Copy List** | `copy_arr = arr.copy()` |
| **Concatenate Lists** | `new_arr = arr + ['Python', 'Rocks']` |
| **Convert List to String** | `', '.join(arr)` → `'Hello, World'` |
| **Convert String to List** | `arr = 'Hello World'.split()` → `['Hello', 'World']` |

#### **Looping Through Lists**

```python
arr = ['apple', 'banana', 'cherry']
for item in arr:
    print(item)  # Outputs each fruit
```

#### **Filtering Elements in a List**

```python
arr = [1, 2, 3, 4, 5]
filtered = [x for x in arr if x > 2]
print(filtered)  # Output: [3, 4, 5]
```

---

#### **Nested Lists**

| Description | Code Example |
|------------|--------------|
| Define a nested list | `nested_list = [[1, 2, 3], [4, 5, 6], [7, 8, 9]]` |
| Access an element | `nested_list[1][2]` → `6` |
| Loop through nested lists | `for sublist in nested_list: print(sublist)` |
| Flatten a nested list | `[item for sublist in nested_list for item in sublist]` → `[1, 2, 3, 4, 5, 6, 7, 8, 9]` |

### Tuples

A **tuple** is an ordered collection of items, similar to a **list**, but with one key difference—**tuples are immutable**. This means once a tuple is created, its contents **cannot be changed**, added to, or removed.

---

#### **Key Differences Between Lists and Tuples**

| Feature | List (`list`) | Tuple (`tuple`) |
|---------|-------------|----------------|
| **Mutability** | ✅ Mutable (can modify, add, remove elements) | ❌ Immutable (cannot change after creation) |
| **Syntax** | Defined using `[]` (square brackets) | Defined using `()` (parentheses) |
| **Performance** | Slower due to dynamic resizing | Faster due to fixed structure |
| **Memory Usage** | Uses more memory | Uses less memory |
| **Intended Use** | Dynamic, frequently modified data | Static, unchangeable data |

---

#### **Defining a List and a Tuple**

```python
# List (Can be modified)
my_list = ["apple", "banana", "cherry"]
my_list.append("date")  # Adding a new element
print(my_list)  # Output: ['apple', 'banana', 'cherry', 'date']

# Tuple (Cannot be modified)
my_tuple = ("apple", "banana", "cherry")
# my_tuple.append("date")  # ❌ This will raise an error!
print(my_tuple)  # Output: ('apple', 'banana', 'cherry')
```

#### **Nested Tuples**

| Description | Code Example |
|------------|--------------|
| Define a nested tuple | `nested_tuple = ((1, 2), (3, 4), (5, 6))` |
| Access an element | `nested_tuple[2][1]` → `6` |
| Iterate through nested tuples | `for subtuple in nested_tuple: print(subtuple)` |

#### **When to Use Tuples vs. Lists**

- **Use a List** when you need a **dynamic** data structure that will change during program execution.
- **Use a Tuple** when you need a **fixed, unchangeable collection** (e.g., **coordinates, config settings, database records**).

{% endtab %}

{% tab title="PowerShell" %}

### **Arrays in PowerShell**

**Arrays** are fixed-size collections used to store ordered data. They allow indexed access but cannot dynamically resize. Arrays are ideal for storing structured lists that don’t change frequently.

| Activity | Code Examples |
|----------|--------------|
| **Define an Array** | `$arr = @('Hello', 'World')` |
| **Access Elements** | `$arr[0]` → `'Hello'` |
| **Get Length** | `$arr.Length` → `2` |
| **Add Elements** | `$arr += 'New'` → `@('Hello', 'World', 'New')` |
| **Remove Last Element** | `$arr = $arr[0..($arr.Length - 2)]` |
| **Remove Specific Index** | `$arr = $arr \| Where-Object {$_ -ne 'World'}` |
| **Sort Elements** | `$arr = $arr \| Sort-Object` |
| **Reverse Elements** | `$arr = $arr \| Sort-Object -Descending` |
| **Check if Element Exists** | `if ('Hello' -in $arr) { Write-Output 'Exists' }` |
| **Loop Through Elements** | `foreach ($item in $arr) { Write-Output $item }` |

---

### **ArrayLists in PowerShell**

**ArrayLists** are dynamically resizable collections, making them more flexible than arrays. They allow elements to be added or removed without needing to reassign the entire structure, which is useful for scripts handling dynamic data. 

| Activity | Code Examples |
|----------|--------------|
| **Define an ArrayList** | `$arrList = [System.Collections.ArrayList]@('Hello', 'World')` |
| **Add Elements** | `$arrList.Add('New')` |
| **Remove Elements** | `$arrList.Remove('Hello')` |
| **Remove by Index** | `$arrList.RemoveAt(1)` |
| **Sort Elements** | `$arrList.Sort()` |
| **Reverse Elements** | `$arrList.Reverse()` |

---

### **Tuples in PowerShell**

**Tuples** store multiple values in a single object, maintaining a fixed structure. Unlike arrays or ArrayLists, tuples are immutable, meaning their values cannot be changed after creation. They are ideal for grouping related values when modification isn’t needed. 

| Activity | Code Examples |
|----------|--------------|
| **Define a Tuple** | `$tuple = [Tuple]::Create('Alice', 30, 'Engineer')` |
| **Access Elements** | `$tuple.Item1` → `'Alice'` |
| **Tuple with Multiple Types** | `$tuple = [Tuple[int, string]]::Create(42, 'Answer')` |

---

### **Choosing Between Arrays, ArrayLists, and Tuples**

| Feature | Arrays | ArrayLists | Tuples |
|---------|--------|-----------|--------|
| **Mutability** | ❌ Fixed size | ✅ Dynamic resizing | ❌ Immutable |
| **Performance** | ✅ Fast | ❌ Slower due to resizing | ✅ Fast |
| **Best Use Case** | Static collections | Dynamic lists | Fixed structured data |

{% endtab %}

{% tab title="Bash" %}

### **Basic Array Operations in Bash**

| Description | Code Example |
|-------------|--------------|
| **Define an Array:** Creates an array with multiple values. | `arr=("Hello" "World")` |
| **Access Elements:** Retrieves an element by index. | `echo ${arr[0]}` → `"Hello"` |
| **Get Array Length:** Gets the number of elements in the array. | `echo ${#arr[@]}` → `2` |
| **Add Elements:** Appends new elements to the array. | `arr+=("NewElement")` |
| **Insert at Specific Index:** Adds an element at a specific position. | `arr=( "${arr[@]:0:1}" "Insert" "${arr[@]:1}" )` |
| **Remove Elements by Index:** Deletes an element from the array. | `unset arr[1]` |
| **Remove Elements by Value:** Searches and removes elements matching a value. | `arr=( "${arr[@]/"World"}" )` |
| **Loop Through an Array:** Iterates over array elements. | `for item in "${arr[@]}"; do echo "$item"; done` |
| **Check if Element Exists:** Searches an array for a specific value. | `[[ "Hello" == "${arr[*]}" ]] && echo "Exists"` |
| **Concatenate Arrays:** Merges multiple arrays into one. | `arr3=( "${arr1[@]}" "${arr2[@]}" )` |
| **Sort an Array:** Sorts array elements alphabetically. | `IFS=$'\n' sorted=($(sort <<<"${arr[*]}")); echo "${sorted[@]}"` |
| **Reverse an Array:** Prints elements in reverse order. | `for ((i=${#arr[@]}-1; i>=0; i--)); do echo "${arr[i]}"; done` |
| **Convert Array to String:** Joins array elements into a single string. | `echo "${arr[*]}"` |
| **Convert String to Array:** Splits a string into an array. | `IFS="," read -r -a arr <<< "Hello,World"` |

### **Advanced Bash Array Operations**

| Description | Command |
|-------------|---------|
| Access the **first** element in the array. | `${arr[0]}` |
| Access the **last** element in the array. | `${arr[-1]}` |
| Print **all elements**, space-separated. | `${arr[@]}` |
| Get the **total number of elements** in the array. | `${#arr[@]}` |
| Get the **string length** of the first element. | `${#arr}` |
| Get the **string length** of the fourth element (index `3`). | `${#arr[3]}` |
| Extract a **subarray** (starting at index `3`, length `2`). | `${arr[@]:3:2}` |
| Print all **keys (indices)** of the array, space-separated. | `${!arr[@]}` |
| Convert a **comma-separated string** into an array. | `IFS="," read -r -a new_arr <<< "One,Two,Three"` |
| Convert an **array to a comma-separated string**. | `echo "${arr[*]}" \| tr ' ' ','` |
| Sort an array **alphabetically**. | `sorted=($(for val in "${arr[@]}"; do echo "$val"; done \| sort))` |
| Print an array **in reverse order**. | `for ((i=${#arr[@]}-1; i>=0; i--)); do echo "${arr[i]}"; done` |
| **Search for a pattern** in the array elements. | `for i in "${arr[@]}"; do echo "$i" \| grep "pattern"; done` |
| **Remove elements** matching `"unwanted"` from the array. | `filtered=($(echo "${arr[@]}" \| tr ' ' '\n' \| grep -v "unwanted"))` |
| Load an array **from a file** line by line. | `mapfile -t arr < file.txt` |

### **Bash Array Manipulation**

| Description | Command |
|-------------|---------|
| **Push** (Add an element to the array) | `Numbers=("${Numbers[@]}" 99)` |
| **Also Push** (Alternate way to add an element) | `Numbers+=('42')` |
| **Remove by Regex Match** (Removes elements matching a pattern) | `Words=( ${Words[@]/Te*/} )` |
| **Remove One Item** (Delete element at index `2`) | `unset Names[2]` |
| **Duplicate** (Create a copy of the array) | `Cities=("${Cities[@]}")` |
| **Concatenate** (Merge two arrays) | `Items=("${Fruits[@]}" "${Vegetables[@]}")` |
| **Read from File** (Store lines of a file into an array) | `logs=(`cat "system.log"`)` |

### **Iteration**

You can iterate through all of the items in an array to do some action on all them with a `for` loop.

```bash
for i in "${arrayName[@]}"; do
  echo $i
done
```

### **Advanced Bash Array Manipulation**

#### **Sorting an Array**

Sorting an array in Bash requires using the `sort` command to preserve the array structure.

```bash
arr=("banana" "apple" "cherry")
IFS=$'\n' sorted=($(sort <<<"${arr[*]}"))
unset IFS
echo "${sorted[@]}"  # Output: apple banana cherry
```

* **Uses `IFS` to handle spaces properly.**  
* **Sorts elements alphabetically.**  

---

#### **Filtering an Array**

Filtering an array involves removing unwanted elements using `grep` or `awk`.

```bash
arr=("apple" "banana" "cherry" "grape")
filtered=($(echo "${arr[@]}" | tr ' ' '\n' | grep -v "banana"))
echo "${filtered[@]}"  # Output: apple cherry grape
```

* **Removes `"banana"` from the array dynamically.**  
* **Uses `grep -v` to exclude elements.**  

---

#### **Multi-Dimensional Arrays in Bash**

Bash does not support true multi-dimensional arrays, but associative arrays (See Dictionaries) can simulate them.

```bash
declare -A matrix
matrix[0,0]="A"
matrix[0,1]="B"
matrix[1,0]="C"
matrix[1,1]="D"

echo "${matrix[0,1]}"  # Output: B
```

* **Uses associative arrays (`declare -A`) to store matrix-like data.**  
* **Access elements using `key,value` pairs.**  

---

#### **Reversing an Array**

Print elements in reverse order dynamically.

```bash
arr=("one" "two" "three")
for ((i=${#arr[@]}-1; i>=0; i--)); do
    echo "${arr[i]}"
done
```

{% endtab %}

{% tab title="CMD .bat" %}

### **Using Arrays in Batch Scripts**

Batch scripting does not have built-in array support like other programming languages, but arrays can be simulated using indexed variables and loops.

#### **Limitations of Arrays in Batch**

- **Each element is stored as a separate variable** using indexed names (`arr[0]`, `arr[1]`, etc.).
- **Loops are required** to iterate through array elements.
- **Elements must be manually managed**, including adding, removing, and modifying values.
- **Limited functionality compared to other scripting languages**, but useful for handling lists of data.

---

### **Batch Script Arrays**

| Activity | Code Examples |
|----------|--------------|
| **Define an Array** | `set arr[0]=Hello` |
| **Access Elements** | `echo %arr[0]%` |
| **Get Length** | `set count=0 & for /L %%i in (0,1,9) do if defined arr[%%i] set /A count+=1 & echo %count%` |
| **Adding Elements** | `set arr[1]=World` |
| **Appending Elements** | `set arr[%count%]=NewItem` (Using a counter to add dynamically) |
| **Removing Elements** | `set arr[1]=` (Clears the value but does not shift indices) |
| **Remove Element by Value** | `for /F "tokens=*" %%i in ('set arr') do if not "%%i"=="World" echo %%i` |
| **Iterate Over Array** | `for /L %%i in (0,1,%count%) do echo !arr[%%i]!` |
| **Check if Element Exists** | `if defined arr[2] echo "Exists"` |
| **Concatenate Arrays** | `set arr[0]=Hello & set arr[1]=World & set arr[2]=Batch` |
| **Sort Elements** | `for /F "tokens=*" %%A in ('set arr') do echo %%A \| sort` |
| **Reverse Elements** | `for /L %%i in (%count%,-1,0) do echo !arr[%%i]!` |
| **Read from File into Array** | `for /F "tokens=*" %%A in (data.txt) do set arr[%count%]=%%A & set /A count+=1` |

---

### **Example: Iterating Over an Array**

```batch
@echo off
setlocal enabledelayedexpansion
set arr[0]=Apple
set arr[1]=Banana
set arr[2]=Cherry

for /L %%i in (0,1,2) do (
    echo !arr[%%i]!
)
```

* Batch arrays require **manual management**, but they are useful for handling lists of data in automation scripts. 
* Each element of the array needs to be defined with the set command.
* A `for` loop is required to iterate through the values of the array.
* Use `enabledelayedexpansion` to handle dynamic variables.

### **Alternative Array Definition**

Another way to implement arrays is to define a space-separated list of values. 

```bat
@echo off 
set list = 1 2 3 4 
(for %%a in (%list%) do ( 
   echo %%a 
))
```

### Accessing Array Values

You can retrieve a value from the array by using subscript syntax, passing the index of the value you want to retrieve within square brackets immediately after the name of the array.

```bat
@echo off 
set a[0]=1 
echo %a[0]%
```

### Modifying an Array

To add an element to the end of the array, you can use the `set` command along with the new final index of the array element.  There is no append function as in other languages.

```bat
@echo off 
set a[0] = 1  
set a[1] = 2  
set a[2] = 3 
Rem Adding an element at the end of an array 
Set a[3] = 4 
echo The last element of the array is %a[3]%
```

You can also modify an existing element of an Array by assigning a new value at a given index.

```bat
@echo off 
set a[0] = 1 
set a[1] = 2  
set a[2] = 3 
Rem Setting the new value for the second element of the array 
Set a[1] = 5 
echo The new value of the second element of the array is %a[1]%
```

### Iterating Over an Array's values

Iterating over an array is achieved by using a `for` loop and stepping through each element of the array. 

```bat
@echo off 
setlocal enabledelayedexpansion 
set category[0] = fruits 
set category[1] = vegetables 
set category[2] = dairy 
set category[3] = grains 
set category[4] = protein 

for /l %%i in (0,1,4) do ( 
   echo !category[%%i]! 
)
```

**Notes:**

* Each element of the array needs to be specifically defined using the `set` command.
* A `for` loop with the `/L` parameter iterates through a sequence of values, allowing traversal of the array-like list.

### Length of an Array

The length of an array is found by iterating over the list of values in the array since there is no direct function to determine the number of elements in an array.

```bat
@echo off 
set Arr[0] = 1 
set Arr[1] = 2 
set Arr[2] = 3 
set Arr[3] = 4 
set "x = 0" 
:LenLoop 

if defined Arr[%x%] ( 
   call echo %%Arr[%x%]%% 
   set /a "x+=1"
   GOTO :LenLoop 
)
echo "The length of the array is" %x%
```

{% endtab %}
{% endtabs %}

## Conditionals

{% tabs %}
{% tab title="Python" %}
| Switch             | Code Examples                                                                                                                                                                                                                                                                                |
| ------------------ | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| If / ElseIf / Else | <p><code>a = 42</code></p><p><code>b = 420</code></p><p><code>if b > a:</code></p><p> <code>print("b is greater than a")</code></p><p><code>elif a == b:</code></p><p> <code>print("a and b are equal")</code></p><p><code>else:</code></p><p> <code>print("a is greater than b")</code></p> |
| Case               |                                                                                                                                                                                                                                                                                              |
{% endtab %}

{% tab title="PowerShell" %}
| Switch             | Code Examples                                                                                                                                                                                                                                                                                                                                                                                                                                      |
| ------------------ | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| If / ElseIf / Else | <p><code>$a = 42</code></p><p><code>$b = 420</code></p><p><code>if ($b -gt $a)</code></p><p><code>{</code></p><p> <code>Write-Host "b is greater than a"</code></p><p><code>}</code></p><p><code>elseif ($a -eq $b)</code></p><p><code>{</code></p><p> <code>Write-Host "a and b are equal"</code></p><p><code>}</code></p><p><code>else</code></p><p><code>{</code></p><p> <code>Write-Host "a is greater than b"</code></p><p><code>}</code></p> |
| Case               |                                                                                                                                                                                                                                                                                                                                                                                                                                                    |
{% endtab %}

{% tab title="Bash" %}

| Switch             | Code Examples               |
| ------------------ | --------------------------- |
| If / ElseIf / Else | `if [ "$var" = "value" ]; then echo "Match"; elif [ "$var" = "other" ]; then echo "Other"; else echo "No Match"; fi` |
| Case               | `case "$var" in value) echo "Match" ;; other) echo "Other" ;; *) echo "No Match" ;; esac` |

### Case/switch

```bash
case "$1" in
  start | up)
    vagrant up
    ;;

  *)
    echo "Usage: $0 {start|stop|ssh}"
    ;;
esac
```

```bash
# String
if [[ -z "$string" ]]; then
  echo "String is empty"
elif [[ -n "$string" ]]; then
  echo "String is not empty"
else
  echo "This never happens"
fi
```
{% endtab %}

{% tab title="CMD .bat" %}

| Switch             | Code Examples               |
| ------------------ | --------------------------- |
| If / ElseIf / Else | `if "%var%"=="value" (echo Match) else (echo No Match)` |
| Case               | `REM Not natively supported in CMD` |

The first decision-making statement is the 'if' statement. The general form of this statement is as follows:

```bash
if(condition) do_something
```

First, a condition is evaluated in the 'if' statement. If the condition is true, it then executes the statements. 

## Checking Variables

One of the common uses for the 'if' statement in Batch Script is for checking variables which are set in the Batch Script itself. The evaluation of the 'if' statement can be done for both strings and numbers.

### Checking Integer Variables

The following example shows how the 'if' statement can be used for numbers.

**Example**

```bat
@echo off 
SET /A a = 5 
SET /A b = 10 
SET /A c = %a% + %b% 
if %c%==15 echo "The value of variable c is 15" 
if %c%==10 echo "The value of variable c is 10"
```

The key things to note about the above script are:

* The first 'if' statement checks if the value of the variable c is 15. If so, then it echo's a string to the command prompt.
* Since the condition in the statement - `if %c% == 10 echo "The value of variable **c** is 10` evaluates to false, the echo part of the statement will not be executed.

**Output**

The above command produces the following output.

```
15
```

### Checking String Variables

The following example shows how the 'if' statement can be used for strings.

**Example**

```bat
@echo off 
SET str1 = String1 
SET str2 = String2 
if %str1%==String1 echo "The value of variable String1" 
if %str2%==String3 echo "The value of variable c is String3"
```

The key thing to note about the above program is −

* The first 'if' statement checks if the value of the variable str1 contains the string “String1”. If so, then it echo's a string to the command prompt.
* Since the condition of the second 'if' statement evaluates to false, the echo part of the statement will not be executed.

**Output**

The above command produces the following output.

```
"The value of variable String1"
```

**Note** − The evaluation in the 'if' statement is case-sensitive. The same program as above is modified a little as shown in the following example. In the first statement, we have changed the comparison criteria. Because of the different casing, the output of the following program would yield nothing.

```bat
@echo off 
SET str1 = String1 
SET str2 = String2 
if %str1%==StrinG1 echo "The value of variable String1" 
if %str2%==String3 echo "The value of variable c is String3"
```
{% endtab %}
{% endtabs %}

## Loops

{% tabs %}
{% tab title="Python" %}
| Loop Type | Code Examples                                                                                                                                                                      |
| --------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| For       | <p><code>fruits = ["apple", "banana", "cherry"]</code></p><p><code>for x in fruits:</code></p><p> <code>print(x)</code></p>                                                        |
| While     | <p><code>i = 1</code></p><p><code>while i &#x3C; 6:</code></p><p> <code>print(i)</code></p><p> <code>i += 1</code></p>                                                             |
| Break     | <p><code>i = 1</code></p><p><code>while i &#x3C; 6:</code></p><p> <code>print(i)</code></p><p> <code>if i == 3:</code></p><p> <code>break</code></p><p> <code>i += 1</code></p>    |
| Continue  | <p><code>i = 1</code></p><p><code>while i &#x3C; 6:</code></p><p> <code>print(i)</code></p><p> <code>if i == 3:</code></p><p> <code>continue</code></p><p> <code>i += 1</code></p> |
{% endtab %}

{% tab title="PowerShell" %}
| Loop Type | Code Examples                                                                                                                                                                                                                                                                  |
| --------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| For       | <p><code>$fruits = @("apple", "banana", "cherry")</code></p><p><code>foreach($x in $fruits)</code></p><p><code>{</code></p><p> <code>Write-Host $x</code></p><p><code>}</code></p>                                                                                             |
| While     | <p><code>$i = 1</code></p><p><code>while ($i -lt 6)</code></p><p><code>{</code></p><p> <code>Write-Host $i</code></p><p> <code>$i++</code></p><p><code>}</code></p>                                                                                                            |
| Break     | <p><code>$i = 1</code></p><p><code>while ($i -lt 6)</code></p><p><code>{</code></p><p> <code>Write-Host $i</code></p><p> <code>if ($i -eq 3)</code></p><p> <code>{</code></p><p> <code>break</code></p><p> <code>}</code></p><p> <code>$i++</code></p><p><code>}</code></p>    |
| Continue  | <p><code>$i = 1</code></p><p><code>while ($i -lt 6)</code></p><p><code>{</code></p><p> <code>Write-Host $i</code></p><p> <code>if ($i -eq 3)</code></p><p> <code>{</code></p><p> <code>continue</code></p><p> <code>}</code></p><p> <code>$i++</code></p><p><code>}</code></p> |
{% endtab %}

{% tab title="Bash" %}

| Loop Type | Code Examples               |
| --------- | --------------------------- |
| For       | `for i in 1 2 3; do echo $i; done` |
| While     | `while [ "$var" != "stop" ]; do echo $var; done` |
| Break     | `for i in 1 2 3; do [ "$i" = "2" ] && break; echo $i; done` |
| Continue  | `for i in 1 2 3; do [ "$i" = "2" ] && continue; echo $i; done` |

### Basic for loop

```bash
for i in /etc/rc.*; do
  echo $i
done
```

### C-like for loop

```bash
for ((i = 0 ; i < 100 ; i++)); do
  echo $i
done
```

### Ranges

```bash
for i in {1..5}; do
    echo "Welcome $i"
done
```

**With step size**

```bash
for i in {5..50..5}; do
    echo "Welcome $i"
done
```

### Reading lines

```bash
cat file.txt | while read line; do
  echo $line
done
```

### Forever

```bash
while true; do
  $commands_here
done
```
{% endtab %}

{% tab title="CMD .bat" %}


TODO: this

| Loop Type | Code Examples |
| --------- | ------------- |
| For       |               |
| While     |               |
| Break     |               |
| Continue  |               |

## Loops

In the decision making chapter, we have seen statements which have been executed one after the other in a sequential manner. Additionally, implementations can also be done in Batch Script to alter the flow of control in a program's logic. They are then classified into flow of control statements.

## `While` Statement Implementation

There is no direct `while` statement available in Batch Scripting but we can do an implementation of this loop very easily by using the if statement and labels.

The first part of the while implementation is to set the counters which will be used to control the evaluation of the 'if' condition. We then define our label which will be used to embody the entire code for the while loop implementation. The 'if' condition evaluates an expression. If the expression evaluates to true, the code block is executed. If the condition evaluates to false then the loop is exited. When the code block is executed, it will return back to the label statement for execution again.

### Syntax

```bat
Set counters
:label
If (expression) (
   Do_something
   Increment counter
   Go back to :label
)
```

* The entire code for the while implementation is placed inside of a label.
* The counter variables must be set or initialized before the while loop implementation starts.
* The expression for the while condition is done using the 'if' statement. If the expression evaluates to true then the relevant code inside the 'if' loop is executed.
* A counter needs to be properly incremented inside of 'if' statement so that the while implementation can terminate at some point in time.
* Finally, we will go back to our label so that we can evaluate our 'if' statement again.

Following is an example of a while loop statement.

### Example

```bat
@echo off
SET /A "index = 1"
SET /A "count = 5"
:while
if %index% leq %count% (
   echo The value of index is %index%
   SET /A "index = index + 1"
   goto :while
)
```

In the above example, we are first initializing the value of an index integer variable to 1. Then our condition in the 'if' loop is that we are evaluating the condition of the expression to be that index should it be less than the value of the count variable. Till the value of index is less than 5, we will print the value of index and then increment the value of index.

## `For` Statement - `List Implementations`

The "FOR" construct offers looping capabilities for batch files. Following is the common construct of the 'for' statement for working with a list of values.

### Syntax

```bat
FOR %%variable IN list DO do_something
```

The classic 'for' statement consists of the following parts −

* Variable declaration – This step is executed only once for the entire loop and used to declare any variables which will be used within the loop. In Batch Script, the variable declaration is done with the %% at the beginning of the variable name.
* List – This will be the list of values for which the 'for' statement should be executed.
* The do\_something code block is what needs to be executed for each iteration for the list of values.

Following is an example of how the 'goto' statement can be used.

### Example

```bat
@echo off 
FOR %%F IN (1 2 3 4 5) DO echo %%F
```

The key thing to note about the above program is −

* The variable declaration is done with the %% sign at the beginning of the variable name.
* The list of values is defined after the IN clause.
* The do\_something code is defined after the echo command. Thus for each value in the list, the echo command will be executed.

## Looping through Ranges

The 'for' statement also has the ability to move through a range of values. Following is the general form of the statement.

## Syntax

```bat
FOR /L %%variable IN (lowerlimit,Increment,Upperlimit) DO do_something
```

Where

* The /L switch is used to denote that the loop is used for iterating through ranges.
* Variable declaration – This step is executed only once for the entire loop and used to declare any variables which will be used within the loop. In Batch Script, the variable declaration is done with the %% at the beginning of the variable name.
* The IN list contains of 3 values. The lowerlimit, the increment, and the upperlimit. So, the loop would start with the lowerlimit and move to the upperlimit value, iterating each time by the Increment value.
* The do\_something code block is what needs to be executed for each iteration.

Following is an example of how the looping through ranges can be carried out.

### Example

```bat
@ECHO OFF 
FOR /L %%X IN (0,1,5) DO ECHO %%X
```

## Classic for Loop Implementation

Following is the classic 'for' statement which is available in most programming languages.

### Typical 'for' loop Syntax

```
for(variable declaration;expression;Increment) {
   statement #1
   statement #2
   …
}
```

The Batch Script language does not have a direct 'for' statement which is similar to the above syntax, but one can still do an implementation of the classic 'for' loop statement using if statements and labels.

Let's look at the general syntax implementation of the classic for loop in batch scripting.

```bat
Set counter
:label

If (expression) exit loop
Do_something
Increment counter
Go back to :label
```

* The entire code for the 'for' implementation is placed inside of a label.
* The counters variables must be set or initialized before the 'for' loop implementation starts.
* The expression for the 'for' loop is done using the 'if' statement. If the expression evaluates to be true then an exit is executed to come out of the loop.
* A counter needs to be properly incremented inside of the 'if' statement so that the 'for' implementation can continue if the expression evaluation is false.
* Finally, we will go back to our label so that we can evaluate our 'if' statement again.

Following is an example of how to carry out the implementation of the classic 'for' loop statement.

### Example

```bat
@echo off 
SET /A i = 1 
:loop 

IF %i%==5 GOTO END 
echo The value of i is %i% 
SET /a i=%i%+1 
GOTO :LOOP 
:END
```

## Looping through Command Line Arguments

The 'for' statement can also be used for checking command line arguments. The following example shows how the 'for' statement can be used to loop through the command line arguments.

### Example

```bat
@ECHO OFF 
:Loop 

IF "%1"=="" GOTO completed 
FOR %%F IN (%1) DO echo %%F 
SHIFT 
GOTO Loop 
:completed
```

### Output

Let's assume that our above code is stored in a file called Test.bat. The above command will produce the following output if the batch file passes the command line arguments of 1,2 and 3 as Test.bat 1 2 3.

```
1 
2 
3
```

## `Break` Statement Implementation

The break statement is used to alter the flow of control inside loops within any programming language. The break statement is normally used in looping constructs and is used to cause immediate termination of the innermost enclosing loop.

The break statement is used to alter the flow of control inside loops within any programming language. The break statement is normally used in looping constructs and is used to cause immediate termination of the innermost enclosing loop.

The Batch Script language does not have a direct 'for' statement which does a break but this can be implemented by using labels. The following example shows the diagrammatic explanation of the break statement implementation in Batch Script.

### Example

```bat
@echo off 
SET /A "index=1" 
SET /A "count=5" 
:while 
if %index% leq %count% ( 
   if %index%==2 goto :Increment 
      echo The value of index is %index% 
:Increment 
   SET /A "index=index + 1" 
   goto :while 
)
```

The key thing to note about the above implementation is the involvement of two 'if' conditions. The second 'if' condition is used to control when the break is implemented. If the second 'if' condition is evaluated to be true, then the code block is not executed and the counter is directly implemented.

Following is an example of how to carry out the implementation of the break statement.

The key thing to note about the above script is the addition of a label called :Increment. When the value of index reaches 2, we want to skip the statement which echoes its value to the command prompt and directly just increment the value of index.

{% endtab %}
{% endtabs %}

## Functions

{% tabs %}
{% tab title="Python" %}
| Functions          | Code Examples                                                                                                                                                                                                                              |
| ------------------ | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| Definition         | <p><code>def hello_function():</code></p><p> <code>print("Hello from my function!")</code></p><p>&#x3C;code>&#x3C;/code></p><p><code>hello_function()</code></p>                                                                           |
| Arguments          | <p><code>def my_name(fname, lname):</code></p><p> <code>print("My name is " + fname + " " + lname)</code></p><p>&#x3C;code>&#x3C;/code></p><p><code>my_function("Wolf", "Zweiler")</code></p>                                              |
| Variable Arguments | <p><code>def second_arg(*children):</code></p><p> <code>print("The youngest child is " + children[1])</code></p><p>&#x3C;code>&#x3C;/code></p><p><code>my_function("Sarah", "Emily", "Tom")</code></p>                                     |
| Named Arguments    | <p><code>def young_child(child3, child2, child1):</code></p><p> <code>print("The youngest child is " + child3)</code></p><p>&#x3C;code>&#x3C;/code></p><p><code>my_function(child1 = "Sarah", child2 = "Emily", child3 = "Tom")</code></p> |
| Default Values     | <p><code>def my_country(country = "Wakanda"):</code></p><p> <code>print("I am from " + country)</code></p><p>&#x3C;code>&#x3C;/code></p><p><code>my_country()</code></p>                                                                   |
| Return Values      | <p><code>def five_times(x):</code></p><p> <code>return 5 * x</code></p>                                                                                                                                                                    |
{% endtab %}

{% tab title="PowerShell" %}
| Functions          | Code Examples                                                                                                                                                                                                                                                                               |
| ------------------ | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Definition         | <p><code>function hello_function()</code></p><p><code>{</code></p><p> <code>Write-Host "Hello from my function!"</code></p><p><code>}</code></p><p><code>hello_function</code></p>                                                                                                          |
| Arguments          | <p><code>function my_name($fname, $lname)</code></p><p><code>{</code></p><p> <code>Write-Host "My name is $fname $lname"</code></p><p><code>}</code></p><p><code>my-function -fname "Wolf" -lname "Zweiler"</code></p>                                                                      |
| Variable Arguments | <p><code>function second_arg()</code></p><p><code>{</code></p><p> <code>Write-Host "The youngest child is $($args[1])"</code></p><p><code>}</code></p><p><code>my-function "Sarah" "Emily" "Tom"</code></p>                                                                                 |
| Named Arguments    | <p><code>function young_child($child3, $child2, $child1)</code></p><p><code>{</code></p><p> <code>Write-Host "The youngest child is $child3"</code></p><p><code>}</code></p><p><code>my-function -child1 "Sarah" -child2 "Emily" -child3 "Tom"</code></p>                                   |
| Default Values     | <p><code>function my_country</code></p><p><code>{</code></p><p> <code>param(</code></p><p> <code>$country = "Wakanda"</code></p><p> <code>)</code></p><p>&#x3C;code>&#x3C;/code></p><p> <code>Write-Host "I am from $country"</code></p><p><code>}</code></p><p><code>my_country</code></p> |
| Return Values      | <p><code>function five_times($x)</code></p><p><code>{</code></p><p> <code>5 * $x</code></p><p><code>}</code></p>                                                                                                                                                                            |
{% endtab %}

{% tab title="Bash" %}

| Functions          | Code Examples               |
| ------------------ | --------------------------- |
| Definition         | `myfunc() { echo "Hello"; }` |
| Arguments          | `myfunc() { echo "Hello $1"; }; myfunc World` |
| Variable Arguments | `myfunc() { for arg in "$@"; do echo $arg; done; }; myfunc a b c` |
| Named Arguments    | `# Not natively supported in Bash` |
| Default Values     | `myfunc() { local var=${1:-default}; echo $var; }; myfunc` |
| Return Values      | `myfunc() { return 42; }; myfunc; echo $?` |

### Arguments

Referencing arguments in a bash script:

| `$#` | Number of arguments                   |
| ---- | ------------------------------------- |
| `$*` | All arguments                         |
| `$@` | All arguments, starting from first    |
| `$1` | First argument, `$2` second, etc.     |
| `$_` | Last argument of the previous command |

### Returning values 

```bash
myfunc() {
    local myresult='some value'
    echo $myresult
}
```

```bash
result="$(myfunc)"
```

Defining Functions

```bash
myfunc() {
    echo "hello $1"
}
```

```bash
# Same as above (alternate syntax)
function myfunc() {
    echo "hello $1"
}
```

```bash
myfunc "John"
```

{% endtab %}

{% tab title="CMD .bat" %}

Basic functions can be defined in batch scripts, hoever they do not accept arguments nor do they have the ability to return values in the programming sense. 

| Functions          | Code Examples               |
| ------------------ | --------------------------- |
| Definition         | `:myfunc echo Hello & goto :eof` |
| Arguments          | `REM Not natively supported in CMD` |
| Variable Arguments | `REM Not natively supported in CMD` |
| Named Arguments    | `REM Not natively supported in CMD` |
| Default Values     | `REM Not natively supported in CMD` |
| Return Values      | `REM Not natively supported in CMD` |

{% endtab %}
{% endtabs %}

## Classes

{% tabs %}
{% tab title="Python" %}
| Activity                   | Code Examples                                                                                                                                                                                                                                                                                                                                                                                      |
| -------------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Class Definition           | <p><code>class MyClass:</code></p><p> <code>x = 5</code></p>                                                                                                                                                                                                                                                                                                                                       |
| Object Creation            | `MyClass()`                                                                                                                                                                                                                                                                                                                                                                                        |
| Using Class Constructors   | <p><code>class Person:</code></p><p> <code>def __init__(self, name, age):</code></p><p> <code>self.name = name</code></p><p> <code>self.age = age</code></p><p>&#x3C;code>&#x3C;/code></p><p><code>p1 = Person("Bob", 42)</code></p>                                                                                                                                                               |
| Defining and using Methods | <p><code>class Person:</code></p><p> <code>def __init__(self, name, age):</code></p><p> <code>self.name = name</code></p><p> <code>self.age = age</code></p><p>&#x3C;code>&#x3C;/code></p><p> <code>def myfunc(self):</code></p><p> <code>print("Hello my name is " + self.name)</code></p><p>&#x3C;code>&#x3C;/code></p><p><code>p1 = Person("Bob", 42)</code></p><p><code>p1.myfunc()</code></p> |
{% endtab %}

{% tab title="PowerShell" %}
| Activity                   | Code Examples                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                  |
| -------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| Class Definition           | <p><code>class MyClass {</code></p><p> <code>$x = 5</code></p><p><code>}</code></p>                                                                                                                                                                                                                                                                                                                                                                                                                                            |
| Object Creation            | `[MyClass]::new()`                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                             |
| Using Class Constructors   | <p><code>class Person {</code></p><p> <code>Person($Name, $Age) {</code></p><p> <code>$this.Name = $Name</code></p><p> <code>$this.Age = $Age</code></p><p> <code>}</code></p><p>&#x3C;code>&#x3C;/code></p><p> <code>$Name = ''</code></p><p> <code>$Age = 0</code></p><p><code>}</code></p><p><code>[Person]::new('Bob', 42)</code></p>                                                                                                                                                                                      |
| Defining and using Methods | <p><code>class Person {</code></p><p> <code>Person($Name, $Age) {</code></p><p> <code>$this.Name = $Name</code></p><p> <code>$this.Age = $Age</code></p><p> <code>}</code></p><p>&#x3C;code>&#x3C;/code></p><p> <code>[string]myfunc() {</code></p><p> <code>return "Hello my name is $($this.Name)"</code></p><p> <code>}</code></p><p>&#x3C;code>&#x3C;/code></p><p> <code>$Name = ''</code></p><p> <code>$Age = 0</code></p><p><code>}</code></p><p>&#x3C;code>&#x3C;/code></p><p><code>[Person]::new('Bob', 42)</code></p> |
{% endtab %}

{% tab title="Bash" %}
TODO:
| Activity                   | Code Examples |
| -------------------------- | ------------- |
| Class Definition           |               |
| Object Creation            |               |
| Using Class Constructors   |               |
| Defining and using Methods |               |
{% endtab %}

{% tab title="CMD .bat" %}
TODO:
| Activity                   | Code Examples |
| -------------------------- | ------------- |
| Class Definition           |               |
| Object Creation            |               |
| Using Class Constructors   |               |
| Defining and using Methods |               |
{% endtab %}
{% endtabs %}

## Comments

{% tabs %}
{% tab title="Python" %}
| Comment Type | Code Examples                                                                   |
| ------------ | ------------------------------------------------------------------------------- |
| Single line  | `# Hello, world!`                                                               |
| Multiline    | <p><code>"""</code></p><p><code>Hello, world!</code></p><p><code>"""</code></p> |
{% endtab %}

{% tab title="PowerShell" %}
| Comment Type | Code Examples                                                                      |
| ------------ | ---------------------------------------------------------------------------------- |
| Single line  | `# Hello, world!`                                                                  |
| Multiline    | <p><code>&#x3C;#</code></p><p><code>Hello, world!</code></p><p><code>#></code></p> |
{% endtab %}

{% tab title="Bash" %}

| Comment Type | Code Examples |
| ------------ | ------------- |
| Single line  | `# Single line comment` |
| Multiline    |  See example below        |

### Comments

```bash
# Single line comment
```

```bash
: '
This is a
multi line
comment
'
```
{% endtab %}

{% tab title="CMD .bat" %}

| Comment Type | Code Examples |
| ------------ | ------------- |
| Single line  |  `Rem This is a comment`             |
| Multiline    |  Not implemented in batch scripts`             |

## Comments Using the Rem Statement

There are two ways to create comments in Batch Script; one is via the Rem command. Any text which follows the Rem statement will be treated as comments and will not be executed. Following is the general syntax of this statement.

### Syntax

```bat
Rem This is a comment
```

### Example

The following example shows a simple way the **Rem** command can be used to explain the function of the code below it.

```bat
@echo off 
Rem This program just displays Hello World 
set message=Hello World 
echo %message%
```

### Output

The above command produces the following output. You will notice that the line with the Rem statement will not be executed.

```
Hello World
```

### Notes:

1. `REM` command must be followed by a space or tab character.

2. You may include any symbol in the comments without any restriction.

3. If `ECHO` is in ON state, the comment is displayed on the command prompt. Otherwise, it is ignored.

4. If you want `ECHO` to be ON and you don't want to display the comment line, use an at sign `@` before `REM` command.

5. If you have too many lines of Rem, it could slow down the code, because in the end each line of code in the batch file still needs to be executed.

## Comments Using the :: Statement

The other way to create comments in Batch Script is via the :: command. Any text which follows the :: statement will be treated as comments and will not be executed. Following is the general syntax of this statement.

### Syntax

```bat
:: This is a comment
```

### Example

The comment marker `::` is used exactly the same as `Rem`.

```bat
@echo off 
:: This program just displays Hello World 
set message = Hello World 
echo %message%
```

# Trick for Multiple Line Comments

Use a `GOTO` statement to simulate a multiline comment by bypassing the lines within the block.

```bat
GOTO MultiLineComment
This line is comment.
And so is this line.
And this one...
:MultiLineComment
```

{% endtab %}
{% endtabs %}

## Data Types

{% tabs %}
{% tab title="Python" %}
| Action            | Code Examples                                            |
| ----------------- | -------------------------------------------------------- |
| Get Object's Type | <p><code>var = 1</code></p><p><code>type(var)</code></p> |
{% endtab %}

{% tab title="PowerShell" %}
| Action            | Code Examples                                                                                                 |
| ----------------- | ------------------------------------------------------------------------------------------------------------- |
| Get Object's Type | <p><code>$var = 1</code></p><p><code>$var | Get-Member</code></p><p>#or</p><p><code>$var.GetType()</code></p> |
{% endtab %}

{% tab title="Bash" %}

Bash does not have the concept of typed variables, though attributes can be defined using the `declare` command.  See the link below for more information:

[https://stackoverflow.com/questions/29840525/get-variable-type-in-bash](https://stackoverflow.com/questions/29840525/get-variable-type-in-bash)



{% endtab %}

{% tab title="CMD .bat" %}
TODO: this

| Action            | Code Examples |
| ----------------- | ------------- |
| Get Object's Type |               |
{% endtab %}
{% endtabs %}

## Dictionaries

{% tabs %}
{% tab title="Python" %}
| **Activity**        | Code Examples                                                                                                                                                                                                                                                                                          |
| ------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| Defining            | <p><code>thisdict = {</code></p><p> <code>"brand": "Ford",</code></p><p> <code>"model": "Mustang",</code></p><p> <code>"year": 1964</code></p><p><code>}</code></p><p><code>print(thisdict)</code></p>                                                                                                 |
| Accessing Elements  | <p><code>thisdict = {</code></p><p> <code>"brand": "Ford",</code></p><p> <code>"model": "Mustang",</code></p><p> <code>"year": 1964</code></p><p><code>}</code></p><p><code>thisdict['brand']</code></p>                                                                                               |
| Updating Elements   | <p><code>thisdict = {</code></p><p> <code>"brand": "Ford",</code></p><p> <code>"model": "Mustang",</code></p><p> <code>"year": 1964</code></p><p><code>}</code></p><p><code>thisdict['brand'] = 'Chevy'</code></p>                                                                                     |
| Enumerating Keys    | <p><code>thisdict = {</code></p><p> <code>"brand": "Ford",</code></p><p> <code>"model": "Mustang",</code></p><p> <code>"year": 1964</code></p><p><code>}</code></p><p><code>for x in thisdict:</code></p><p> <code>print(x)</code></p>                                                                 |
| Enumerating Values  | <p><code>thisdict = {</code></p><p> <code>"brand": "Ford",</code></p><p> <code>"model": "Mustang",</code></p><p> <code>"year": 1964</code></p><p><code>}</code></p><p><code>for x in thisdict.values():</code></p><p> <code>print(x)</code></p>                                                        |
| Check if key exists | <p><code>thisdict = {</code></p><p> <code>"brand": "Ford",</code></p><p> <code>"model": "Mustang",</code></p><p> <code>"year": 1964</code></p><p><code>}</code></p><p><code>if "model" in thisdict:</code></p><p> <code>print("Yes, 'model' is one of the keys in the thisdict dictionary")</code></p> |
| Adding items        | <p><code>thisdict = {</code></p><p> <code>"brand": "Ford",</code></p><p> <code>"model": "Mustang",</code></p><p> <code>"year": 1964</code></p><p><code>}</code></p><p><code>thisdict["color"] = "red"</code></p>                                                                                       |
{% endtab %}

{% tab title="PowerShell" %}
| **Activity**        | Code Examples                                                                                                                                                                                                                                                                                                                                                 |
| ------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Defining            | <p><code>$thisdict = @{</code></p><p> <code>brand = "Ford"</code></p><p> <code>model = "Mustang"</code></p><p> <code>year = 1964</code></p><p><code>}</code></p>                                                                                                                                                                                              |
| Accessing Elements  | <p><code>$thisdict = @{</code></p><p> <code>brand = "Ford"</code></p><p> <code>model = "Mustang"</code></p><p> <code>year = 1964</code></p><p><code>}</code></p><p><code>$thisdict.brand</code></p><p>&#x3C;code>&#x3C;/code></p><p><code>or</code></p><p>&#x3C;code>&#x3C;/code></p><p><code>$thisdict['brand']</code></p>                                   |
| Updating Elements   | <p><code>$thisdict = @{</code></p><p> <code>brand = "Ford"</code></p><p> <code>model = "Mustang"</code></p><p> <code>year = 1964</code></p><p><code>}</code></p><p><code>$thisdict.brand = 'Chevy'</code></p>                                                                                                                                                 |
| Enumerating Keys    | <p><code>$thisdict = @{</code></p><p> <code>brand = "Ford"</code></p><p> <code>model = "Mustang"</code></p><p> <code>year = 1964</code></p><p><code>}</code></p><p><code>$thisdict.Keys | ForEach-Object {</code></p><p> <code>$_</code></p><p><code>}</code></p>                                                                                             |
| Enumerating Values  | <p><code>$thisdict = @{</code></p><p> <code>brand = "Ford"</code></p><p> <code>model = "Mustang"</code></p><p> <code>year = 1964</code></p><p><code>}</code></p><p><code>$thisdict.Values | ForEach-Object {</code></p><p> <code>$_</code></p><p><code>}</code></p>                                                                                           |
| Check if key exists | <p><code>$thisdict = @{</code></p><p> <code>brand = "Ford"</code></p><p> <code>model = "Mustang"</code></p><p> <code>year = 1964</code></p><p><code>}</code></p><p><code>if ($thisdict.ContainsKey("model"))</code></p><p><code>{</code></p><p> <code>Write-Host "Yes, 'model' is one of the keys in the thisdict dictionary"</code></p><p><code>}</code></p> |
| Adding items        | <p><code>$thisdict = @{</code></p><p> <code>brand = "Ford"</code></p><p> <code>model = "Mustang"</code></p><p> <code>year = 1964</code></p><p><code>}</code></p><p><code>$thisdict.color = 'red'</code></p>                                                                                                                                                   |
{% endtab %}

{% tab title="Bash" %}
TODO: this

| **Activity**        | Code Examples |
| ------------------- | ------------- |
| Defining            |               |
| Accessing Elements  |               |
| Updating Elements   |               |
| Enumerating Keys    |               |
| Enumerating Values  |               |
| Check if key exists |               |
| Adding items        |               |

### Defining a dictionary

```bash
declare -A sounds
```

```bash
sounds[dog]="bark"
sounds[cow]="moo"
sounds[bird]="tweet"
sounds[wolf]="howl"
```

Declares `sound` as a Dictionary object (aka associative array).

### Working with dictionaries

```bash
echo ${sounds[dog]} # Dog's sound
echo ${sounds[@]}   # All values
echo ${!sounds[@]}  # All keys
echo ${#sounds[@]}  # Number of elements
unset sounds[dog]   # Delete dog
```

### Iteration 

**Iterate over values**

```bash
for val in "${sounds[@]}"; do
  echo $val
done
```

**Iterate over keys**

```bash
for key in "${!sounds[@]}"; do
  echo $key
done
```
{% endtab %}

{% tab title="CMD .bat" %}
TODO: this

| **Activity**        | Code Examples |
| ------------------- | ------------- |
| Defining            |               |
| Accessing Elements  |               |
| Updating Elements   |               |
| Enumerating Keys    |               |
| Enumerating Values  |               |
| Check if key exists |               |
| Adding items        |               |

## Creating Structures in Arrays

Structures can also be implemented in batch files using a little bit of an extra coding for implementation. The following example shows how this can be achieved.

### Example

```bat
@echo off 
set len = 3 
set obj[0].Name = Joe 
set obj[0].ID = 1 
set obj[1].Name = Mark 
set obj[1].ID = 2 
set obj[2].Name = Mohan 
set obj[2].ID = 3 
set i = 0 
:loop 

if %i% equ %len% goto :eof 
set cur.Name= 
set cur.ID=

for /f "usebackq delims==.tokens=1-3" %%j in (`set obj[%i%]`) do ( 
   set cur.%%k=%%l 
) 
echo Name = %cur.Name% 
echo Value = %cur.ID% 
set /a i = %i%+1 
goto loop
```

The following key things need to be noted about the above code:

* Each variable defined using the `set` command has 2 values associated with each index of the array.
* The variable **i** is set to 0 so that we can loop through the structure will the length of the array which is 3.
* We always check for the condition on whether the value of i is equal to the value of **len** and if not, we loop through the code.
* We are able to access each element of the structure using the `obj\[%i%]` notation.

### Output

The above command produces the following output.

```bat
Name = Joe 
Value = 1 
Name = Mark 
Value = 2 
Name = Mohan 
Value = 3
```
{% endtab %}
{% endtabs %}

## Lambdas

{% tabs %}
{% tab title="Python" %}
| Lambda | Code Examples                                                            |
| ------ | ------------------------------------------------------------------------ |
| Lambda | <p><code>x = lambda a : a + 10</code></p><p><code>print(x(5))</code></p> |
{% endtab %}

{% tab title="PowerShell" %}
| Lambda | Code Examples                                                                 |
| ------ | ----------------------------------------------------------------------------- |
| Lambda | <p><code>$x = { param($a) $a + 10 }</code></p><p><code>&#x26; $x 5</code></p> |
{% endtab %}

{% tab title="Bash" %}

This is implemented by creating a basic inline function in bash.

| Lambda | Code Examples               |
| ------ | --------------------------- |
| Lambda | `lambda() { echo $(($1 + 10)); }; lambda 5` |
{% endtab %}

{% tab title="CMD .bat" %}

Batch scripting does not natively support lambda functions. 

| Lambda | Code Examples               |
| ------ | --------------------------- |
| Lambda | `REM Not natively supported in CMD` |
{% endtab %}
{% endtabs %}

## Math Operators

TODO: Add other operator types

{% tabs %}
{% tab title="Python" %}
| Operator       | Code Examples   |
| -------------- | --------------- |
| Addition       | `var = 1 + 1`   |
| Subtraction    | `var = 1 - 1`   |
| Multiplication | `var = 1 * 1`   |
| Division       | `var = 1 / 1`   |
| Modulus        | `var = 1 % 1`   |
| Floor          | `var = 10 // 3` |
| Exponent       | `var = 10 ** 3` |
{% endtab %}

{% tab title="PowerShell" %}
| Operator       | Code Examples                  |
| -------------- | ------------------------------ |
| Addition       | `$var = 1 + 1`                 |
| Subtraction    | `$var = 1 - 1`                 |
| Multiplication | `$var = 1 * 1`                 |
| Division       | `$var = 1 / 1`                 |
| Modulus        | `$var = 1 % 1`                 |
| Floor          | `$var = [Math]::Floor(10 / 3)` |
| Exponent       | `$var = [Math]::Pow(10, 3)`    |
{% endtab %}

{% tab title="Bash" %}
| Operator       | Code Examples               |
| -------------- | --------------------------- |
| Addition       | `echo $((1 + 1))`           |
| Subtraction    | `echo $((1 - 1))`           |
| Multiplication | `echo $((1 * 1))`           |
| Division       | `echo $((1 / 1))`           |
| Modulus        | `echo $((1 % 1))`           |
| Floor          | `echo $((10 / 3))`          |
| Exponent       | `echo $((10 ** 3))`         |
{% endtab %}

{% tab title="CMD .bat" %}

An operator is a symbol that tells the compiler to perform specific mathematical or logical manipulations.

In batch scripting, the following types of operators are possible:

* Arithmetic operators
* Relational operators
* Logical operators
* Assignment operators
* Bitwise operators

## Arithmetic Operators

Batch script language supports the normal Arithmetic operators as any language. Following are the Arithmetic operators available.

[Show Example](https://www.tutorialspoint.com/batch\_script/batch\_script\_arithmetic\_operators.htm)

| Operator | Description                                                       | Example             |
| -------- | ----------------------------------------------------------------- | ------------------- |
| +        | Addition of two operands                                          | 1 + 2 will give 3   |
| −        | Subtracts second operand from the first                           | 2 − 1 will give 1   |
| \*       | Multiplication of both operands                                   | 2 \* 2 will give 4  |
| /        | Division of the numerator by the denominator                      | 3 / 2 will give 1.5 |
| %        | Modulus operator and remainder of after an integer/float division | 3 % 2 will give 1   |

Batch scripts do not natively support Floors or Exponents.

## Relational Operators

Relational operators allow of the comparison of objects. Below are the relational operators available.

[Show Example](https://www.tutorialspoint.com/batch\_script/batch\_script\_relational\_operators.htm)

| Operator | Description                                                                    | Example                |
| -------- | ------------------------------------------------------------------------------ | ---------------------- |
| EQU      | Tests the equality between two objects                                         | 2 EQU 2 will give true |
| NEQ      | Tests the difference between two objects                                       | 3 NEQ 2 will give true |
| LSS      | Checks to see if the left object is less than the right operand                | 2 LSS 3 will give true |
| LEQ      | Checks to see if the left object is less than or equal to the right operand    | 2 LEQ 3 will give true |
| GTR      | Checks to see if the left object is greater than the right operand             | 3 GTR 2 will give true |
| GEQ      | Checks to see if the left object is greater than or equal to the right operand | 3 GEQ 2 will give true |

## Logical Operators

Logical operators are used to evaluate Boolean expressions. Following are the logical operators available.

The batch language is equipped with a full set of Boolean logic operators like AND, OR, XOR, but only for binary numbers. Neither are there any values for TRUE or FALSE. The only logical operator available for conditions is the NOT operator.

[Show Example](https://www.tutorialspoint.com/batch\_script/batch\_script\_logical\_operators.htm)

| Operator | Description                        |
| -------- | ---------------------------------- |
| AND      | This is the logical “and” operator |
| OR       | This is the logical “or” operator  |
| NOT      | This is the logical “not” operator |

## Assignment Operators

Batch Script language also provides assignment operators. Following are the assignment operators available.

[Show Example](https://www.tutorialspoint.com/batch\_script/batch\_script\_assignment\_operators.htm)

| Operator | Description                                                                                        | Example                                                  |
| -------- | -------------------------------------------------------------------------------------------------- | -------------------------------------------------------- |
| +=       | This adds right operand to the left operand and assigns the result to left operand                 | <p>Set /A a = 5</p><p>a += 3</p><p>Output will be 8</p>  |
| -=       | This subtracts the right operand from the left operand and assigns the result to the left operand  | <p>Set /A a = 5</p><p>a -= 3</p><p>Output will be 2</p>  |
| \*=      | This multiplies the right operand with the left operand and assigns the result to the left operand | <p>Set /A a = 5</p><p>a *= 3</p><p>Output will be 15</p> |
| /=       | This divides the left operand with the right operand and assigns the result to the left operand    | <p>Set /A a = 6</p><p>a/ = 3</p><p>Output will be 2</p>  |
| %=       | This takes modulus using two operands and assigns the result to the left operand                   | <p>Set /A a = 5</p><p>a% = 3</p><p>Output will be 2</p>  |

## Bitwise Operators

Bitwise operators are also possible in batch script. Following are the operators available.

[Show Example](https://www.tutorialspoint.com/batch\_script/batch\_script\_bitwise\_operators.htm)

| Operator | Description                                        |
| -------- | -------------------------------------------------- |
| &        | This is the bitwise “and” operator                 |
| \|       | This is the bitwise “or” operator                  |
| ^        | This is the bitwise “xor” or Exclusive or operator |

Following is the truth table showcasing these operators.

| p | q | p & q | p \| q | p ^ q |
| - | - | ----- | ------ | ----- |
| 0 | 0 | 0     | 0      | 0     |
| 0 | 1 | 0     | 1      | 1     |
| 1 | 1 | 1     | 1      | 0     |
| 1 | 0 | 0     | 1      | 1     |
{% endtab %}
{% endtabs %}

## Error Handling

{% tabs %}
{% tab title="Python" %}
| Error Handling | Code Examples                                                                                                                                                                                                                                                                                          |
| -------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| Try/Except     | <p><code>try:</code></p><p> <code>print(x)</code></p><p><code>except:</code></p><p> <code>print("An exception occurred")</code></p>                                                                                                                                                                    |
| Else           | <p><code>try:</code><br><code></code></p><p> <code>print("Hello")</code><br><code></code></p><p><code>except:</code><br><code></code></p><p> <code>print("Something went wrong")</code><br><code></code></p><p><code>else:</code><br><code></code></p><p> <code>print("Nothing went wrong")</code></p> |
| Finally        | <p><code>try:</code></p><p> <code>f = open("file.txt") f.write("Lorum Ipsum")</code></p><p><code>except:</code></p><p> <code>print("Something went wrong when writing to the file")</code></p><p><code>finally:</code></p><p> <code>f.close()</code></p>                                               |
| Raise          | <p><code>x = -1</code></p><p><code>if x &#x3C; 0:</code></p><p> <code>raise Exception("Sorry, no numbers below zero")</code></p>                                                                                                                                                                       |
{% endtab %}

{% tab title="PowerShell" %}
| Error Handling | Code Examples                                                                                                                                                       |
| -------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Try/Catch      | <p><code>try {</code></p><p> <code>Write-Host $x</code></p><p><code>} catch {</code></p><p> <code>Write-Host "An exception ocurred"</code></p><p><code>}</code></p> |
{% endtab %}

{% tab title="Bash" %}
TODO: this

| Error Handling | Code Examples |
| -------------- | ------------- |
| Try/Catch      |               |

### Trap errors

```
trap 'echo Error at about $LINENO' ERR
```

or

```
traperr() {
  echo "ERROR: ${BASH_SOURCE[1]} at about ${BASH_LINENO[0]}"
}

set -o errtrace
trap traperr ERR
```

### Raising errors 

```
myfunc() {
  return 1
}
```

```
if myfunc; then
  echo "success"
else
  echo "failure"
fi
```
{% endtab %}

{% tab title="CMD .bat" %}
TODO: this

| Error Handling | Code Examples |
| -------------- | ------------- |
| Try/Catch      |               |
{% endtab %}
{% endtabs %}

## Shell Command Execution

{% tabs %}
{% tab title="Python" %}

{% endtab %}

{% tab title="PowerShell" %}
To execute regular Windows shell commands (from cmd.exe) in PowerShell, simply type the command the same way you would in the Windows command shell. Some commands may not work in the same way, and some may need the full filename (example: to se a directory listing in cmd.exe `dir` is the command. To use this in PowerShell you would need to specify `dir.exe`.

IEX (Invoke-Expression)
{% endtab %}

{% tab title="Bash" %}
### Shell execution 

```
pwd
echo "I'm in $(pwd)"
echo "I'm in `pwd`"
```
{% endtab %}

{% tab title="CMD .bat" %}

{% endtab %}
{% endtabs %}

## Output Redirection

{% tabs %}
{% tab title="Python" %}

{% endtab %}

{% tab title="PowerShell" %}
## Redirect Standard Error to the nether

```
2>null
```

Many cmdlets also have an `ErrorAction` property

```
-ErrorAction Silent
```
{% endtab %}

{% tab title="Bash" %}
Redirect Standard Error to the nether

```
2>/dev/null
```
{% endtab %}

{% tab title="CMD .bat" %}
There are three universal “files” for keyboard input, printing text on the screen and printing errors on the screen. The “Standard In” file, known as **stdin**, contains the input to the program/script. The “Standard Out” file, known as **stdout**, is used to write output for display on the screen. Finally, the “Standard Err” file, known as **stderr**, contains any error messages for display on the screen.

Each of these three standard files, otherwise known as the standard streams, are referenced using the numbers 0, 1, and 2. Stdin is file 0, stdout is file 1, and stderr is file 2.

## Redirecting Output (Stdout and Stderr)

One common practice in batch files is sending the output of a program to a log file. The > operator sends, or redirects, stdout or stderr to another file. The following example shows how this can be done.

```
Dir C:\ > list.txt
```

In the above example, the **stdout** of the command Dir C: is redirected to the file list.txt.

If you append the number 2 to the redirection filter, then it would redirect the **stderr** to the file lists.txt.

```
Dir C:\ 2> list.txt
```

One can even combine the **stdout** and **stderr** streams using the file number and the '&' prefix. Following is an example.

```
DIR C:\ > lists.txt 2>&1
```

## Suppressing Program Output

The pseudo file NUL is used to discard any output from a program. The following example shows that the output of the command DIR is discarded by sending the output to NUL.

```
Dir C:\ > NUL
```

### Stdin

To work with the Stdin, you have to use a workaround to achieve this. This can be done by redirecting the command prompt's own stdin, called CON.

The following example shows how you can redirect the output to a file called lists.txt. After you execute the below command, the command prompt will take all the input entered by user till it gets an EOF character. Later, it sends all the input to the file lists.txt.

```
TYPE CON > lists.txt
```
{% endtab %}
{% endtabs %}

## HERE docs

In scripting, a heredoc (here document) is a way to feed a block of text into a command or script. It's often used to generate multi-line output or pass structured text to commands like cat, echo, or tee. Some benefits of using HERE docs:

* Simplifies Multi-Line Input – Instead of writing multiple commands, you can provide large text blocks neatly to a single input.
* Improves Readability – Using heredocs makes scripts easier to read and maintain, especially when handling structured data.
* Supports Variable Expansion – In most languages, heredocs allow variables to be expanded dynamically.

{% tabs %}
{% tab title="Python" %}

Python doesn't have a direct heredoc equivalent, but triple-quoted strings (`"""` or `'''`) serve a similar purpose.

```python
text = """This is a multi-line string.
It works like a heredoc."""
print(text)
```

{% endtab %}

{% tab title="PowerShell" %}

PowerShell uses here-strings, which are enclosed in `@"` and `"@`, which support expansion and variables (or `@'` and `'@` for literal strings).

```powershell
$text = @"
This is a PowerShell here-string.
It spans multiple lines.
"@
Write-Output $text
```

**Note**

Here-strings in PowerShell are useful for handling multi-line text, but they come with some limitations:

* Must Start on a New Line – The opening `@"` or `@'` must be on its own line, or PowerShell will throw an error.
* No Indentation for Closing Marker – The closing `"@` or `'@` must start at the very beginning of a line, which can make formatting tricky.
* Limited Formatting Control – Unlike heredocs in Bash, PowerShell here-strings don’t support indentation or trimming whitespace easily.

{% endtab %}

{% tab title="Bash" %}
### Heredoc 

Heredocs in Bash scripting offer several additional benefits, making them a powerful tool for handling multi-line text inputs efficiently:

* Avoids Escape Characters – Unlike inline strings, heredocs allow you to include quotes and special characters without excessive escaping.
* Supports Variable Expansion – Unless explicitly prevented with `<<'EOF'`, heredocs expand variables, making dynamic content generation easier.

```
cat <<HERE
hello
world
HERE
```

Everything between `<<EOF` and `EOF` is treated as input for cat, allowing the script to process multi-line text without needing individual echo statements. `EOF` can be any unique string of ASCII characters.

{% endtab %}

{% tab title="CMD .bat" %}

Batch scripting lacks a true heredoc feature, but workarounds exist using echo and parentheses.

```bat
(
echo This is a simulated heredoc.
echo Batch scripting doesn't support heredocs natively.
) > output.txt
```

{% endtab %}
{% endtabs %}

## Package Management

{% tabs %}
{% tab title="Python" %}

| Activity      | Code Examples |
|--------------|--------------|
| Install      | `pip install <package-name>` |
| Import       | `import <package-name>` |
| List         | `pip list` |
| Update       | `pip install --upgrade <package-name>` |
| Uninstall    | `pip uninstall <package-name>` |
| Search       | `pip search <package-name>` (Deprecated, use `pip install <package-name>` to check availability) |
| Show Details | `pip show <package-name>` |
| Freeze       | `pip freeze` (Lists installed packages in a format suitable for requirements.txt) |

You can also check out [this guide](https://packaging.python.org/en/latest/tutorials/packaging-projects/) for more details!

{% endtab %}

{% tab title="PowerShell" %}

| Activity      | Code Examples |
|--------------|--------------|
| Install      | `Install-Package <package-name>` - PowerShell | Microsoft Learn](https://learn.microsoft.com/en-us/powershell/module/packagemanagement/install-package?view=powershellget-2.x) |
| Import       | `Import-Module <module-name>` |
| List         | `Get-Package` - PowerShell | Microsoft Learn](https://learn.microsoft.com/en-us/powershell/module/packagemanagement/get-package?view=powershellget-2.x) |
| Update       | `Update-Package <package-name>` |
| Uninstall    | `Uninstall-Package <package-name>` |
| Search       | `Find-Package <package-name>` |
| Show Details | `Get-Package -Name <package-name>` |

PowerShell uses **PackageManagement** to handle software packages, and it supports multiple providers like NuGet and Chocolatey. 

{% endtab %}

{% tab title="Winget" %}

### Winget package management

Winget is used for managing applications on Windows, similar to package managers on Linux and macOS. 

| Activity      | Code Examples |
|--------------|--------------|
| Install      | `winget install <package-name>` |
| List         | `winget list` |
| Update       | `winget upgrade <package-name>` |
| Update All   | `winget upgrade --all` |
| Uninstall    | `winget uninstall <package-name>` |
| Search       | `winget search <package-name>` |
| Show Details | `winget show <package-name>` |

You can find more details on Winget commands [here](https://learn.microsoft.com/en-us/windows/package-manager/winget/). 

{% endtab %}

{% tab title="Chocolatey" %}

### Chocolatey package management

Chocolatey is a powerful package manager for Windows, making software installation and updates much more efficient. 

| Activity      | Code Examples |
|--------------|--------------|
| Install      | `choco install <package-name>` |
| List         | `choco list --local-only` |
| Update       | `choco upgrade <package-name>` |
| Update All   | `choco upgrade all` |
| Uninstall    | `choco uninstall <package-name>` |
| Search       | `choco search <package-name>` |
| Show Details | `choco info <package-name>` |
| Check for Outdated Packages | `choco outdated` |

You can find more details on Chocolatey commands [here](https://docs.chocolatey.org/en-us/choco/commands/). 

{% endtab %}

{% tab title="Bash" %}

| Activity      | Code Examples |
|--------------|--------------|
| Install      | `sudo apt install <package-name>` (Debian/Ubuntu) <br> `sudo dnf install <package-name>` (Fedora/RHEL) |
| Import       | Not applicable in Bash package management (Packages are installed, not imported) |
| List         | `apt list --installed` (Debian/Ubuntu) <br> `dnf list installed` (Fedora/RHEL) |
| Update       | `sudo apt update` (Debian/Ubuntu) <br> `sudo dnf update` (Fedora/RHEL) |
| Upgrade      | `sudo apt upgrade` (Debian/Ubuntu) <br> `sudo dnf upgrade` (Fedora/RHEL) |
| Remove       | `sudo apt remove <package-name>` (Debian/Ubuntu) <br> `sudo dnf remove <package-name>` (Fedora/RHEL) |
| Search       | `apt search <package-name>` (Debian/Ubuntu) <br> `dnf search <package-name>` (Fedora/RHEL) |
| Clean Cache  | `sudo apt clean` (Debian/Ubuntu) <br> `sudo dnf clean all` (Fedora/RHEL) |

{% endtab %}

{% tab title="CMD .bat" %}

Windows lacks built-in package management, but has a somewhat similar feature using DISM (Deployment Image Servicing and Management) for managing additional features.  These features can also be installed/removed using PowerShell commands as well.

| Activity      | Code Examples |
|--------------|--------------|
| Install Feature | `DISM /Online /Enable-Feature /FeatureName:<feature-name>` |
| Remove Feature  | `DISM /Online /Disable-Feature /FeatureName:<feature-name>` |
| List Installed Features | `DISM /Online /Get-Features` |
| Check Feature Status | `DISM /Online /Get-FeatureInfo /FeatureName:<feature-name>` |
| Install Feature via PowerShell | `Enable-WindowsOptionalFeature -Online -FeatureName <feature-name>` |
| Remove Feature via PowerShell | `Disable-WindowsOptionalFeature -Online -FeatureName <feature-name>` |

You can find more details on managing Windows features [here](https://learn.microsoft.com/en-us/windows/client-management/client-tools/add-remove-hide-features).

{% endtab %}
{% endtabs %}

References

* [https://devhints.io/bash](https://devhints.io/bash)
* [https://wiki.bash-hackers.org/syntax/expansion/cmdsubst](https://wiki.bash-hackers.org/syntax/expansion/cmdsubst)
* [https://www.tutorialspoint.com/batch\_script/batch\_script\_syntax.htm](https://www.tutorialspoint.com/batch\_script/batch\_script\_syntax.htm)
*

If you like this content and would like to see more, please consider [buying me a coffee](https://www.buymeacoffee.com/zweilosec)!
