# Script Language Syntax

TODO: need syntax examples for Bash and Windows Batch scripting (issue [#22](https://github.com/zweilosec/Infosec-Notes/issues/22))

* Add syntax examples for Bash and Windows Batch scripting
* Add example output for all

## Basic syntax examples for Python, PowerShell, Bash, and Windows cmd.exe batch

### Variables

{% tabs %}
{% tab title="Python" %}
TODO: this
| Type                         | Code Examples                                                   |
| ---------------------------- | --------------------------------------------------------------- |
| Standard Variable            | `var = "Hello"`                                                 |
| Global Variable              | <p><code>global var</code></p><p><code>var = "Hello"</code></p> |
| Environment Variables        |                                                                 |
| Retrieving Variable Contents |                                                                 |
{% endtab %}

{% tab title="PowerShell" %}
TODO: this
| Type                         | Code Examples           |
| ---------------------------- | ----------------------- |
| Standard Variable            | `$var = "Hello"`        |
| Global Variable              | `$global:var = "Hello"` |
| Environment Variables        |                         |
| Retrieving Variable Contents |                         |
{% endtab %}

{% tab title="Bash" %}
| Type                         | Code Examples               |
| ---------------------------- | --------------------------- |
| Standard Variable            | `var="Hello"`             |
| Global Variable              | `export var="Hello"`      |
| Environment Variables        | `echo $HOME`                |
| Retrieving Variable Contents | `echo $var`                 |
{% endtab %}

{% tab title="CMD .bat" %}
| Type                         | Code Examples               |
| ---------------------------- | --------------------------- |
| Standard Variable            | `set var=Hello`             |
| Global Variable              | `set var=Hello`             |
| Environment Variables        | `echo %PATH%`               |
| Retrieving Variable Contents | `echo %var%`                |

### Set Command

The other way in which variables can be initialized is via the 'set' command. Following is the syntax of the set command.

#### Syntax

```bat
set /A variable-name=value
```

where,

* **variable-name** is the name of the variable you want to set.
* **value** is the value which needs to be set against the variable.
* **/A –** This switch is used if the value needs to be numeric in nature.

The following example shows a simple way the set command can be used.

#### Example

```bat
@echo off 
set message=Hello World 
echo %message%
```

### Working with Numeric Values

In batch script, it is also possible to define a variable to hold a numeric value. This can be done by using the /A switch.

The following code shows a simple way in which numeric values can be set with the /A switch.

```bat
@echo off 
SET /A a = 5 
SET /A b = 10 
SET /A c = %a% + %b% 
echo %c%
```

### Local vs Global Variables

In any programming language, there is an option to mark variables as having some sort of scope, i.e. the section of code on which they can be accessed. Normally, variable having a global scope can be accessed anywhere from a program whereas local scoped variables have a defined boundary in which they can be accessed.

DOS scripting also has a definition for locally and globally scoped variables. By default, variables are global to your entire command prompt session. Call the SETLOCAL command to make variables local to the scope of your script. After calling SETLOCAL, any variable assignments revert upon calling ENDLOCAL, calling EXIT, or when execution reaches the end of file (EOF) in your script. The following example shows the difference when local and global variables are set in the script.

#### Example

```bat
@echo off 
set globalvar = 5
SETLOCAL
set var = 13145
set /A var = %var% + 5
echo %var%
echo %globalvar%
ENDLOCAL
```

Few key things to note about the above program.

* The 'globalvar' is defined with a global scope and is available throughout the entire script.
* The 'var' variable is defined in a local scope because it is enclosed between a 'SETLOCAL' and 'ENDLOCAL' block. Hence, this variable will be destroyed as soon the 'ENDLOCAL' statement is executed.

### Working with Environment Variables

If you have variables that would be used across batch files, then it is always preferable to use environment variables. Once the environment variable is defined, it can be accessed via the % sign. The following example shows how to see the JAVA\_HOME defined on a system. The JAVA\_HOME variable is a key component that is normally used by a wide variety of applications.

```bat
@echo off 
echo %JAVA_HOME%
```

The output would show the JAVA\_HOME directory which would depend from system to system. Following is an example of an output.

```
C:\Atlassian\Bitbucket\4.0.1\jre
```
{% endtab %}
{% endtabs %}

### Strings

{% tabs %}
{% tab title="Python" %}
| Method                              | Code Examples                                                                                                                                                                                |
| ----------------------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Normal String                       | <p><code>"Hello World"</code></p><p><code>'Hello World'</code></p>                                                                                                                           |
| Empty String                        | <p><code>""</code></p><p><code>''</code></p>                                                                                                                                                 |
| Multiline String                    | <p><code>"""Hello</code></p><p><code>World"""</code></p>                                                                                                                                     |
| Select Character from String        | <p><code>str = 'Hello'</code></p><p><code>str[1]</code></p><p><strong><code># 'e'</code></strong></p>                                                                                        |
| Get Length                          | <p><code>str = 'Hello'</code></p><p><code>len(str)</code></p><p><strong><code># 5</code></strong></p>                                                                                        |
| Remove whitespace at front and back | <p><code>str = ' Hello World '</code></p><p><code>str.strip()</code></p><p><strong><code># 'Hello World'</code></strong></p>                                                                 |
| To Lowercase                        | <p><code>str = 'HELLO WORLD'</code></p><p><code>str.lower()</code></p><p><strong><code># 'hello world'</code></strong></p>                                                                   |
| To Uppercase                        | <p><code>str = 'hello world'</code></p><p><code>str.upper()</code></p><p><strong><code># 'HELLO WORLD'</code></strong></p>                                                                   |
| Replace                             | <p><code>str = 'Hello'</code></p><p><code>str.replace('H', 'Y')</code></p><p><strong><code># 'Yello'</code></strong></p>                                                                     |
| Split                               | <p><code>str = 'Hello, World'</code></p><p><code>str.split(',')</code></p><p><strong><code># ['Hello', ' World']</code></strong></p>                                                         |
| Join                                | <p><code>list = ["Hello", "World"]</code></p><p><code>", ".join(list)</code></p><p><strong><code># 'Hello World'</code></strong></p>                                                         |
| Formatting                          | <p><code>price = 42</code></p><p><code>txt = "The price is {} dollars"</code></p><p><code>print(txt.format(price))</code></p><p><strong><code># The price is 42 dollars</code></strong></p>  |
| Formatting by Index                 | <p><code>price = 42</code></p><p><code>txt = "The price is {0} dollars"</code></p><p><code>print(txt.format(price))</code></p><p><strong><code># The price is 42 dollars</code></strong></p> |
| Formatting Strings                  | <p><code>price = 42</code></p><p><code>f"The price is {price} dollars"</code></p><p><strong><code># The price is 42 dollars</code></strong></p>                                              |
{% endtab %}

{% tab title="PowerShell" %}
| Method                              | Code Examples                                                                                                                                                                           |
| ----------------------------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Normal String                       | <p><code>"Hello World"</code></p><p><code>'Hello World'</code></p>                                                                                                                      |
| Empty String                        | <p><code>""</code></p><p><code>''</code></p>                                                                                                                                            |
| Multiline String                    | <p><code>"Hello</code></p><p><code>World</code></p><p><code>"</code></p>                                                                                                                |
| Select Character from String        | <p><code>$str = 'Hello'</code></p><p><code>$str[1]</code></p><p><strong><code># e</code></strong></p>                                                                                   |
| Get Length                          | <p><code>$str = 'Hello'</code></p><p><code>$str.Length</code></p><p><strong><code># 5</code></strong></p>                                                                               |
| Remove whitespace at front and back | <p><code>$str = ' Hello World '</code></p><p><code>$str.Trim()</code></p><p><strong><code># 'Hello World'</code></strong></p>                                                           |
| To Lowercase                        | <p><code>$str = 'HELLO WORLD'</code></p><p><code>$str.ToLower()</code></p><p><strong><code># hello world</code></strong></p>                                                            |
| To Uppercase                        | <p><code>$str = 'hello world'</code></p><p><code>$str.ToUpper()</code></p><p><strong><code># HELLO WORLD</code></strong></p>                                                            |
| Replace                             | <p><code>$str = 'Hello'</code></p><p><code>$str.Replace('H', 'Y')</code></p><p><strong><code># Yello</code></strong></p>                                                                |
| Split                               | <p><code>'Hello, World' -split ','</code></p><p><strong><code># @('Hello', ' World')</code></strong></p>                                                                                |
| Join                                | <p><code>$array = @("Hello", "World")</code></p><p><code>$array -join ", "</code></p><p><code>[String]::Join(', ', $array)</code></p><p><strong><code># Hello World</code></strong></p> |
| Formatting                          | <p><code>$price = 42</code></p><p><code>$txt = "The price is {0} dollars"</code></p><p><code>$txt -f $price</code></p><p><strong><code># The price is 42 dollars</code></strong></p>    |
| Formatting by Index                 | <p><code>$price = 42</code></p><p><code>$txt = "The price is {0} dollars"</code></p><p><code>$txt -f $price</code></p><p><strong><code># The price is 42 dollars</code></strong></p>    |
| Formatting Strings                  | <p><code>$price = 42</code></p><p><code>$txt = "The price is $price dollars"</code></p><p><strong><code># The price is 42 dollars</code></strong></p>                                   |
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

#### Basics <a href="#basics" id="basics"></a>

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

See: [Parameter expansion](http://wiki.bash-hackers.org/syntax/pe)

```
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

```
STR="Hello world"
echo ${STR:6:5}   # "world"
echo ${STR: -5:5}  # "world"
```

```
SRC="/path/to/foo.cpp"
BASE=${SRC##*/}   #=> "foo.cpp" (basepath)
DIR=${SRC%$BASE}  #=> "/path/to/" (dirpath)
```

#### Default values <a href="#default-values" id="default-values"></a>

| `${FOO:-val}`     | `$FOO`, or `val` if unset (or null)                      |
| ----------------- | -------------------------------------------------------- |
| `${FOO:=val}`     | Set `$FOO` to `val` if unset (or null)                   |
| `${FOO:+val}`     | `val` if `$FOO` is set (and not null)                    |
| `${FOO:?message}` | Show error message and exit if `$FOO` is unset (or null) |

Omitting the `:` removes the (non)nullity checks, e.g. `${FOO-val}` expands to `val` if unset otherwise `$FOO`.

#### Substitution <a href="#substitution" id="substitution"></a>

| `${FOO%suffix}`   | Remove suffix       |
| ----------------- | ------------------- |
| `${FOO#prefix}`   | Remove prefix       |
| `${FOO%%suffix}`  | Remove long suffix  |
| `${FOO##prefix}`  | Remove long prefix  |
| `${FOO/from/to}`  | Replace first match |
| `${FOO//from/to}` | Replace all         |
| `${FOO/%from/to}` | Replace suffix      |
| `${FOO/#from/to}` | Replace prefix      |

#### Substrings <a href="#substrings" id="substrings"></a>

| `${FOO:0:3}`    | Substring _(position, length)_ |
| --------------- | ------------------------------ |
| `${FOO:(-3):3}` | Substring from the right       |

#### Length <a href="#length" id="length"></a>

| `${#FOO}` | Length of `$FOO` |
| --------- | ---------------- |

#### Manipulation <a href="#manipulation" id="manipulation"></a>

```
STR="HELLO WORLD!"
echo ${STR,}   #=> "hELLO WORLD!" (lowercase 1st letter)
echo ${STR,,}  #=> "hello world!" (all lowercase)

STR="hello world!"
echo ${STR^}   #=> "Hello world!" (uppercase 1st letter)
echo ${STR^^}  #=> "HELLO WORLD!" (all uppercase)
```

#### String quotes <a href="#string-quotes" id="string-quotes"></a>

```
NAME="John"
echo "Hi $NAME"  #=> Hi John
echo 'Hi $NAME'  #=> Hi $NAME
```
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

An empty string can be created in DOS Scripting by assigning it no value during it's initialization as shown in the following example.

```
Set a=
```

To check for an existence of an empty string, you need to encompass the variable name in square brackets and also compare it against a value in square brackets as shown in the following example.

```
[%a%]==[]
```

The following example shows how an empty string can be created and how to check for the existence of an empty string.

### Example

```bat
@echo off 
SET a= 
SET b=Hello 
if [%a%]==[] echo "String A is empty" 
if [%b%]==[] echo "String B is empty "
```

A string can be created in DOS in the following way.

### Example

```bat
@echo off 
:: This program just displays Hello World 
set message = Hello World 
echo %message%
```
{% endtab %}
{% endtabs %}

### Type Casting

{% tabs %}
{% tab title="Python" %}
TODO:
| Type       | Code Examples       |
| ---------- | ------------------- |
| As Integer | `i = int("10")`     |
| As Float   | `i = float("10.5")` |
| As String  | `i = str(10)`       |
| As Char    |                     |
{% endtab %}

{% tab title="PowerShell" %}
TODO:
| Type       | Code Examples        |
| ---------- | -------------------- |
| As Integer | `$i = [int]"10"`     |
| As Float   | `$i = [float]"10.5"` |
| As String  | `$i = [string]10`    |
| As Char    |                      |
{% endtab %}

{% tab title="Bash" %}
| Type       | Code Examples               |
| ---------- | --------------------------- |
| As Integer | `var=$((10))`               |
| As Float   | `var=$(echo "10.5" | bc)` |
| As String  | `var="10"`                |
| As Char    | `var="a"`                 |
{% endtab %}

{% tab title="CMD .bat" %}
| Type       | Code Examples               |
| ---------- | --------------------------- |
| As Integer | `set /A var=10`             |
| As Float   | `REM Not natively supported`|
| As String  | `set var=10`                |
| As Char    | `set var=a`                 |
{% endtab %}
{% endtabs %}

### Arrays

{% tabs %}
{% tab title="Python" %}
| Activity                | Code examples                                                                                                        |
| ----------------------- | -------------------------------------------------------------------------------------------------------------------- |
| Define                  | `['Hello', 'World']`                                                                                                 |
| Access Elements         | <p><code>arr = ['Hello', 'World']</code></p><p><code>arr[0]</code></p><p><strong><code># 'Hello'</code></strong></p> |
| Get Length              | <p><code>arr = ['Hello', 'World']</code></p><p><code>len(arr)</code></p>                                             |
| Adding Elements         | <p><code>arr = ['Hello', 'the']</code></p><p><code>arr.append('World')</code></p>                                    |
| Removing Elements       | <p><code>arr = ['Hello', 'World']</code></p><p><code>arr.pop(1)</code></p>                                           |
| Remove Element by Value | <p><code>arr = ['Hello', 'World']</code></p><p><code>arr.remove('Hello')</code></p>                                  |
{% endtab %}

{% tab title="PowerShell" %}
| Activity                | Code examples                                                                                                                 |
| ----------------------- | ----------------------------------------------------------------------------------------------------------------------------- |
| Define                  | `@('Hello', 'World')`                                                                                                         |
| Access Elements         | <p><code>$arr = @('Hello', 'World')</code></p><p><code>$arr[0]</code></p><p><strong><code># Hello</code></strong></p>         |
| Get Length              | <p><code>$arr = @('Hello', 'World')</code></p><p><code>$arr.Length</code></p>                                                 |
| Adding Elements         | <p><code>$arr = @('Hello', 'the')</code></p><p><code>$arr += "World"</code></p>                                               |
| Removing Elements       | <p><code>$arr = [System.Collections.ArrayList]@('Hello', 'World')</code></p><p><code>$arr.RemoveAt($arr.Count - 1)</code></p> |
| Remove Element by Value | <p><code>$arr = [System.Collections.ArrayList]@('Hello', 'World')</code></p><p><code>$arr.Remove("Hello")</code></p>          |
{% endtab %}

{% tab title="Bash" %}

| Activity                | Code examples               |
| ----------------------- | --------------------------- |
| Define                  | `arr=("Hello" "World")` |
| Access Elements         | `echo ${arr[0]}`           |
| Get Length              | `echo ${#arr[@]}`          |
| Adding Elements         | `arr+=("NewElement")`    |
| Removing Elements       | `unset arr[1]`             |
| Remove Element by Value | `arr=("${arr[@]/World}")`|


#### Working with arrays <a href="#working-with-arrays" id="working-with-arrays"></a>

```
echo ${Fruits[0]}           # Element #0
echo ${Fruits[-1]}          # Last element
echo ${Fruits[@]}           # All elements, space-separated
echo ${#Fruits[@]}          # Number of elements
echo ${#Fruits}             # String length of the 1st element
echo ${#Fruits[3]}          # String length of the Nth element
echo ${Fruits[@]:3:2}       # Range (from position 3, length 2)
echo ${!Fruits[@]}          # Keys of all elements, space-separated
```

#### Operations <a href="#operations" id="operations"></a>

```
Fruits=("${Fruits[@]}" "Watermelon")    # Push
Fruits+=('Watermelon')                  # Also Push
Fruits=( ${Fruits[@]/Ap*/} )            # Remove by regex match
unset Fruits[2]                         # Remove one item
Fruits=("${Fruits[@]}")                 # Duplicate
Fruits=("${Fruits[@]}" "${Veggies[@]}") # Concatenate
lines=(`cat "logfile"`)                 # Read from file
```

#### Iteration <a href="#iteration" id="iteration"></a>

```
for i in "${arrayName[@]}"; do
  echo $i
done
```

#### Defining arrays <a href="#defining-arrays" id="defining-arrays"></a>

```
Fruits=('Apple' 'Banana' 'Orange')
```

```
Fruits[0]="Apple"
Fruits[1]="Banana"
Fruits[2]="Orange"
```
{% endtab %}

{% tab title="CMD .bat" %}

| Activity                | Code examples               |
| ----------------------- | --------------------------- |
| Define                  | `set arr[0]=Hello`         |
| Access Elements         | `echo %arr[0]%`            |
| Get Length              | `set count=0 & for /L %%i in (0,1,9) do if defined arr[%%i] set /A count+=1 & echo %count%` |
| Adding Elements         | `set arr[1]=World`         |
| Removing Elements       | `set arr[1]=`              |
| Remove Element by Value | `for /F "tokens=*" %%i in ('set arr') do if not "%%i"=="World" echo %%i` |

Arrays are not specifically defined as a type in Batch Script but can be implemented. The following things need to be noted when arrays are implemented in Batch Script.

* Each element of the array needs to be defined with the set command.
* The 'for' loop would be required to iterate through the values of the array.

### Creating an Array

An array is created by using the `set` command.

```
set a[0]=1
```

Where 0 is the index of the array and 1 is the value assigned to the first element of the array.

Another way to implement arrays is to define a list of values and iterate through the list of values. The following example show how this can be implemented.

#### Example

```bat
@echo off 
set list = 1 2 3 4 
(for %%a in (%list%) do ( 
   echo %%a 
))
```

#### Output

The above command produces the following output.

```
1
2
3
4
```

### Accessing Arrays

You can retrieve a value from the array by using subscript syntax, passing the index of the value you want to retrieve within square brackets immediately after the name of the array.

#### Example

```bat
@echo off 
set a[0]=1 
echo %a[0]%
```

Indexes start from 0 which means the first element can be accessed using index 0, the second element can be accessed using index 1 and so on. 

```bat
@echo off
set a[0] = 1 
set a[1] = 2 
set a[2] = 3 
echo The first element of the array is %a[0]% 
echo The second element of the array is %a[1]% 
echo The third element of the array is %a[2]%
```

The above command produces the following output.

```
The first element of the array is 1 
The second element of the array is 2 
The third element of the array is 3
```

### Modifying an Array

To add an element to the end of the array, you can use the `set` command along with the new final index of the array element.  There is no append function as in other languages.

#### Example

```bat
@echo off 
set a[0] = 1  
set a[1] = 2  
set a[2] = 3 
Rem Adding an element at the end of an array 
Set a[3] = 4 
echo The last element of the array is %a[3]%
```

The above command produces the following output.

```
The last element of the array is 4
```

You can modify an existing element of an Array by assigning a new value at a given index.

```bat
@echo off 
set a[0] = 1 
set a[1] = 2  
set a[2] = 3 
Rem Setting the new value for the second element of the array 
Set a[1] = 5 
echo The new value of the second element of the array is %a[1]%
```

The above command produces the following output.

```
The new value of the second element of the array is 5
```

### Iterating Over an Array

Iterating over an array is achieved by using a 'for' loop and stepping through each element of the array. 

```bat
@echo off 
setlocal enabledelayedexpansion 
set topic[0] = comments 
set topic[1] = variables 
set topic[2] = Arrays 
set topic[3] = Decision making 
set topic[4] = Time and date 
set topic[5] = Operators 

for /l %%n in (0,1,5) do ( 
   echo !topic[%%n]! 
)
```

**Notes:****

* Each element of the array needs to be specifically defined using the set command.
* The 'for' loop with the /L parameter for moving through ranges is used to iterate through the array.

#### Output

The above command produces the following output.

```
Comments 
variables 
Arrays 
Decision making 
Time and date 
Operators
```

### Length of an Array

The length of an array is found by iterating over the list of values in the array since there is no direct function to determine the number of elements in an array.

```bat
@echo off 
set Arr[0] = 1 
set Arr[1] = 2 
set Arr[2] = 3 
set Arr[3] = 4 
set "x = 0" 
:SymLoop 

if defined Arr[%x%] ( 
   call echo %%Arr[%x%]%% 
   set /a "x+=1"
   GOTO :SymLoop 
)
echo "The length of the array is" %x%
```

#### Output

Output The above command produces the following output.

```
The length of the array is 4
```
{% endtab %}
{% endtabs %}

### Conditionals

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

#### Case/switch <a href="#caseswitch" id="caseswitch"></a>

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

### Checking Variables

One of the common uses for the 'if' statement in Batch Script is for checking variables which are set in the Batch Script itself. The evaluation of the 'if' statement can be done for both strings and numbers.

#### Checking Integer Variables

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

#### Checking String Variables

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

### Loops

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

#### Basic for loop <a href="#basic-for-loop" id="basic-for-loop"></a>

```bash
for i in /etc/rc.*; do
  echo $i
done
```

#### C-like for loop <a href="#c-like-for-loop" id="c-like-for-loop"></a>

```bash
for ((i = 0 ; i < 100 ; i++)); do
  echo $i
done
```

#### Ranges <a href="#ranges" id="ranges"></a>

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

#### Reading lines <a href="#reading-lines" id="reading-lines"></a>

```bash
cat file.txt | while read line; do
  echo $line
done
```

#### Forever <a href="#forever" id="forever"></a>

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

### Loops

In the decision making chapter, we have seen statements which have been executed one after the other in a sequential manner. Additionally, implementations can also be done in Batch Script to alter the flow of control in a program's logic. They are then classified into flow of control statements.

### `While` Statement Implementation

There is no direct `while` statement available in Batch Scripting but we can do an implementation of this loop very easily by using the if statement and labels.

The first part of the while implementation is to set the counters which will be used to control the evaluation of the 'if' condition. We then define our label which will be used to embody the entire code for the while loop implementation. The 'if' condition evaluates an expression. If the expression evaluates to true, the code block is executed. If the condition evaluates to false then the loop is exited. When the code block is executed, it will return back to the label statement for execution again.

#### Syntax

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

#### Example

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

### `For` Statement - `List Implementations`

The "FOR" construct offers looping capabilities for batch files. Following is the common construct of the 'for' statement for working with a list of values.

#### Syntax

```bat
FOR %%variable IN list DO do_something
```

The classic 'for' statement consists of the following parts −

* Variable declaration – This step is executed only once for the entire loop and used to declare any variables which will be used within the loop. In Batch Script, the variable declaration is done with the %% at the beginning of the variable name.
* List – This will be the list of values for which the 'for' statement should be executed.
* The do\_something code block is what needs to be executed for each iteration for the list of values.

Following is an example of how the 'goto' statement can be used.

#### Example

```bat
@echo off 
FOR %%F IN (1 2 3 4 5) DO echo %%F
```

The key thing to note about the above program is −

* The variable declaration is done with the %% sign at the beginning of the variable name.
* The list of values is defined after the IN clause.
* The do\_something code is defined after the echo command. Thus for each value in the list, the echo command will be executed.

### Looping through Ranges

The 'for' statement also has the ability to move through a range of values. Following is the general form of the statement.

### Syntax

```bat
FOR /L %%variable IN (lowerlimit,Increment,Upperlimit) DO do_something
```

Where

* The /L switch is used to denote that the loop is used for iterating through ranges.
* Variable declaration – This step is executed only once for the entire loop and used to declare any variables which will be used within the loop. In Batch Script, the variable declaration is done with the %% at the beginning of the variable name.
* The IN list contains of 3 values. The lowerlimit, the increment, and the upperlimit. So, the loop would start with the lowerlimit and move to the upperlimit value, iterating each time by the Increment value.
* The do\_something code block is what needs to be executed for each iteration.

Following is an example of how the looping through ranges can be carried out.

#### Example

```bat
@ECHO OFF 
FOR /L %%X IN (0,1,5) DO ECHO %%X
```

### Classic for Loop Implementation

Following is the classic 'for' statement which is available in most programming languages.

#### Typical 'for' loop Syntax

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

#### Example

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

### Looping through Command Line Arguments

The 'for' statement can also be used for checking command line arguments. The following example shows how the 'for' statement can be used to loop through the command line arguments.

#### Example

```bat
@ECHO OFF 
:Loop 

IF "%1"=="" GOTO completed 
FOR %%F IN (%1) DO echo %%F 
SHIFT 
GOTO Loop 
:completed
```

#### Output

Let's assume that our above code is stored in a file called Test.bat. The above command will produce the following output if the batch file passes the command line arguments of 1,2 and 3 as Test.bat 1 2 3.

```
1 
2 
3
```

### `Break` Statement Implementation

The break statement is used to alter the flow of control inside loops within any programming language. The break statement is normally used in looping constructs and is used to cause immediate termination of the innermost enclosing loop.

The break statement is used to alter the flow of control inside loops within any programming language. The break statement is normally used in looping constructs and is used to cause immediate termination of the innermost enclosing loop.

The Batch Script language does not have a direct 'for' statement which does a break but this can be implemented by using labels. The following example shows the diagrammatic explanation of the break statement implementation in Batch Script.

#### Example

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

### Functions

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

#### Arguments <a href="#arguments" id="arguments"></a>

Referencing arguments in a bash script:

| `$#` | Number of arguments                   |
| ---- | ------------------------------------- |
| `$*` | All arguments                         |
| `$@` | All arguments, starting from first    |
| `$1` | First argument, `$2` second, etc.     |
| `$_` | Last argument of the previous command |

#### Returning values <a href="#returning-values" id="returning-values"></a>

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

### Classes

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

### Comments

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

#### Comments <a href="#comments" id="comments"></a>

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

### Comments Using the Rem Statement

There are two ways to create comments in Batch Script; one is via the Rem command. Any text which follows the Rem statement will be treated as comments and will not be executed. Following is the general syntax of this statement.

#### Syntax

```bat
Rem This is a comment
```

#### Example

The following example shows a simple way the **Rem** command can be used to explain the function of the code below it.

```bat
@echo off 
Rem This program just displays Hello World 
set message=Hello World 
echo %message%
```

#### Output

The above command produces the following output. You will notice that the line with the Rem statement will not be executed.

```
Hello World
```

#### Notes:

1. `REM` command must be followed by a space or tab character.

2. You may include any symbol in the comments without any restriction.

3. If `ECHO` is in ON state, the comment is displayed on the command prompt. Otherwise, it is ignored.

4. If you want `ECHO` to be ON and you don't want to display the comment line, use an at sign `@` before `REM` command.

5. If you have too many lines of Rem, it could slow down the code, because in the end each line of code in the batch file still needs to be executed.

### Comments Using the :: Statement

The other way to create comments in Batch Script is via the :: command. Any text which follows the :: statement will be treated as comments and will not be executed. Following is the general syntax of this statement.

#### Syntax

```bat
:: This is a comment
```

#### Example

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

### Data Types

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

### Dictionaries

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

#### Defining a dictionary <a href="#defining" id="defining"></a>

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

#### Working with dictionaries <a href="#working-with-dictionaries" id="working-with-dictionaries"></a>

```bash
echo ${sounds[dog]} # Dog's sound
echo ${sounds[@]}   # All values
echo ${!sounds[@]}  # All keys
echo ${#sounds[@]}  # Number of elements
unset sounds[dog]   # Delete dog
```

#### Iteration <a href="#iteration-1" id="iteration-1"></a>

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

### Creating Structures in Arrays

Structures can also be implemented in batch files using a little bit of an extra coding for implementation. The following example shows how this can be achieved.

#### Example

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

#### Output

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

### Lambdas

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

### Math Operators

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

### Arithmetic Operators

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

### Relational Operators

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

### Logical Operators

Logical operators are used to evaluate Boolean expressions. Following are the logical operators available.

The batch language is equipped with a full set of Boolean logic operators like AND, OR, XOR, but only for binary numbers. Neither are there any values for TRUE or FALSE. The only logical operator available for conditions is the NOT operator.

[Show Example](https://www.tutorialspoint.com/batch\_script/batch\_script\_logical\_operators.htm)

| Operator | Description                        |
| -------- | ---------------------------------- |
| AND      | This is the logical “and” operator |
| OR       | This is the logical “or” operator  |
| NOT      | This is the logical “not” operator |

### Assignment Operators

Batch Script language also provides assignment operators. Following are the assignment operators available.

[Show Example](https://www.tutorialspoint.com/batch\_script/batch\_script\_assignment\_operators.htm)

| Operator | Description                                                                                        | Example                                                  |
| -------- | -------------------------------------------------------------------------------------------------- | -------------------------------------------------------- |
| +=       | This adds right operand to the left operand and assigns the result to left operand                 | <p>Set /A a = 5</p><p>a += 3</p><p>Output will be 8</p>  |
| -=       | This subtracts the right operand from the left operand and assigns the result to the left operand  | <p>Set /A a = 5</p><p>a -= 3</p><p>Output will be 2</p>  |
| \*=      | This multiplies the right operand with the left operand and assigns the result to the left operand | <p>Set /A a = 5</p><p>a *= 3</p><p>Output will be 15</p> |
| /=       | This divides the left operand with the right operand and assigns the result to the left operand    | <p>Set /A a = 6</p><p>a/ = 3</p><p>Output will be 2</p>  |
| %=       | This takes modulus using two operands and assigns the result to the left operand                   | <p>Set /A a = 5</p><p>a% = 3</p><p>Output will be 2</p>  |

### Bitwise Operators

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

### Error Handling

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

#### Trap errors <a href="#trap-errors" id="trap-errors"></a>

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

#### Raising errors <a href="#raising-errors" id="raising-errors"></a>

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

### Shell Command Execution

{% tabs %}
{% tab title="Python" %}

{% endtab %}

{% tab title="PowerShell" %}
To execute regular Windows shell commands (from cmd.exe) in PowerShell, simply type the command the same way you would in the Windows command shell. Some commands may not work in the same way, and some may need the full filename (example: to se a directory listing in cmd.exe `dir` is the command. To use this in PowerShell you would need to specify `dir.exe`.

IEX (Invoke-Expression)
{% endtab %}

{% tab title="Bash" %}
#### Shell execution <a href="#shell-execution" id="shell-execution"></a>

```
pwd
echo "I'm in $(pwd)"
echo "I'm in `pwd`"
```
{% endtab %}

{% tab title="CMD .bat" %}

{% endtab %}
{% endtabs %}

### Output Redirection

{% tabs %}
{% tab title="Python" %}

{% endtab %}

{% tab title="PowerShell" %}
### Redirect Standard Error to the nether

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

### Redirecting Output (Stdout and Stderr)

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

### Suppressing Program Output

The pseudo file NUL is used to discard any output from a program. The following example shows that the output of the command DIR is discarded by sending the output to NUL.

```
Dir C:\ > NUL
```

#### Stdin

To work with the Stdin, you have to use a workaround to achieve this. This can be done by redirecting the command prompt's own stdin, called CON.

The following example shows how you can redirect the output to a file called lists.txt. After you execute the below command, the command prompt will take all the input entered by user till it gets an EOF character. Later, it sends all the input to the file lists.txt.

```
TYPE CON > lists.txt
```
{% endtab %}
{% endtabs %}

### HERE docs

{% tabs %}
{% tab title="Python" %}

{% endtab %}

{% tab title="PowerShell" %}

{% endtab %}

{% tab title="Bash" %}
#### Heredoc <a href="#heredoc" id="heredoc"></a>

```
cat <<HERE
hello world
HERE
```
{% endtab %}

{% tab title="CMD .bat" %}

{% endtab %}
{% endtabs %}

### Package Management

{% tabs %}
{% tab title="Python" %}
| Activity | Code Examples          |
| -------- | ---------------------- |
| Install  | `pip install requests` |
| Import   | `import requests`      |
| List     | `pip list`             |
{% endtab %}

{% tab title="PowerShell" %}
| Activity | Code Examples               |
| -------- | --------------------------- |
| Install  | `Install-Module Pester`     |
| Import   | `Import-Module Pester`      |
| List     | `Get-Module -ListAvailable` |
{% endtab %}

{% tab title="Bash" %}
TODO: this

| Activity | Code Examples |
| -------- | ------------- |
| Install  |               |
| Import   |               |
| List     |               |
{% endtab %}

{% tab title="CMD .bat" %}
TODO: this

| Activity | Code Examples |
| -------- | ------------- |
| Install  |               |
| Import   |               |
| List     |               |
{% endtab %}
{% endtabs %}

References

* [https://devhints.io/bash](https://devhints.io/bash)
* [https://wiki.bash-hackers.org/syntax/expansion/cmdsubst](https://wiki.bash-hackers.org/syntax/expansion/cmdsubst)
* [https://www.tutorialspoint.com/batch\_script/batch\_script\_syntax.htm](https://www.tutorialspoint.com/batch\_script/batch\_script\_syntax.htm)
*

If you like this content and would like to see more, please consider [buying me a coffee](https://www.buymeacoffee.com/zweilosec)!
