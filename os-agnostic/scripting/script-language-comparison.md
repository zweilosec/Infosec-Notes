# Script Language Syntax

TODO: Add output for all examples

TODO: Add examples for Bash and Windows Batch scripting

## Basic syntax examples for Python, PowerShell, Bash, and Windows cmd.exe batch

### Variables

{% tabs %}
{% tab title="Python" %}
<table>
  <thead>
    <tr>
      <th style="text-align:left">Type</th>
      <th style="text-align:left">Code Examples</th>
    </tr>
  </thead>
  <tbody>
    <tr>
      <td style="text-align:left">Standard Variable</td>
      <td style="text-align:left"><code>var = &quot;Hello&quot;</code>
      </td>
    </tr>
    <tr>
      <td style="text-align:left">Global Variable</td>
      <td style="text-align:left">
        <p><code>global var</code>
        </p>
        <p><code>var = &quot;Hello&quot;</code>
        </p>
      </td>
    </tr>
    <tr>
      <td style="text-align:left">Environment Variables</td>
      <td style="text-align:left"></td>
    </tr>
    <tr>
      <td style="text-align:left">Retrieving Variable Contents</td>
      <td style="text-align:left"></td>
    </tr>
  </tbody>
</table>
{% endtab %}

{% tab title="PowerShell" %}
| Type | Code Examples |
| :--- | :--- |
| Standard Variable | `$var = "Hello"` |
| Global Variable | `$global:var = "Hello"` |
| Environment Variables |  |
| Retrieving Variable Contents |  |
{% endtab %}

{% tab title="Bash" %}
TODO: this

| Type | Code Examples |
| :--- | :--- |
| Standard Variable |  |
| Global Variable |  |
| Environment Variables |  |
| Retrieving Variable Contents |  |
{% endtab %}

{% tab title="CMD .bat" %}
TODO: this

| Type | Code Examples |
| :--- | :--- |
| Standard Variable |  |
| Global Variable |  |
| Environment Variables |  |
| Retrieving Variable Contents |  |



### Set Command

The other way in which variables can be initialized is via the ‘set’ command. Following is the syntax of the set command.

#### Syntax

```text
set /A variable-name=value
```

where,

* **variable-name** is the name of the variable you want to set.
* **value** is the value which needs to be set against the variable.
* **/A –** This switch is used if the value needs to be numeric in nature.

The following example shows a simple way the set command can be used.

#### Example

```text
@echo off 
set message=Hello World 
echo %message%
```



### Working with Numeric Values

In batch script, it is also possible to define a variable to hold a numeric value. This can be done by using the /A switch.

The following code shows a simple way in which numeric values can be set with the /A switch.

```text
@echo off 
SET /A a = 5 
SET /A b = 10 
SET /A c = %a% + %b% 
echo %c%
```



### Local vs Global Variables

In any programming language, there is an option to mark variables as having some sort of scope, i.e. the section of code on which they can be accessed. Normally, variable having a global scope can be accessed anywhere from a program whereas local scoped variables have a defined boundary in which they can be accessed.

DOS scripting also has a definition for locally and globally scoped variables. By default, variables are global to your entire command prompt session. Call the SETLOCAL command to make variables local to the scope of your script. After calling SETLOCAL, any variable assignments revert upon calling ENDLOCAL, calling EXIT, or when execution reaches the end of file \(EOF\) in your script. The following example shows the difference when local and global variables are set in the script.

#### Example

```text
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

* The ‘globalvar’ is defined with a global scope and is available throughout the entire script.
* The ‘var‘ variable is defined in a local scope because it is enclosed between a ‘SETLOCAL’ and ‘ENDLOCAL’ block. Hence, this variable will be destroyed as soon the ‘ENDLOCAL’ statement is executed.



### Working with Environment Variables

If you have variables that would be used across batch files, then it is always preferable to use environment variables. Once the environment variable is defined, it can be accessed via the % sign. The following example shows how to see the JAVA\_HOME defined on a system. The JAVA\_HOME variable is a key component that is normally used by a wide variety of applications.

```text
@echo off 
echo %JAVA_HOME%
```

The output would show the JAVA\_HOME directory which would depend from system to system. Following is an example of an output.

```text
C:\Atlassian\Bitbucket\4.0.1\jre
```
{% endtab %}
{% endtabs %}

### Strings

{% tabs %}
{% tab title="Python" %}
<table>
  <thead>
    <tr>
      <th style="text-align:left">Method</th>
      <th style="text-align:left">Code Examples</th>
    </tr>
  </thead>
  <tbody>
    <tr>
      <td style="text-align:left">Normal String</td>
      <td style="text-align:left">
        <p><code>&quot;Hello World&quot;</code>
        </p>
        <p><code>&apos;Hello World&apos;</code>
        </p>
      </td>
    </tr>
    <tr>
      <td style="text-align:left">Empty String</td>
      <td style="text-align:left">
        <p><code>&quot;&quot;</code>
        </p>
        <p><code>&apos;&apos;</code>
        </p>
      </td>
    </tr>
    <tr>
      <td style="text-align:left">Multiline String</td>
      <td style="text-align:left">
        <p><code>&quot;&quot;&quot;Hello</code>
        </p>
        <p><code>World&quot;&quot;&quot;</code>
        </p>
      </td>
    </tr>
    <tr>
      <td style="text-align:left">Select Character from String</td>
      <td style="text-align:left">
        <p><code>str = &apos;Hello&apos;</code>
        </p>
        <p><code>str[1]</code>
        </p>
        <p><b><code># &apos;e&apos;</code></b>
        </p>
      </td>
    </tr>
    <tr>
      <td style="text-align:left">Get Length</td>
      <td style="text-align:left">
        <p><code>str = &apos;Hello&apos;</code>
        </p>
        <p><code>len(str)</code>
        </p>
        <p><b><code># 5</code></b>
        </p>
      </td>
    </tr>
    <tr>
      <td style="text-align:left">Remove whitespace at front and back</td>
      <td style="text-align:left">
        <p><code>str = &apos; Hello World &apos;</code>
        </p>
        <p><code>str.strip()</code>
        </p>
        <p><b><code># &apos;Hello World&apos;</code></b>
        </p>
      </td>
    </tr>
    <tr>
      <td style="text-align:left">To Lowercase</td>
      <td style="text-align:left">
        <p><code>str = &apos;HELLO WORLD&apos;</code>
        </p>
        <p><code>str.lower()</code>
        </p>
        <p><b><code># &apos;hello world&apos;</code></b>
        </p>
      </td>
    </tr>
    <tr>
      <td style="text-align:left">To Uppercase</td>
      <td style="text-align:left">
        <p><code>str = &apos;hello world&apos;</code>
        </p>
        <p><code>str.upper()</code>
        </p>
        <p><b><code># &apos;HELLO WORLD&apos;</code></b>
        </p>
      </td>
    </tr>
    <tr>
      <td style="text-align:left">Replace</td>
      <td style="text-align:left">
        <p><code>str = &apos;Hello&apos;</code>
        </p>
        <p><code>str.replace(&apos;H&apos;, &apos;Y&apos;)</code>
        </p>
        <p><b><code># &apos;Yello&apos;</code></b>
        </p>
      </td>
    </tr>
    <tr>
      <td style="text-align:left">Split</td>
      <td style="text-align:left">
        <p><code>str = &apos;Hello, World&apos;</code>
        </p>
        <p><code>str.split(&apos;,&apos;)</code>
        </p>
        <p><b><code># [&apos;Hello&apos;, &apos; World&apos;]</code></b>
        </p>
      </td>
    </tr>
    <tr>
      <td style="text-align:left">Join</td>
      <td style="text-align:left">
        <p><code>list = [&quot;Hello&quot;, &quot;World&quot;]</code>
        </p>
        <p><code>&quot;, &quot;.join(list)</code>
        </p>
        <p><b><code># &apos;Hello World&apos;</code></b>
        </p>
      </td>
    </tr>
    <tr>
      <td style="text-align:left">Formatting</td>
      <td style="text-align:left">
        <p><code>price = 42</code>
        </p>
        <p><code>txt = &quot;The price is {} dollars&quot;</code>
        </p>
        <p><code>print(txt.format(price))</code>
        </p>
        <p><b><code># The price is 42 dollars</code></b>
        </p>
      </td>
    </tr>
    <tr>
      <td style="text-align:left">Formatting by Index</td>
      <td style="text-align:left">
        <p><code>price = 42</code>
        </p>
        <p><code>txt = &quot;The price is {0} dollars&quot;</code>
        </p>
        <p><code>print(txt.format(price))</code>
        </p>
        <p><b><code># The price is 42 dollars</code></b>
        </p>
      </td>
    </tr>
    <tr>
      <td style="text-align:left">Formatting Strings</td>
      <td style="text-align:left">
        <p><code>price = 42</code>
        </p>
        <p><code>f&quot;The price is {price} dollars&quot;</code>
        </p>
        <p><b><code># The price is 42 dollars</code></b>
        </p>
      </td>
    </tr>
  </tbody>
</table>
{% endtab %}

{% tab title="PowerShell" %}
<table>
  <thead>
    <tr>
      <th style="text-align:left">Method</th>
      <th style="text-align:left">Code Examples</th>
    </tr>
  </thead>
  <tbody>
    <tr>
      <td style="text-align:left">Normal String</td>
      <td style="text-align:left">
        <p><code>&quot;Hello World&quot;</code>
        </p>
        <p><code>&apos;Hello World&apos;</code>
        </p>
      </td>
    </tr>
    <tr>
      <td style="text-align:left">Empty String</td>
      <td style="text-align:left">
        <p><code>&quot;&quot;</code>
        </p>
        <p><code>&apos;&apos;</code>
        </p>
      </td>
    </tr>
    <tr>
      <td style="text-align:left">Multiline String</td>
      <td style="text-align:left">
        <p><code>&quot;Hello</code>
        </p>
        <p><code>World</code>
        </p>
        <p><code>&quot;</code>
        </p>
      </td>
    </tr>
    <tr>
      <td style="text-align:left">Select Character from String</td>
      <td style="text-align:left">
        <p><code>$str = &apos;Hello&apos;</code>
        </p>
        <p><code>$str[1]</code>
        </p>
        <p><b><code># e</code></b>
        </p>
      </td>
    </tr>
    <tr>
      <td style="text-align:left">Get Length</td>
      <td style="text-align:left">
        <p><code>$str = &apos;Hello&apos;</code>
        </p>
        <p><code>$str.Length</code>
        </p>
        <p><b><code># 5</code></b>
        </p>
      </td>
    </tr>
    <tr>
      <td style="text-align:left">Remove whitespace at front and back</td>
      <td style="text-align:left">
        <p><code>$str = &apos; Hello World &apos;</code>
        </p>
        <p><code>$str.Trim()</code>
        </p>
        <p><b><code># &apos;Hello World&apos;</code></b>
        </p>
      </td>
    </tr>
    <tr>
      <td style="text-align:left">To Lowercase</td>
      <td style="text-align:left">
        <p><code>$str = &apos;HELLO WORLD&apos;</code>
        </p>
        <p><code>$str.ToLower()</code>
        </p>
        <p><b><code># hello world</code></b>
        </p>
      </td>
    </tr>
    <tr>
      <td style="text-align:left">To Uppercase</td>
      <td style="text-align:left">
        <p><code>$str = &apos;hello world&apos;</code>
        </p>
        <p><code>$str.ToUpper()</code>
        </p>
        <p><b><code># HELLO WORLD</code></b>
        </p>
      </td>
    </tr>
    <tr>
      <td style="text-align:left">Replace</td>
      <td style="text-align:left">
        <p><code>$str = &apos;Hello&apos;</code>
        </p>
        <p><code>$str.Replace(&apos;H&apos;, &apos;Y&apos;)</code>
        </p>
        <p><b><code># Yello</code></b>
        </p>
      </td>
    </tr>
    <tr>
      <td style="text-align:left">Split</td>
      <td style="text-align:left">
        <p><code>&apos;Hello, World&apos; -split &apos;,&apos;</code>
        </p>
        <p><b><code># @(&apos;Hello&apos;, &apos; World&apos;)</code></b>
        </p>
      </td>
    </tr>
    <tr>
      <td style="text-align:left">Join</td>
      <td style="text-align:left">
        <p><code>$array = @(&quot;Hello&quot;, &quot;World&quot;)</code>
        </p>
        <p><code>$array -join &quot;, &quot;</code>
        </p>
        <p><code>[String]::Join(&apos;, &apos;, $array)</code>
        </p>
        <p><b><code># Hello World</code></b>
        </p>
      </td>
    </tr>
    <tr>
      <td style="text-align:left">Formatting</td>
      <td style="text-align:left">
        <p><code>$price = 42</code>
        </p>
        <p><code>$txt = &quot;The price is {0} dollars&quot;</code>
        </p>
        <p><code>$txt -f $price</code>
        </p>
        <p><b><code># The price is 42 dollars</code></b>
        </p>
      </td>
    </tr>
    <tr>
      <td style="text-align:left">Formatting by Index</td>
      <td style="text-align:left">
        <p><code>$price = 42</code>
        </p>
        <p><code>$txt = &quot;The price is {0} dollars&quot;</code>
        </p>
        <p><code>$txt -f $price</code>
        </p>
        <p><b><code># The price is 42 dollars</code></b>
        </p>
      </td>
    </tr>
    <tr>
      <td style="text-align:left">Formatting Strings</td>
      <td style="text-align:left">
        <p><code>$price = 42</code>
        </p>
        <p><code>$txt = &quot;The price is $price dollars&quot;</code>
        </p>
        <p><b><code># The price is 42 dollars</code></b>
        </p>
      </td>
    </tr>
  </tbody>
</table>
{% endtab %}

{% tab title="Bash" %}
TODO: this

| Method | Code Examples |
| :--- | :--- |
| Normal String |  |
| Empty String |  |
| Multiline String |  |
| Select Character from String |  |
| Get Length |  |
| Remove whitespace at front and back |  |
| To Lowercase |  |
| To Uppercase |  |
| Replace |  |
| Split |  |
| Join |  |
| Formatting |  |
| Formatting by Index |  |
| Formatting Strings |  |



#### Basics <a id="basics"></a>

```text
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

```text
length=2
echo ${name:0:length}  #=> "Jo"
```

See: [Parameter expansion](http://wiki.bash-hackers.org/syntax/pe)

```text
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

```text
STR="Hello world"
echo ${STR:6:5}   # "world"
echo ${STR: -5:5}  # "world"
```

```text
SRC="/path/to/foo.cpp"
BASE=${SRC##*/}   #=> "foo.cpp" (basepath)
DIR=${SRC%$BASE}  #=> "/path/to/" (dirpath)
```

#### Default values <a id="default-values"></a>

| `${FOO:-val}` | `$FOO`, or `val` if unset \(or null\) |
| :--- | :--- |
| `${FOO:=val}` | Set `$FOO` to `val` if unset \(or null\) |
| `${FOO:+val}` | `val` if `$FOO` is set \(and not null\) |
| `${FOO:?message}` | Show error message and exit if `$FOO` is unset \(or null\) |

Omitting the `:` removes the \(non\)nullity checks, e.g. `${FOO-val}` expands to `val` if unset otherwise `$FOO`.

#### Substitution <a id="substitution"></a>

| `${FOO%suffix}` | Remove suffix |
| :--- | :--- |
| `${FOO#prefix}` | Remove prefix |
| `${FOO%%suffix}` | Remove long suffix |
| `${FOO##prefix}` | Remove long prefix |
| `${FOO/from/to}` | Replace first match |
| `${FOO//from/to}` | Replace all |
| `${FOO/%from/to}` | Replace suffix |
| `${FOO/#from/to}` | Replace prefix |

####  <a id="comments"></a>

#### Substrings <a id="substrings"></a>

| `${FOO:0:3}` | Substring _\(position, length\)_ |
| :--- | :--- |
| `${FOO:(-3):3}` | Substring from the right |

#### Length <a id="length"></a>

| `${#FOO}` | Length of `$FOO` |
| :--- | :--- |


#### Manipulation <a id="manipulation"></a>

```text
STR="HELLO WORLD!"
echo ${STR,}   #=> "hELLO WORLD!" (lowercase 1st letter)
echo ${STR,,}  #=> "hello world!" (all lowercase)

STR="hello world!"
echo ${STR^}   #=> "Hello world!" (uppercase 1st letter)
echo ${STR^^}  #=> "HELLO WORLD!" (all uppercase)
```

#### String quotes <a id="string-quotes"></a>

```text
NAME="John"
echo "Hi $NAME"  #=> Hi John
echo 'Hi $NAME'  #=> Hi $NAME
```
{% endtab %}

{% tab title="CMD .bat" %}
TODO: this

| Method | Code Examples |
| :--- | :--- |
| Normal String |  |
| Empty String |  |
| Multiline String |  |
| Select Character from String |  |
| Get Length |  |
| Remove whitespace at front and back |  |
| To Lowercase |  |
| To Uppercase |  |
| Replace |  |
| Split |  |
| Join |  |
| Formatting |  |
| Formatting by Index |  |
| Formatting Strings |  |



An empty string can be created in DOS Scripting by assigning it no value during it’s initialization as shown in the following example.

```text
Set a=
```

To check for an existence of an empty string, you need to encompass the variable name in square brackets and also compare it against a value in square brackets as shown in the following example.

```text
[%a%]==[]
```

The following example shows how an empty string can be created and how to check for the existence of an empty string.

### Example

```text
@echo off 
SET a= 
SET b=Hello 
if [%a%]==[] echo "String A is empty" 
if [%b%]==[] echo "String B is empty "
```

A string can be created in DOS in the following way.

### Example

```text
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
| Type | Code Examples |
| :--- | :--- |
| As Integer | `i = int("10")` |
| As Float | `i = float("10.5")` |
| As String | `i = str(10)` |
| As Char |  |
{% endtab %}

{% tab title="PowerShell" %}
| Type | Code Examples |
| :--- | :--- |
| As Integer | `$i = [int]"10"` |
| As Float | `$i = [float]"10.5"`  |
| As String | `$i = [string]10` |
| As Char |  |
{% endtab %}

{% tab title="Bash" %}
| Type | Code Examples |
| :--- | :--- |
| As Integer |  |
| As Float |  |
| As String |  |
| As Char |  |
{% endtab %}

{% tab title="CMD .bat" %}
| Type | Code Examples |
| :--- | :--- |
| As Integer |  |
| As Float |  |
| As String |  |
| As Char |  |
{% endtab %}
{% endtabs %}

### Arrays

{% tabs %}
{% tab title="Python" %}
<table>
  <thead>
    <tr>
      <th style="text-align:left">Activity</th>
      <th style="text-align:left">Code examples</th>
    </tr>
  </thead>
  <tbody>
    <tr>
      <td style="text-align:left">Define</td>
      <td style="text-align:left"><code>[&apos;Hello&apos;, &apos;World&apos;]</code>
      </td>
    </tr>
    <tr>
      <td style="text-align:left">Access Elements</td>
      <td style="text-align:left">
        <p><code>arr = [&apos;Hello&apos;, &apos;World&apos;]</code>
        </p>
        <p><code>arr[0]</code>
        </p>
        <p><b><code># &apos;Hello&apos;</code></b>
        </p>
      </td>
    </tr>
    <tr>
      <td style="text-align:left">Get Length</td>
      <td style="text-align:left">
        <p><code>arr = [&apos;Hello&apos;, &apos;World&apos;]</code>
        </p>
        <p><code>len(arr)</code>
        </p>
      </td>
    </tr>
    <tr>
      <td style="text-align:left">Adding Elements</td>
      <td style="text-align:left">
        <p><code>arr = [&apos;Hello&apos;, &apos;the&apos;]</code>
        </p>
        <p><code>arr.append(&apos;World&apos;)</code>
        </p>
      </td>
    </tr>
    <tr>
      <td style="text-align:left">Removing Elements</td>
      <td style="text-align:left">
        <p><code>arr = [&apos;Hello&apos;, &apos;World&apos;]</code>
        </p>
        <p><code>arr.pop(1)</code>
        </p>
      </td>
    </tr>
    <tr>
      <td style="text-align:left">Remove Element by Value</td>
      <td style="text-align:left">
        <p><code>arr = [&apos;Hello&apos;, &apos;World&apos;]</code>
        </p>
        <p><code>arr.remove(&apos;Hello&apos;)</code>
        </p>
      </td>
    </tr>
  </tbody>
</table>
{% endtab %}

{% tab title="PowerShell" %}


<table>
  <thead>
    <tr>
      <th style="text-align:left">Activity</th>
      <th style="text-align:left">Code examples</th>
    </tr>
  </thead>
  <tbody>
    <tr>
      <td style="text-align:left">Define</td>
      <td style="text-align:left"><code>@(&apos;Hello&apos;, &apos;World&apos;)</code>
      </td>
    </tr>
    <tr>
      <td style="text-align:left">Access Elements</td>
      <td style="text-align:left">
        <p><code>$arr = @(&apos;Hello&apos;, &apos;World&apos;)</code>
        </p>
        <p><code>$arr[0]</code>
        </p>
        <p><b><code># Hello</code></b>
        </p>
      </td>
    </tr>
    <tr>
      <td style="text-align:left">Get Length</td>
      <td style="text-align:left">
        <p><code>$arr = @(&apos;Hello&apos;, &apos;World&apos;)</code>
        </p>
        <p><code>$arr.Length</code>
        </p>
      </td>
    </tr>
    <tr>
      <td style="text-align:left">Adding Elements</td>
      <td style="text-align:left">
        <p><code>$arr = @(&apos;Hello&apos;, &apos;the&apos;)</code>
        </p>
        <p><code>$arr += &quot;World&quot;</code>
        </p>
      </td>
    </tr>
    <tr>
      <td style="text-align:left">Removing Elements</td>
      <td style="text-align:left">
        <p><code>$arr = [System.Collections.ArrayList]@(&apos;Hello&apos;, &apos;World&apos;)</code>
        </p>
        <p><code>$arr.RemoveAt($arr.Count - 1)</code>
        </p>
      </td>
    </tr>
    <tr>
      <td style="text-align:left">Remove Element by Value</td>
      <td style="text-align:left">
        <p><code>$arr = [System.Collections.ArrayList]@(&apos;Hello&apos;, &apos;World&apos;)</code>
        </p>
        <p><code>$arr.Remove(&quot;Hello&quot;)</code>
        </p>
      </td>
    </tr>
  </tbody>
</table>
{% endtab %}

{% tab title="Bash" %}
TODO: this

| Activity | Code examples |
| :--- | :--- |
| Define |  |
| Access Elements |  |
| Get Length |  |
| Adding Elements |  |
| Removing Elements |  |
| Remove Element by Value |  |



#### Working with arrays <a id="working-with-arrays"></a>

```text
echo ${Fruits[0]}           # Element #0
echo ${Fruits[-1]}          # Last element
echo ${Fruits[@]}           # All elements, space-separated
echo ${#Fruits[@]}          # Number of elements
echo ${#Fruits}             # String length of the 1st element
echo ${#Fruits[3]}          # String length of the Nth element
echo ${Fruits[@]:3:2}       # Range (from position 3, length 2)
echo ${!Fruits[@]}          # Keys of all elements, space-separated
```

#### Operations <a id="operations"></a>

```text
Fruits=("${Fruits[@]}" "Watermelon")    # Push
Fruits+=('Watermelon')                  # Also Push
Fruits=( ${Fruits[@]/Ap*/} )            # Remove by regex match
unset Fruits[2]                         # Remove one item
Fruits=("${Fruits[@]}")                 # Duplicate
Fruits=("${Fruits[@]}" "${Veggies[@]}") # Concatenate
lines=(`cat "logfile"`)                 # Read from file
```

#### Iteration <a id="iteration"></a>

```text
for i in "${arrayName[@]}"; do
  echo $i
done
```

#### Defining arrays <a id="defining-arrays"></a>

```text
Fruits=('Apple' 'Banana' 'Orange')
```

```text
Fruits[0]="Apple"
Fruits[1]="Banana"
Fruits[2]="Orange"
```
{% endtab %}

{% tab title="CMD .bat" %}
TODO: this

| Activity | Code examples |
| :--- | :--- |
| Define |  |
| Access Elements |  |
| Get Length |  |
| Adding Elements |  |
| Removing Elements |  |
| Remove Element by Value |  |



Arrays are not specifically defined as a type in Batch Script but can be implemented. The following things need to be noted when arrays are implemented in Batch Script.

* Each element of the array needs to be defined with the set command.
* The ‘for’ loop would be required to iterate through the values of the array.

### Creating an Array

An array is created by using the following set command.

```text
set a[0]=1
```

Where 0 is the index of the array and 1 is the value assigned to the first element of the array.

Another way to implement arrays is to define a list of values and iterate through the list of values. The following example show how this can be implemented.

#### Example

```text
@echo off 
set list = 1 2 3 4 
(for %%a in (%list%) do ( 
   echo %%a 
))
```

#### Output

The above command produces the following output.

```text
1
2
3
4
```

### Accessing Arrays

You can retrieve a value from the array by using subscript syntax, passing the index of the value you want to retrieve within square brackets immediately after the name of the array.

#### Example

```text
@echo off 
set a[0]=1 
echo %a[0]%
```

In this example, the index starts from 0 which means the first element can be accessed using index as 0, the second element can be accessed using index as 1 and so on. Let's check the following example to create, initialize and access arrays −

```text
@echo off
set a[0] = 1 
set a[1] = 2 
set a[2] = 3 
echo The first element of the array is %a[0]% 
echo The second element of the array is %a[1]% 
echo The third element of the array is %a[2]%
```

The above command produces the following output.

```text
The first element of the array is 1 
The second element of the array is 2 
The third element of the array is 3
```

### Modifying an Array

To add an element to the end of the array, you can use the set element along with the last index of the array element.

#### Example

```text
@echo off 
set a[0] = 1  
set a[1] = 2  
set a[2] = 3 
Rem Adding an element at the end of an array 
Set a[3] = 4 
echo The last element of the array is %a[3]%
```

The above command produces the following output.

```text
The last element of the array is 4
```

You can modify an existing element of an Array by assigning a new value at a given index as shown in the following example −

```text
@echo off 
set a[0] = 1 
set a[1] = 2  
set a[2] = 3 
Rem Setting the new value for the second element of the array 
Set a[1] = 5 
echo The new value of the second element of the array is %a[1]%
```

The above command produces the following output.

```text
The new value of the second element of the array is 5
```

### Iterating Over an Array

Iterating over an array is achieved by using the ‘for’ loop and going through each element of the array. The following example shows a simple way that an array can be implemented.

```text
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

Following things need to be noted about the above program −

* Each element of the array needs to be specifically defined using the set command.
* The ‘for’ loop with the /L parameter for moving through ranges is used to iterate through the array.

#### Output

The above command produces the following output.

```text
Comments 
variables 
Arrays 
Decision making 
Time and date 
Operators
```

### Length of an Array

The length of an array is done by iterating over the list of values in the array since there is no direct function to determine the number of elements in an array.

```text
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

```text
The length of the array is 4
```
{% endtab %}
{% endtabs %}

### Conditionals

{% tabs %}
{% tab title="Python" %}
<table>
  <thead>
    <tr>
      <th style="text-align:left">Switch</th>
      <th style="text-align:left">Code Examples</th>
    </tr>
  </thead>
  <tbody>
    <tr>
      <td style="text-align:left">If / ElseIf / Else</td>
      <td style="text-align:left">
        <p><code>a = 42</code>
        </p>
        <p><code>b = 420</code>
        </p>
        <p><code>if b &gt; a:</code>
        </p>
        <p><code>  print(&quot;b is greater than a&quot;)</code>
        </p>
        <p><code>elif a == b:</code>
        </p>
        <p><code>  print(&quot;a and b are equal&quot;)</code>
        </p>
        <p><code>else:</code>
        </p>
        <p><code>  print(&quot;a is greater than b&quot;)</code>
        </p>
      </td>
    </tr>
    <tr>
      <td style="text-align:left">Case</td>
      <td style="text-align:left"></td>
    </tr>
  </tbody>
</table>
{% endtab %}

{% tab title="PowerShell" %}
<table>
  <thead>
    <tr>
      <th style="text-align:left">Switch</th>
      <th style="text-align:left">Code Examples</th>
    </tr>
  </thead>
  <tbody>
    <tr>
      <td style="text-align:left">If / ElseIf / Else</td>
      <td style="text-align:left">
        <p><code>$a = 42</code>
        </p>
        <p><code>$b = 420</code>
        </p>
        <p><code>if ($b -gt $a)</code>
        </p>
        <p><code>{</code>
        </p>
        <p><code>    Write-Host &quot;b is greater than a&quot;</code>
        </p>
        <p><code>}</code>
        </p>
        <p><code>elseif ($a -eq $b)</code>
        </p>
        <p><code>{</code>
        </p>
        <p><code>    Write-Host &quot;a and b are equal&quot;  </code>
        </p>
        <p><code>}</code>
        </p>
        <p><code>else</code>
        </p>
        <p><code>{</code>
        </p>
        <p><code>  Write-Host &quot;a is greater than b&quot;</code>
        </p>
        <p><code>}</code>
        </p>
      </td>
    </tr>
    <tr>
      <td style="text-align:left">Case</td>
      <td style="text-align:left"></td>
    </tr>
  </tbody>
</table>
{% endtab %}

{% tab title="Bash" %}
TODO: this

| Switch | Code Examples |
| :--- | :--- |
| If / ElseIf / Else |  |
| Case |  |



#### Case/switch <a id="caseswitch"></a>

```text
case "$1" in
  start | up)
    vagrant up
    ;;

  *)
    echo "Usage: $0 {start|stop|ssh}"
    ;;
esac
```

```text
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
TODO: this

| Switch | Code Examples |
| :--- | :--- |
| If / ElseIf / Else |  |
| Case |  |



The first decision-making statement is the ‘if’ statement. The general form of this statement in Batch Script is as follows −

```text
if(condition) do_something
```

The general working of this statement is that first a condition is evaluated in the ‘if’ statement. If the condition is true, it then executes the statements. The following diagram shows the flow of the **if** statement.

### Checking Variables

One of the common uses for the ‘if’ statement in Batch Script is for checking variables which are set in Batch Script itself. The evaluation of the ‘if’ statement can be done for both strings and numbers.

#### Checking Integer Variables

The following example shows how the ‘if’ statement can be used for numbers.

**Example**

```text
@echo off 
SET /A a = 5 
SET /A b = 10 
SET /A c = %a% + %b% 
if %c%==15 echo "The value of variable c is 15" 
if %c%==10 echo "The value of variable c is 10"
```

The key thing to note about the above program is −

* The first ‘if’ statement checks if the value of the variable c is 15. If so, then it echo’s a string to the command prompt.
* Since the condition in the statement - if %c% == 10 echo "The value of variable **c** is 10 evaluates to false, the echo part of the statement will not be executed.

**Output**

The above command produces the following output.

```text
15
```

#### Checking String Variables

The following example shows how the ‘if’ statement can be used for strings.

**Example**

```text
@echo off 
SET str1 = String1 
SET str2 = String2 
if %str1%==String1 echo "The value of variable String1" 
if %str2%==String3 echo "The value of variable c is String3"
```

The key thing to note about the above program is −

* The first ‘if’ statement checks if the value of the variable str1 contains the string “String1”. If so, then it echo’s a string to the command prompt.
* Since the condition of the second ‘if’ statement evaluates to false, the echo part of the statement will not be executed.

**Output**

The above command produces the following output.

```text
"The value of variable String1"
```

**Note** − One key thing to note is that the evaluation in the ‘if’ statement is "case-sensitive”. The same program as above is modified a little as shown in the following example. In the first statement, we have changed the comparison criteria. Because of the different casing, the output of the following program would yield nothing.

```text
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
<table>
  <thead>
    <tr>
      <th style="text-align:left">Loop Type</th>
      <th style="text-align:left">Code Examples</th>
    </tr>
  </thead>
  <tbody>
    <tr>
      <td style="text-align:left">For</td>
      <td style="text-align:left">
        <p><code>fruits = [&quot;apple&quot;, &quot;banana&quot;, &quot;cherry&quot;]</code>
        </p>
        <p><code>for x in fruits:</code>
        </p>
        <p><code>  print(x)</code>
        </p>
      </td>
    </tr>
    <tr>
      <td style="text-align:left">While</td>
      <td style="text-align:left">
        <p><code>i = 1</code>
        </p>
        <p><code>while i &lt; 6:</code>
        </p>
        <p><code>  print(i)</code>
        </p>
        <p><code>  i += 1</code>
        </p>
      </td>
    </tr>
    <tr>
      <td style="text-align:left">Break</td>
      <td style="text-align:left">
        <p><code>i = 1</code>
        </p>
        <p><code>while i &lt; 6:</code>
        </p>
        <p><code>   print(i)</code>
        </p>
        <p><code>   if i == 3:</code>
        </p>
        <p><code>     break</code>
        </p>
        <p><code>  i += 1</code>
        </p>
      </td>
    </tr>
    <tr>
      <td style="text-align:left">Continue</td>
      <td style="text-align:left">
        <p><code>i = 1</code>
        </p>
        <p><code>while i &lt; 6:</code>
        </p>
        <p><code>   print(i)</code>
        </p>
        <p><code>   if i == 3:</code>
        </p>
        <p><code>     continue</code>
        </p>
        <p><code>  i += 1</code>
        </p>
      </td>
    </tr>
  </tbody>
</table>
{% endtab %}

{% tab title="PowerShell" %}
<table>
  <thead>
    <tr>
      <th style="text-align:left">Loop Type</th>
      <th style="text-align:left">Code Examples</th>
    </tr>
  </thead>
  <tbody>
    <tr>
      <td style="text-align:left">For</td>
      <td style="text-align:left">
        <p><code>$fruits = @(&quot;apple&quot;, &quot;banana&quot;, &quot;cherry&quot;)</code>
        </p>
        <p><code>foreach($x in $fruits)</code>
        </p>
        <p><code>{</code>
        </p>
        <p><code>    Write-Host $x</code>
        </p>
        <p><code>}</code>
        </p>
      </td>
    </tr>
    <tr>
      <td style="text-align:left">While</td>
      <td style="text-align:left">
        <p><code>$i = 1</code>
        </p>
        <p><code>while ($i -lt 6)</code>
        </p>
        <p><code>{</code>
        </p>
        <p><code>    Write-Host $i</code>
        </p>
        <p><code>    $i++</code>
        </p>
        <p><code>}</code>
        </p>
      </td>
    </tr>
    <tr>
      <td style="text-align:left">Break</td>
      <td style="text-align:left">
        <p><code>$i = 1</code>
        </p>
        <p><code>while ($i -lt 6)</code>
        </p>
        <p><code>{</code>
        </p>
        <p><code>    Write-Host $i</code>
        </p>
        <p><code>    if ($i -eq 3)</code>
        </p>
        <p><code>    {</code>
        </p>
        <p><code>        break</code>
        </p>
        <p><code>    }</code>
        </p>
        <p><code>    $i++</code>
        </p>
        <p><code>}</code>
        </p>
      </td>
    </tr>
    <tr>
      <td style="text-align:left">Continue</td>
      <td style="text-align:left">
        <p><code>$i = 1</code>
        </p>
        <p><code>while ($i -lt 6)</code>
        </p>
        <p><code>{</code>
        </p>
        <p><code>    Write-Host $i</code>
        </p>
        <p><code>    if ($i -eq 3)</code>
        </p>
        <p><code>    {</code>
        </p>
        <p><code>        continue</code>
        </p>
        <p><code>    }</code>
        </p>
        <p><code>    $i++</code>
        </p>
        <p><code>}</code>
        </p>
      </td>
    </tr>
  </tbody>
</table>
{% endtab %}

{% tab title="Bash" %}
TODO: this

| Loop Type | Code Examples |
| :--- | :--- |
| For |  |
| While |  |
| Break |  |
| Continue |  |



#### Basic for loop <a id="basic-for-loop"></a>

```text
for i in /etc/rc.*; do
  echo $i
done
```

#### C-like for loop <a id="c-like-for-loop"></a>

```text
for ((i = 0 ; i < 100 ; i++)); do
  echo $i
done
```

#### Ranges <a id="ranges"></a>

```text
for i in {1..5}; do
    echo "Welcome $i"
done
```

**With step size**

```text
for i in {5..50..5}; do
    echo "Welcome $i"
done
```

#### Reading lines <a id="reading-lines"></a>

```text
cat file.txt | while read line; do
  echo $line
done
```

#### Forever <a id="forever"></a>

```text
while true; do
  ···
done
```
{% endtab %}

{% tab title="CMD .bat" %}
TODO: this

| Loop Type | Code Examples |
| :--- | :--- |
| For |  |
| While |  |
| Break |  |
| Continue |  |
{% endtab %}
{% endtabs %}

### Functions

{% tabs %}
{% tab title="Python" %}
<table>
  <thead>
    <tr>
      <th style="text-align:left">Functions</th>
      <th style="text-align:left">Code Examples</th>
    </tr>
  </thead>
  <tbody>
    <tr>
      <td style="text-align:left">Definition</td>
      <td style="text-align:left">
        <p><code>def hello_function():</code>
        </p>
        <p><code>  print(&quot;Hello from my function!&quot;)</code>
        </p>
        <p>&lt;code&gt;&lt;/code&gt;</p>
        <p><code>hello_function()</code>
        </p>
      </td>
    </tr>
    <tr>
      <td style="text-align:left">Arguments</td>
      <td style="text-align:left">
        <p><code>def my_name(fname, lname):</code>
        </p>
        <p><code>  print(&quot;My name is &quot; + fname + &quot; &quot; + lname)</code>
        </p>
        <p>&lt;code&gt;&lt;/code&gt;</p>
        <p><code>my_function(&quot;Wolf&quot;, &quot;Zweiler&quot;)</code>
        </p>
      </td>
    </tr>
    <tr>
      <td style="text-align:left">Variable Arguments</td>
      <td style="text-align:left">
        <p><code>def second_arg(*children):</code>
        </p>
        <p><code>  print(&quot;The youngest child is &quot; + children[1])</code>
        </p>
        <p>&lt;code&gt;&lt;/code&gt;</p>
        <p><code>my_function(&quot;Sarah&quot;, &quot;Emily&quot;, &quot;Tom&quot;)</code>
        </p>
      </td>
    </tr>
    <tr>
      <td style="text-align:left">Named Arguments</td>
      <td style="text-align:left">
        <p><code>def young_child(child3, child2, child1):</code>
        </p>
        <p><code>  print(&quot;The youngest child is &quot; + child3)</code>
        </p>
        <p>&lt;code&gt;&lt;/code&gt;</p>
        <p><code>my_function(child1 = &quot;Sarah&quot;, child2 = &quot;Emily&quot;, child3 = &quot;Tom&quot;)</code>
        </p>
      </td>
    </tr>
    <tr>
      <td style="text-align:left">Default Values</td>
      <td style="text-align:left">
        <p><code>def my_country(country = &quot;Wakanda&quot;):</code>
        </p>
        <p><code>  print(&quot;I am from &quot; + country)</code>
        </p>
        <p>&lt;code&gt;&lt;/code&gt;</p>
        <p><code>my_country()</code>
        </p>
      </td>
    </tr>
    <tr>
      <td style="text-align:left">Return Values</td>
      <td style="text-align:left">
        <p><code>def five_times(x):</code>
        </p>
        <p><code>  return 5 * x</code>
        </p>
      </td>
    </tr>
  </tbody>
</table>
{% endtab %}

{% tab title="PowerShell" %}
<table>
  <thead>
    <tr>
      <th style="text-align:left">Functions</th>
      <th style="text-align:left">Code Examples</th>
    </tr>
  </thead>
  <tbody>
    <tr>
      <td style="text-align:left">Definition</td>
      <td style="text-align:left">
        <p><code>function hello_function()</code>
        </p>
        <p><code>{</code>
        </p>
        <p><code>  Write-Host &quot;Hello from my function!&quot;  </code>
        </p>
        <p><code>}</code>
        </p>
        <p><code>hello_function</code>
        </p>
      </td>
    </tr>
    <tr>
      <td style="text-align:left">Arguments</td>
      <td style="text-align:left">
        <p><code>function my_name($fname, $lname)</code>
        </p>
        <p><code>{</code>
        </p>
        <p><code>    Write-Host &quot;My name is $fname $lname&quot;</code>
        </p>
        <p><code>}</code>
        </p>
        <p><code>my-function -fname &quot;Wolf&quot; -lname &quot;Zweiler&quot;</code>
        </p>
      </td>
    </tr>
    <tr>
      <td style="text-align:left">Variable Arguments</td>
      <td style="text-align:left">
        <p><code>function second_arg()</code>
        </p>
        <p><code>{</code>
        </p>
        <p><code>    Write-Host &quot;The youngest child is $($args[1])&quot;</code>
        </p>
        <p><code>}</code>
        </p>
        <p><code>  </code>
        </p>
        <p><code>my-function &quot;Sarah&quot; &quot;Emily&quot; &quot;Tom&quot;</code>
        </p>
      </td>
    </tr>
    <tr>
      <td style="text-align:left">Named Arguments</td>
      <td style="text-align:left">
        <p><code>function young_child($child3, $child2, $child1)</code>
        </p>
        <p><code>{</code>
        </p>
        <p><code>    Write-Host &quot;The youngest child is $child3&quot;</code>
        </p>
        <p><code>}</code>
        </p>
        <p><code>  </code>
        </p>
        <p><code>my-function -child1 &quot;Sarah&quot; -child2 &quot;Emily&quot; -child3 &quot;Tom&quot;</code>
        </p>
      </td>
    </tr>
    <tr>
      <td style="text-align:left">Default Values</td>
      <td style="text-align:left">
        <p><code>function my_country</code>
        </p>
        <p><code>{</code>
        </p>
        <p><code>    param(</code>
        </p>
        <p><code>        $country = &quot;Wakanda&quot;</code>
        </p>
        <p><code>    )</code>
        </p>
        <p>&lt;code&gt;&lt;/code&gt;</p>
        <p><code>    Write-Host &quot;I am from $country&quot;</code>
        </p>
        <p><code>}</code>
        </p>
        <p><code>my_country</code>
        </p>
      </td>
    </tr>
    <tr>
      <td style="text-align:left">Return Values</td>
      <td style="text-align:left">
        <p><code>function five_times($x)</code>
        </p>
        <p><code>{</code>
        </p>
        <p><code>    5 * $x</code>
        </p>
        <p><code>}</code>
        </p>
      </td>
    </tr>
  </tbody>
</table>
{% endtab %}

{% tab title="Bash" %}
TODO: this

| Functions | Code Examples |
| :--- | :--- |
| Definition |  |
| Arguments |  |
| Variable Arguments |  |
| Named Arguments |  |
| Default Values |  |
| Return Values |  |



#### Arguments <a id="arguments"></a>

| `$#` | Number of arguments |
| :--- | :--- |
| `$*` | All arguments |
| `$@` | All arguments, starting from first |
| `$1` | First argument |
| `$_` | Last argument of the previous command |

#### Returning values <a id="returning-values"></a>

```text
myfunc() {
    local myresult='some value'
    echo $myresult
}
```

```text
result="$(myfunc)"
```

Defining Functions

```text
myfunc() {
    echo "hello $1"
}
```

```text
# Same as above (alternate syntax)
function myfunc() {
    echo "hello $1"
}
```

```text
myfunc "John"
```
{% endtab %}

{% tab title="CMD .bat" %}
TODO: this

| Functions | Code Examples |
| :--- | :--- |
| Definition |  |
| Arguments |  |
| Variable Arguments |  |
| Named Arguments |  |
| Default Values |  |
| Return Values |  |
{% endtab %}
{% endtabs %}

### Classes

{% tabs %}
{% tab title="Python" %}
<table>
  <thead>
    <tr>
      <th style="text-align:left">Activity</th>
      <th style="text-align:left">Code Examples</th>
    </tr>
  </thead>
  <tbody>
    <tr>
      <td style="text-align:left">Class Definition</td>
      <td style="text-align:left">
        <p><code>class MyClass:</code>
        </p>
        <p><code>  x = 5</code>
        </p>
      </td>
    </tr>
    <tr>
      <td style="text-align:left">Object Creation</td>
      <td style="text-align:left"><code>MyClass()</code>
      </td>
    </tr>
    <tr>
      <td style="text-align:left">Using Class Constructors</td>
      <td style="text-align:left">
        <p><code>class Person:</code>
        </p>
        <p><code>  def __init__(self, name, age):</code>
        </p>
        <p><code>    self.name = name</code>
        </p>
        <p><code>    self.age = age</code>
        </p>
        <p>&lt;code&gt;&lt;/code&gt;</p>
        <p><code>p1 = Person(&quot;Bob&quot;, 42)</code>
        </p>
      </td>
    </tr>
    <tr>
      <td style="text-align:left">Defining and using Methods</td>
      <td style="text-align:left">
        <p><code>class Person:</code>
        </p>
        <p><code>  def __init__(self, name, age):</code>
        </p>
        <p><code>    self.name = name</code>
        </p>
        <p><code>    self.age = age</code>
        </p>
        <p>&lt;code&gt;&lt;/code&gt;</p>
        <p><code>  def myfunc(self):</code>
        </p>
        <p><code>    print(&quot;Hello my name is &quot; + self.name)</code>
        </p>
        <p>&lt;code&gt;&lt;/code&gt;</p>
        <p><code>p1 = Person(&quot;Bob&quot;, 42)</code>
        </p>
        <p><code>p1.myfunc()</code>
        </p>
      </td>
    </tr>
  </tbody>
</table>
{% endtab %}

{% tab title="PowerShell" %}
<table>
  <thead>
    <tr>
      <th style="text-align:left">Activity</th>
      <th style="text-align:left">Code Examples</th>
    </tr>
  </thead>
  <tbody>
    <tr>
      <td style="text-align:left">Class Definition</td>
      <td style="text-align:left">
        <p><code>class MyClass {</code>
        </p>
        <p><code>    $x = 5</code>
        </p>
        <p><code>}</code>
        </p>
      </td>
    </tr>
    <tr>
      <td style="text-align:left">Object Creation</td>
      <td style="text-align:left"><code>[MyClass]::new()</code>
      </td>
    </tr>
    <tr>
      <td style="text-align:left">Using Class Constructors</td>
      <td style="text-align:left">
        <p><code>class Person {</code>
        </p>
        <p><code>    Person($Name, $Age) {</code>
        </p>
        <p><code>        $this.Name = $Name</code>
        </p>
        <p><code>        $this.Age = $Age</code>
        </p>
        <p><code>    }</code>
        </p>
        <p>&lt;code&gt;&lt;/code&gt;</p>
        <p><code>    $Name = &apos;&apos;</code>
        </p>
        <p><code>    $Age = 0</code>
        </p>
        <p><code>}</code>
        </p>
        <p><code>[Person]::new(&apos;Bob&apos;, 42)</code>
        </p>
      </td>
    </tr>
    <tr>
      <td style="text-align:left">Defining and using Methods</td>
      <td style="text-align:left">
        <p><code>class Person {</code>
        </p>
        <p><code>    Person($Name, $Age) {</code>
        </p>
        <p><code>        $this.Name = $Name</code>
        </p>
        <p><code>        $this.Age = $Age</code>
        </p>
        <p><code>    }</code>
        </p>
        <p>&lt;code&gt;&lt;/code&gt;</p>
        <p><code>    [string]myfunc() {</code>
        </p>
        <p><code>        return &quot;Hello my name is $($this.Name)&quot;</code>
        </p>
        <p><code>    }</code>
        </p>
        <p>&lt;code&gt;&lt;/code&gt;</p>
        <p><code>    $Name = &apos;&apos;</code>
        </p>
        <p><code>    $Age = 0</code>
        </p>
        <p><code>}</code>
        </p>
        <p>&lt;code&gt;&lt;/code&gt;</p>
        <p><code>[Person]::new(&apos;Bob&apos;, 42)</code>
        </p>
      </td>
    </tr>
  </tbody>
</table>
{% endtab %}

{% tab title="Bash" %}
| Activity | Code Examples |
| :--- | :--- |
| Class Definition |  |
| Object Creation |  |
| Using Class Constructors |  |
| Defining and using Methods |  |
{% endtab %}

{% tab title="CMD .bat" %}
| Activity | Code Examples |
| :--- | :--- |
| Class Definition |  |
| Object Creation |  |
| Using Class Constructors |  |
| Defining and using Methods |  |
{% endtab %}
{% endtabs %}

### Comments

{% tabs %}
{% tab title="Python" %}
<table>
  <thead>
    <tr>
      <th style="text-align:left">Comment Type</th>
      <th style="text-align:left">Code Examples</th>
    </tr>
  </thead>
  <tbody>
    <tr>
      <td style="text-align:left">Single line</td>
      <td style="text-align:left"><code># Hello, world!</code>
      </td>
    </tr>
    <tr>
      <td style="text-align:left">Multiline</td>
      <td style="text-align:left">
        <p><code>&quot;&quot;&quot;</code>
        </p>
        <p><code>Hello, world!</code>
        </p>
        <p><code>&quot;&quot;&quot;</code>
        </p>
      </td>
    </tr>
  </tbody>
</table>
{% endtab %}

{% tab title="PowerShell" %}
<table>
  <thead>
    <tr>
      <th style="text-align:left">Comment Type</th>
      <th style="text-align:left">Code Examples</th>
    </tr>
  </thead>
  <tbody>
    <tr>
      <td style="text-align:left">Single line</td>
      <td style="text-align:left"><code># Hello, world!</code>
      </td>
    </tr>
    <tr>
      <td style="text-align:left">Multiline</td>
      <td style="text-align:left">
        <p><code>&lt;# </code>
        </p>
        <p><code>Hello, world!</code>
        </p>
        <p><code>#&gt;</code>
        </p>
      </td>
    </tr>
  </tbody>
</table>
{% endtab %}

{% tab title="Bash" %}
TODO: this

| Comment Type | Code Examples |
| :--- | :--- |
| Single line |  |
| Multiline |  |



#### Comments <a id="comments"></a>

```text
# Single line comment
```

```text
: '
This is a
multi line
comment
'
```
{% endtab %}

{% tab title="CMD .bat" %}
TODO: this

| Comment Type | Code Examples |
| :--- | :--- |
| Single line |  |
| Multiline |  |

### Comments Using the Rem Statement

There are two ways to create comments in Batch Script; one is via the Rem command. Any text which follows the Rem statement will be treated as comments and will not be executed. Following is the general syntax of this statement.

#### Syntax

```text
Rem Remarks
```

where ‘Remarks’ is the comments which needs to be added.

The following example shows a simple way the **Rem** command can be used.

#### Example

```text
@echo off 
Rem This program just displays Hello World 
set message=Hello World 
echo %message%
```

#### Output

The above command produces the following output. You will notice that the line with the Rem statement will not be executed.

```text
Hello World
```

### Comments Using the :: Statement

The other way to create comments in Batch Script is via the :: command. Any text which follows the :: statement will be treated as comments and will not be executed. Following is the general syntax of this statement.

#### Syntax

```text
:: Remarks
```

where ‘Remarks’ is the comment which needs to be added.

The following example shows the usage of the "::" command.

#### Example

```text
@echo off 
:: This program just displays Hello World 
set message = Hello World 
echo %message%
```

#### Output

The above command produces the following output. You will notice that the line with the :: statement will not be executed.

```text
Hello World
```

**Note** − If you have too many lines of Rem, it could slow down the code, because in the end each line of code in the batch file still needs to be executed.
{% endtab %}
{% endtabs %}

### Data Types

{% tabs %}
{% tab title="Python" %}
<table>
  <thead>
    <tr>
      <th style="text-align:left">Action</th>
      <th style="text-align:left">Code Examples</th>
    </tr>
  </thead>
  <tbody>
    <tr>
      <td style="text-align:left">Get Object&apos;s Type</td>
      <td style="text-align:left">
        <p><code>var = 1</code>
        </p>
        <p><code>type(var)</code>
        </p>
      </td>
    </tr>
  </tbody>
</table>
{% endtab %}

{% tab title="PowerShell" %}
<table>
  <thead>
    <tr>
      <th style="text-align:left">Action</th>
      <th style="text-align:left">Code Examples</th>
    </tr>
  </thead>
  <tbody>
    <tr>
      <td style="text-align:left">Get Object&apos;s Type</td>
      <td style="text-align:left">
        <p><code>$var = 1</code>
        </p>
        <p><code>$var | Get-Member</code>
        </p>
        <p></p>
        <p>#or</p>
        <p></p>
        <p><code>$var.GetType()</code>
        </p>
      </td>
    </tr>
  </tbody>
</table>
{% endtab %}

{% tab title="Bash" %}
TODO: this

| Action | Code Examples |
| :--- | :--- |
| Get Object's Type |  |
{% endtab %}

{% tab title="CMD .bat" %}
TODO: this

| Action | Code Examples |
| :--- | :--- |
| Get Object's Type |  |
{% endtab %}
{% endtabs %}

### Dictionaries

{% tabs %}
{% tab title="Python" %}
<table>
  <thead>
    <tr>
      <th style="text-align:left"><b>Activity</b>
      </th>
      <th style="text-align:left">Code Examples</th>
    </tr>
  </thead>
  <tbody>
    <tr>
      <td style="text-align:left">Defining</td>
      <td style="text-align:left">
        <p><code>thisdict = {</code>
        </p>
        <p><code>  &quot;brand&quot;: &quot;Ford&quot;,</code>
        </p>
        <p><code>  &quot;model&quot;: &quot;Mustang&quot;,</code>
        </p>
        <p><code>  &quot;year&quot;: 1964</code>
        </p>
        <p><code>}</code>
        </p>
        <p><code>print(thisdict)</code>
        </p>
      </td>
    </tr>
    <tr>
      <td style="text-align:left">Accessing Elements</td>
      <td style="text-align:left">
        <p><code>thisdict = {</code>
        </p>
        <p><code>  &quot;brand&quot;: &quot;Ford&quot;,</code>
        </p>
        <p><code>  &quot;model&quot;: &quot;Mustang&quot;,</code>
        </p>
        <p><code>  &quot;year&quot;: 1964</code>
        </p>
        <p><code>}</code>
        </p>
        <p><code>thisdict[&apos;brand&apos;]</code>
        </p>
      </td>
    </tr>
    <tr>
      <td style="text-align:left">Updating Elements</td>
      <td style="text-align:left">
        <p><code>thisdict = {</code>
        </p>
        <p><code>  &quot;brand&quot;: &quot;Ford&quot;,</code>
        </p>
        <p><code>  &quot;model&quot;: &quot;Mustang&quot;,</code>
        </p>
        <p><code>  &quot;year&quot;: 1964</code>
        </p>
        <p><code>}</code>
        </p>
        <p><code>thisdict[&apos;brand&apos;] = &apos;Chevy&apos;</code>
        </p>
      </td>
    </tr>
    <tr>
      <td style="text-align:left">Enumerating Keys</td>
      <td style="text-align:left">
        <p><code>thisdict = {</code>
        </p>
        <p><code>  &quot;brand&quot;: &quot;Ford&quot;,</code>
        </p>
        <p><code>  &quot;model&quot;: &quot;Mustang&quot;,</code>
        </p>
        <p><code>  &quot;year&quot;: 1964</code>
        </p>
        <p><code>}</code>
        </p>
        <p><code>for x in thisdict:</code>
        </p>
        <p><code>    print(x)</code>
        </p>
      </td>
    </tr>
    <tr>
      <td style="text-align:left">Enumerating Values</td>
      <td style="text-align:left">
        <p><code>thisdict = {</code>
        </p>
        <p><code>  &quot;brand&quot;: &quot;Ford&quot;,</code>
        </p>
        <p><code>  &quot;model&quot;: &quot;Mustang&quot;,</code>
        </p>
        <p><code>  &quot;year&quot;: 1964</code>
        </p>
        <p><code>}</code>
        </p>
        <p><code>for x in thisdict.values():</code>
        </p>
        <p><code>    print(x)</code>
        </p>
      </td>
    </tr>
    <tr>
      <td style="text-align:left">Check if key exists</td>
      <td style="text-align:left">
        <p><code>thisdict = {</code>
        </p>
        <p><code>  &quot;brand&quot;: &quot;Ford&quot;,</code>
        </p>
        <p><code>  &quot;model&quot;: &quot;Mustang&quot;,</code>
        </p>
        <p><code>  &quot;year&quot;: 1964</code>
        </p>
        <p><code>}</code>
        </p>
        <p><code>if &quot;model&quot; in thisdict:</code>
        </p>
        <p><code>  print(&quot;Yes, &apos;model&apos; is one of the keys in the thisdict dictionary&quot;)</code>
        </p>
      </td>
    </tr>
    <tr>
      <td style="text-align:left">Adding items</td>
      <td style="text-align:left">
        <p><code>thisdict = {</code>
        </p>
        <p><code>  &quot;brand&quot;: &quot;Ford&quot;,</code>
        </p>
        <p><code>  &quot;model&quot;: &quot;Mustang&quot;,</code>
        </p>
        <p><code>  &quot;year&quot;: 1964</code>
        </p>
        <p><code>}</code>
        </p>
        <p><code>thisdict[&quot;color&quot;] = &quot;red&quot;</code>
        </p>
      </td>
    </tr>
  </tbody>
</table>
{% endtab %}

{% tab title="PowerShell" %}
<table>
  <thead>
    <tr>
      <th style="text-align:left"><b>Activity</b>
      </th>
      <th style="text-align:left">Code Examples</th>
    </tr>
  </thead>
  <tbody>
    <tr>
      <td style="text-align:left">Defining</td>
      <td style="text-align:left">
        <p><code>$thisdict = @{</code>
        </p>
        <p><code>  brand = &quot;Ford&quot;</code>
        </p>
        <p><code>  model = &quot;Mustang&quot;</code>
        </p>
        <p><code>  year = 1964</code>
        </p>
        <p><code>}</code>
        </p>
      </td>
    </tr>
    <tr>
      <td style="text-align:left">Accessing Elements</td>
      <td style="text-align:left">
        <p><code>$thisdict = @{</code>
        </p>
        <p><code>  brand = &quot;Ford&quot;</code>
        </p>
        <p><code>  model = &quot;Mustang&quot;</code>
        </p>
        <p><code>  year = 1964</code>
        </p>
        <p><code>}</code>
        </p>
        <p><code>$thisdict.brand</code>
        </p>
        <p>&lt;code&gt;&lt;/code&gt;</p>
        <p><code>or</code>
        </p>
        <p>&lt;code&gt;&lt;/code&gt;</p>
        <p><code>$thisdict[&apos;brand&apos;]</code>
        </p>
      </td>
    </tr>
    <tr>
      <td style="text-align:left">Updating Elements</td>
      <td style="text-align:left">
        <p><code>$thisdict = @{</code>
        </p>
        <p><code>  brand = &quot;Ford&quot;</code>
        </p>
        <p><code>  model = &quot;Mustang&quot;</code>
        </p>
        <p><code>  year = 1964</code>
        </p>
        <p><code>}</code>
        </p>
        <p><code>$thisdict.brand = &apos;Chevy&apos;</code>
        </p>
      </td>
    </tr>
    <tr>
      <td style="text-align:left">Enumerating Keys</td>
      <td style="text-align:left">
        <p><code>$thisdict = @{</code>
        </p>
        <p><code>  brand = &quot;Ford&quot;</code>
        </p>
        <p><code>  model = &quot;Mustang&quot;</code>
        </p>
        <p><code>  year = 1964</code>
        </p>
        <p><code>}</code>
        </p>
        <p><code>$thisdict.Keys | ForEach-Object {</code>
        </p>
        <p><code>    $_</code>
        </p>
        <p><code>}</code>
        </p>
      </td>
    </tr>
    <tr>
      <td style="text-align:left">Enumerating Values</td>
      <td style="text-align:left">
        <p><code>$thisdict = @{</code>
        </p>
        <p><code>  brand = &quot;Ford&quot;</code>
        </p>
        <p><code>  model = &quot;Mustang&quot;</code>
        </p>
        <p><code>  year = 1964</code>
        </p>
        <p><code>}</code>
        </p>
        <p><code>$thisdict.Values | ForEach-Object {</code>
        </p>
        <p><code>    $_</code>
        </p>
        <p><code>}</code>
        </p>
      </td>
    </tr>
    <tr>
      <td style="text-align:left">Check if key exists</td>
      <td style="text-align:left">
        <p><code>$thisdict = @{</code>
        </p>
        <p><code>  brand = &quot;Ford&quot;</code>
        </p>
        <p><code>  model = &quot;Mustang&quot;</code>
        </p>
        <p><code>  year = 1964</code>
        </p>
        <p><code>}</code>
        </p>
        <p><code>if ($thisdict.ContainsKey(&quot;model&quot;))</code>
        </p>
        <p><code>{</code>
        </p>
        <p><code>    Write-Host &quot;Yes, &apos;model&apos; is one of the keys in the thisdict dictionary&quot;</code>
        </p>
        <p><code>}</code>
        </p>
      </td>
    </tr>
    <tr>
      <td style="text-align:left">Adding items</td>
      <td style="text-align:left">
        <p><code>$thisdict = @{</code>
        </p>
        <p><code>  brand = &quot;Ford&quot;</code>
        </p>
        <p><code>  model = &quot;Mustang&quot;</code>
        </p>
        <p><code>  year = 1964</code>
        </p>
        <p><code>}</code>
        </p>
        <p><code>$thisdict.color = &apos;red&apos;</code>
        </p>
      </td>
    </tr>
  </tbody>
</table>
{% endtab %}

{% tab title="Bash" %}
TODO: this

| **Activity** | Code Examples |
| :--- | :--- |
| Defining |  |
| Accessing Elements |  |
| Updating Elements |  |
| Enumerating Keys |  |
| Enumerating Values |  |
| Check if key exists |  |
| Adding items |  |



#### Defining <a id="defining"></a>

```text
declare -A sounds
```

```text
sounds[dog]="bark"
sounds[cow]="moo"
sounds[bird]="tweet"
sounds[wolf]="howl"
```

Declares `sound` as a Dictionary object \(aka associative array\).

#### Working with dictionaries <a id="working-with-dictionaries"></a>

```text
echo ${sounds[dog]} # Dog's sound
echo ${sounds[@]}   # All values
echo ${!sounds[@]}  # All keys
echo ${#sounds[@]}  # Number of elements
unset sounds[dog]   # Delete dog
```

#### Iteration <a id="iteration-1"></a>

**Iterate over values**

```text
for val in "${sounds[@]}"; do
  echo $val
done
```

**Iterate over keys**

```text
for key in "${!sounds[@]}"; do
  echo $key
done
```
{% endtab %}

{% tab title="CMD .bat" %}
TODO: this

| **Activity** | Code Examples |
| :--- | :--- |
| Defining |  |
| Accessing Elements |  |
| Updating Elements |  |
| Enumerating Keys |  |
| Enumerating Values |  |
| Check if key exists |  |
| Adding items |  |



### Creating Structures in Arrays

Structures can also be implemented in batch files using a little bit of an extra coding for implementation. The following example shows how this can be achieved.

#### Example

```text
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

The following key things need to be noted about the above code.

* Each variable defined using the set command has 2 values associated with each index of the array.
* The variable **i** is set to 0 so that we can loop through the structure will the length of the array which is 3.
* We always check for the condition on whether the value of i is equal to the value of **len** and if not, we loop through the code.
* We are able to access each element of the structure using the obj\[%i%\] notation.

#### Output

The above command produces the following output.

```text
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
<table>
  <thead>
    <tr>
      <th style="text-align:left">Lambda</th>
      <th style="text-align:left">Code Examples</th>
    </tr>
  </thead>
  <tbody>
    <tr>
      <td style="text-align:left">Lambda</td>
      <td style="text-align:left">
        <p><code>x = lambda a : a + 10</code>
        </p>
        <p><code>print(x(5))</code>
        </p>
      </td>
    </tr>
  </tbody>
</table>
{% endtab %}

{% tab title="PowerShell" %}
<table>
  <thead>
    <tr>
      <th style="text-align:left">Lambda</th>
      <th style="text-align:left">Code Examples</th>
    </tr>
  </thead>
  <tbody>
    <tr>
      <td style="text-align:left">Lambda</td>
      <td style="text-align:left">
        <p><code>$x = { param($a) $a + 10 }</code>
        </p>
        <p><code>&amp; $x 5</code>
        </p>
      </td>
    </tr>
  </tbody>
</table>
{% endtab %}

{% tab title="Bash" %}
TODO: this

| Lambda | Code Examples |
| :--- | :--- |
| Lambda |  |
{% endtab %}

{% tab title="CMD .bat" %}
TODO: this

| Lambda | Code Examples |
| :--- | :--- |
| Lambda |  |
{% endtab %}
{% endtabs %}

### Math Operators

TODO: Add other operator types

{% tabs %}
{% tab title="Python" %}
| Operator | Code Examples |
| :--- | :--- |
| Addition | `var = 1 + 1` |
| Subtraction | `var = 1 - 1` |
| Multiplication | `var = 1 * 1` |
| Division | `var = 1 / 1` |
| Modulus | `var = 1 % 1` |
| Floor | `var = 10 // 3` |
| Exponent | `var = 10 ** 3` |
{% endtab %}

{% tab title="PowerShell" %}
| Operator | Code Examples |
| :--- | :--- |
| Addition | `$var = 1 + 1` |
| Subtraction | `$var = 1 - 1` |
| Multiplication | `$var = 1 * 1` |
| Division | `$var = 1 / 1` |
| Modulus | `$var = 1 % 1` |
| Floor | `$var = [Math]::Floor(10 / 3)` |
| Exponent | `$var = [Math]::Pow(10, 3)` |
{% endtab %}

{% tab title="Bash" %}
TODO: this

| Operator | Code Examples |
| :--- | :--- |
| Addition |  |
| Subtraction |  |
| Multiplication |  |
| Division |  |
| Modulus |  |
| Floor |  |
| Exponent |  |
{% endtab %}

{% tab title="CMD .bat" %}
TODO: this

| Operator | Code Examples |
| :--- | :--- |
| Addition |  |
| Subtraction |  |
| Multiplication |  |
| Division |  |
| Modulus |  |
| Floor |  |
| Exponent |  |



An operator is a symbol that tells the compiler to perform specific mathematical or logical manipulations.

In batch script, the following types of operators are possible.

* Arithmetic operators
* Relational operators
* Logical operators
* Assignment operators
* Bitwise operators

### Arithmetic Operators

Batch script language supports the normal Arithmetic operators as any language. Following are the Arithmetic operators available.

[Show Example](https://www.tutorialspoint.com/batch_script/batch_script_arithmetic_operators.htm)

| Operator | Description | Example |
| :--- | :--- | :--- |
| + | Addition of two operands | 1 + 2 will give 3 |
| − | Subtracts second operand from the first | 2 − 1 will give 1 |
| \* | Multiplication of both operands | 2 \* 2 will give 4 |
| / | Division of the numerator by the denominator | 3 / 2 will give 1.5 |
| % | Modulus operator and remainder of after an integer/float division | 3 % 2 will give 1 |

### Relational Operators

Relational operators allow of the comparison of objects. Below are the relational operators available.

[Show Example](https://www.tutorialspoint.com/batch_script/batch_script_relational_operators.htm)

| Operator | Description | Example |
| :--- | :--- | :--- |
| EQU | Tests the equality between two objects | 2 EQU 2 will give true |
| NEQ | Tests the difference between two objects | 3 NEQ 2 will give true |
| LSS | Checks to see if the left object is less than the right operand | 2 LSS 3 will give true |
| LEQ | Checks to see if the left object is less than or equal to the right operand | 2 LEQ 3 will give true |
| GTR | Checks to see if the left object is greater than the right operand | 3 GTR 2 will give true |
| GEQ | Checks to see if the left object is greater than or equal to the right operand | 3 GEQ 2 will give true |

### Logical Operators

Logical operators are used to evaluate Boolean expressions. Following are the logical operators available.

The batch language is equipped with a full set of Boolean logic operators like AND, OR, XOR, but only for binary numbers. Neither are there any values for TRUE or FALSE. The only logical operator available for conditions is the NOT operator.

[Show Example](https://www.tutorialspoint.com/batch_script/batch_script_logical_operators.htm)

| Operator | Description |
| :--- | :--- |
| AND | This is the logical “and” operator |
| OR | This is the logical “or” operator |
| NOT | This is the logical “not” operator |

### Assignment Operators

Batch Script language also provides assignment operators. Following are the assignment operators available.

[Show Example](https://www.tutorialspoint.com/batch_script/batch_script_assignment_operators.htm)

<table>
  <thead>
    <tr>
      <th style="text-align:left">Operator</th>
      <th style="text-align:left">Description</th>
      <th style="text-align:left">Example</th>
    </tr>
  </thead>
  <tbody>
    <tr>
      <td style="text-align:left">+=</td>
      <td style="text-align:left">This adds right operand to the left operand and assigns the result to
        left operand</td>
      <td style="text-align:left">
        <p>Set /A a = 5</p>
        <p>a += 3</p>
        <p>Output will be 8</p>
      </td>
    </tr>
    <tr>
      <td style="text-align:left">-=</td>
      <td style="text-align:left">This subtracts the right operand from the left operand and assigns the
        result to the left operand</td>
      <td style="text-align:left">
        <p>Set /A a = 5</p>
        <p>a -= 3</p>
        <p>Output will be 2</p>
      </td>
    </tr>
    <tr>
      <td style="text-align:left">*=</td>
      <td style="text-align:left">This multiplies the right operand with the left operand and assigns the
        result to the left operand</td>
      <td style="text-align:left">
        <p>Set /A a = 5</p>
        <p>a *= 3</p>
        <p>Output will be 15</p>
      </td>
    </tr>
    <tr>
      <td style="text-align:left">/=</td>
      <td style="text-align:left">This divides the left operand with the right operand and assigns the result
        to the left operand</td>
      <td style="text-align:left">
        <p>Set /A a = 6</p>
        <p>a/ = 3</p>
        <p>Output will be 2</p>
      </td>
    </tr>
    <tr>
      <td style="text-align:left">%=</td>
      <td style="text-align:left">This takes modulus using two operands and assigns the result to the left
        operand</td>
      <td style="text-align:left">
        <p>Set /A a = 5</p>
        <p>a% = 3</p>
        <p>Output will be 2</p>
      </td>
    </tr>
  </tbody>
</table>

### Bitwise Operators

Bitwise operators are also possible in batch script. Following are the operators available.

[Show Example](https://www.tutorialspoint.com/batch_script/batch_script_bitwise_operators.htm)

| Operator | Description |
| :--- | :--- |
| & | This is the bitwise “and” operator |
| \| | This is the bitwise “or” operator |
| ^ | This is the bitwise “xor” or Exclusive or operator |

Following is the truth table showcasing these operators.

| p | q | p & q | p \| q | p ^ q |
| :--- | :--- | :--- | :--- | :--- |
| 0 | 0 | 0 | 0 | 0 |
| 0 | 1 | 0 | 1 | 1 |
| 1 | 1 | 1 | 1 | 0 |
| 1 | 0 | 0 | 1 | 1 |
{% endtab %}
{% endtabs %}

### Error Handling

{% tabs %}
{% tab title="Python" %}
<table>
  <thead>
    <tr>
      <th style="text-align:left">Error Handling</th>
      <th style="text-align:left">Code Examples</th>
    </tr>
  </thead>
  <tbody>
    <tr>
      <td style="text-align:left">Try/Except</td>
      <td style="text-align:left">
        <p><code>try:</code>
        </p>
        <p><code>  print(x)</code>
        </p>
        <p><code>except:</code>
        </p>
        <p><code>  print(&quot;An exception occurred&quot;)</code>
        </p>
      </td>
    </tr>
    <tr>
      <td style="text-align:left">Else</td>
      <td style="text-align:left">
        <p><code>try:<br /></code>
        </p>
        <p><code>  print(&quot;Hello&quot;)<br /></code>
        </p>
        <p><code>except:<br /></code>
        </p>
        <p><code>  print(&quot;Something went wrong&quot;)<br /></code>
        </p>
        <p><code>else:<br /></code>
        </p>
        <p><code>  print(&quot;Nothing went wrong&quot;)</code>
        </p>
      </td>
    </tr>
    <tr>
      <td style="text-align:left">Finally</td>
      <td style="text-align:left">
        <p><code>try: </code>
        </p>
        <p><code>  f = open(&quot;file.txt&quot;) f.write(&quot;Lorum Ipsum&quot;) </code>
        </p>
        <p><code>except: </code>
        </p>
        <p><code>  print(&quot;Something went wrong when writing to the file&quot;) </code>
        </p>
        <p><code>finally: </code>
        </p>
        <p><code>  f.close()</code>
        </p>
      </td>
    </tr>
    <tr>
      <td style="text-align:left">Raise</td>
      <td style="text-align:left">
        <p><code>x = -1</code>
        </p>
        <p><code>if x &lt; 0: </code>
        </p>
        <p><code>  raise Exception(&quot;Sorry, no numbers below zero&quot;)</code>
        </p>
      </td>
    </tr>
  </tbody>
</table>
{% endtab %}

{% tab title="PowerShell" %}
<table>
  <thead>
    <tr>
      <th style="text-align:left">Error Handling</th>
      <th style="text-align:left">Code Examples</th>
    </tr>
  </thead>
  <tbody>
    <tr>
      <td style="text-align:left">Try/Catch</td>
      <td style="text-align:left">
        <p><code>try {</code>
        </p>
        <p><code>    Write-Host $x </code>
        </p>
        <p><code>} catch {</code>
        </p>
        <p><code>    Write-Host &quot;An exception ocurred&quot;</code>
        </p>
        <p><code>}</code>
        </p>
      </td>
    </tr>
  </tbody>
</table>
{% endtab %}

{% tab title="Bash" %}
TODO: this

| Error Handling | Code Examples |
| :--- | :--- |
| Try/Catch |  |



#### Trap errors <a id="trap-errors"></a>

```text
trap 'echo Error at about $LINENO' ERR
```

or

```text
traperr() {
  echo "ERROR: ${BASH_SOURCE[1]} at about ${BASH_LINENO[0]}"
}

set -o errtrace
trap traperr ERR
```

#### Raising errors <a id="raising-errors"></a>

```text
myfunc() {
  return 1
}
```

```text
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
| :--- | :--- |
| Try/Catch |  |
{% endtab %}
{% endtabs %}

### Shell Command Execution

{% tabs %}
{% tab title="Python" %}

{% endtab %}

{% tab title="PowerShell" %}

{% endtab %}

{% tab title="Bash" %}


#### Shell execution <a id="shell-execution"></a>

```text
echo "I'm in $(pwd)"
echo "I'm in `pwd`"
```
{% endtab %}

{% tab title="CMD .bat" %}

{% endtab %}
{% endtabs %}

### HERE docs

{% tabs %}
{% tab title="Python" %}

{% endtab %}

{% tab title="PowerShell" %}

{% endtab %}

{% tab title="Bash" %}


#### Heredoc <a id="heredoc"></a>

```text
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
| Activity | Code Examples |
| :--- | :--- |
| Install | `pip install requests` |
| Import | `import requests` |
| List | `pip list` |
{% endtab %}

{% tab title="PowerShell" %}
| Activity | Code Examples |
| :--- | :--- |
| Install | `Install-Module Pester` |
| Import | `Import-Module Pester` |
| List | `Get-Module -ListAvailable` |
{% endtab %}

{% tab title="Bash" %}
TODO: this

| Activity | Code Examples |
| :--- | :--- |
| Install |  |
| Import |  |
| List |  |
{% endtab %}

{% tab title="CMD .bat" %}
TODO: this

| Activity | Code Examples |
| :--- | :--- |
| Install |  |
| Import |  |
| List |  |
{% endtab %}
{% endtabs %}

References 

* [https://devhints.io/bash](https://devhints.io/bash)
* [https://wiki.bash-hackers.org/syntax/expansion/cmdsubst](https://wiki.bash-hackers.org/syntax/expansion/cmdsubst)
* [https://www.tutorialspoint.com/batch\_script/batch\_script\_syntax.htm](https://www.tutorialspoint.com/batch_script/batch_script_syntax.htm)
* 
