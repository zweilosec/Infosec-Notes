# Script Language Comparison

TODO: Add output for all examples

TODO: Add examples for Bash and Windows Batch scripting

## Syntax Comparisons Between Python, PowerShell, Bash, and Windows batch

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
  </tbody>
</table>
{% endtab %}

{% tab title="PowerShell" %}
| Type | Code Examples |
| :--- | :--- |
| Standard Variable | `$var = "Hello"` |
| Global Variable | `$global:var = "Hello"` |
{% endtab %}

{% tab title="Bash" %}
TODO: this

| Type | Code Examples |
| :--- | :--- |
| Standard Variable |  |
| Global Variable |  |
{% endtab %}

{% tab title="CMD .bat" %}
TODO: this

| Type | Code Examples |
| :--- | :--- |
| Standard Variable |  |
| Global Variable |  |
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
        <p><code># &apos;Hello&apos;</code>
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
        <p><code># Hello</code>
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
{% endtab %}
{% endtabs %}

### Type Casting

{% tabs %}
{% tab title="Python" %}
| Type | Code Examples |
| :--- | :--- |
| Integers | `i = int("10")` |
| Floats | `i = float("10.5")` |
| Strings | `i = str(10)` |
{% endtab %}

{% tab title="PowerShell" %}
| Type | Code Examples |
| :--- | :--- |
| Integers | `$i = [int]"10"` |
| Floats | `$i = [float]"10.5"`  |
| Strings | `$i = [string]10` |
{% endtab %}

{% tab title="Bash" %}
| Type | Code Examples |
| :--- | :--- |
| Integers |  |
| Floats |  |
| Strings |  |
{% endtab %}

{% tab title="CMD .bat" %}
| Type | Code Examples |
| :--- | :--- |
| Integers |  |
| Floats |  |
| Strings |  |
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
        <p><code>a = 33</code>
        </p>
        <p><code>b = 200</code>
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
        <p><code>$a = 33</code>
        </p>
        <p><code>$b = 200</code>
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
{% endtab %}

{% tab title="CMD .bat" %}
TODO: this

| Switch | Code Examples |
| :--- | :--- |
| If / ElseIf / Else |  |
| Case |  |
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
{% endtab %}

{% tab title="CMD .bat" %}
TODO: this

| Comment Type | Code Examples |
| :--- | :--- |
| Single line |  |
| Multiline |  |
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
{% endtab %}
{% endtabs %}

### Functions

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
        <p><code>a = 33</code>
        </p>
        <p><code>b = 200</code>
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
        <p><code>$a = 33</code>
        </p>
        <p><code>$b = 200</code>
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
{% endtab %}

{% tab title="CMD .bat" %}
TODO: this

| Switch | Code Examples |
| :--- | :--- |
| If / ElseIf / Else |  |
| Case |  |
{% endtab %}
{% endtabs %}

```text
	PowerShell	Python
Definition	
function my-function()
{
  Write-Host "Hello from a function"  
}
my-function
def my_function():
  print("Hello from a function")

my_function()
Arguments	
function my-function($fname, $lname)
{
    Write-Host "$fname $lname"
}
  

my-function -fname "Adam" -lname "Driscoll"
def my_function(fname, lname):
  print(fname + " " + lname)

my_function("Adam", "Driscoll")
Variable Arguments	
function my-function()
{
    Write-Host "$($args[2])"
}
  
my-function "Bill" "Ted" "adam"
def my_function(*kids):
  print("The youngest child is " + kids[2])

my_function("Emil", "Tobias", "Linus")
Named Arguments	
function my-function($child3, $child2, $child1)
{
    Write-Host "The youngest child is $child3"
}
  
my-function -child1 "Emil" -child2 "Tobias" -child3 "Linus"
def my_function(child3, child2, child1):
  print("The youngest child is " + child3)

my_function(child1 = "Emil", child2 = "Tobias", child3 = "Linus")
Default Values	
function my-function
{
    param(
        $country = "Norway"
    )

    Write-Host "I am from $country"
}
def my_function(country = "Norway"):
  print("I am from " + country)
Return Values	
function my-function($x)
{
    5 * $x
}
  
def my_function(x):
  return 5 * x
```

|  | PowerShell | Python |
| :--- | :--- | :--- |
| Definition |  |  |
| Arguments |  |  |
| Variable Arguments |  |  |
| Named Arguments |  |  |
| Default Values |  |  |
| Return Values |  |  |

### Lambdas

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
        <p><code>a = 33</code>
        </p>
        <p><code>b = 200</code>
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
        <p><code>$a = 33</code>
        </p>
        <p><code>$b = 200</code>
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
{% endtab %}

{% tab title="CMD .bat" %}
TODO: this

| Switch | Code Examples |
| :--- | :--- |
| If / ElseIf / Else |  |
| Case |  |
{% endtab %}
{% endtabs %}

```text
	PowerShell	Python
Lambda	
$x = { param($a) $a + 10 }
& $x 5
x = lambda a : a + 10
print(x(5))
```

|  | PowerShell | Python |
| :--- | :--- | :--- |
| Lambda |  |  |

### Loops

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
        <p><code>a = 33</code>
        </p>
        <p><code>b = 200</code>
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
        <p><code>$a = 33</code>
        </p>
        <p><code>$b = 200</code>
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
{% endtab %}

{% tab title="CMD .bat" %}
TODO: this

| Switch | Code Examples |
| :--- | :--- |
| If / ElseIf / Else |  |
| Case |  |
{% endtab %}
{% endtabs %}

```text
	PowerShell	Python
For	
$fruits = @("apple", "banana", "cherry")
foreach($x in $fruits)
{
    Write-Host $x
}
  
fruits = ["apple", "banana", "cherry"]
for x in fruits:
  print(x)
While	
$i = 1
while ($i -lt 6)
{
    Write-Host $i
    $i++
}
i = 1
while i < 6:
  print(i)
  i += 1
Break	
$i = 1
while ($i -lt 6)
{
    Write-Host $i
    if ($i -eq 3)
    {
        break
    }
    $i++
}
i = 1
while i < 6:
   print(i)
   if i == 3:
     break
  i += 1
Continue	
$i = 1
while ($i -lt 6)
{
    Write-Host $i
    if ($i -eq 3)
    {
        continue
    }
    $i++
}
i = 1
while i < 6:
   print(i)
   if i == 3:
     continue
  i += 1
```

|  | PowerShell | Python |
| :--- | :--- | :--- |
| For |  |  |
| While |  |  |
| Break |  |  |
| Continue |  |  |

### Operators

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
        <p><code>a = 33</code>
        </p>
        <p><code>b = 200</code>
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
        <p><code>$a = 33</code>
        </p>
        <p><code>$b = 200</code>
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
{% endtab %}

{% tab title="CMD .bat" %}
TODO: this

| Switch | Code Examples |
| :--- | :--- |
| If / ElseIf / Else |  |
| Case |  |
{% endtab %}
{% endtabs %}

```text
	PowerShell	Python
Addition	
$var = 1 + 1
var = 1 + 1
Subtraction	
$var = 1 - 1
var = 1 - 1
Multiplication	
$var = 1 * 1
var = 1 * 1
Division	
$var = 1 / 1
var = 1 / 1
Modulus	
$var = 1 % 1
var = 1 % 1
Floor	
[Math]::Floor(10 / 3)
10 // 3
Exponent	
[Math]::Pow(10, 3)
10 ** 3
```

|  | PowerShell | Python |
| :--- | :--- | :--- |
| Addition |  |  |
| Subtraction |  |  |
| Multiplication |  |  |
| Division |  |  |
| Modulus |  |  |
| Floor |  |  |
| Exponent |  |  |

### Package Management

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
        <p><code>a = 33</code>
        </p>
        <p><code>b = 200</code>
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
        <p><code>$a = 33</code>
        </p>
        <p><code>$b = 200</code>
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
{% endtab %}

{% tab title="CMD .bat" %}
TODO: this

| Switch | Code Examples |
| :--- | :--- |
| If / ElseIf / Else |  |
| Case |  |
{% endtab %}
{% endtabs %}

```text
	PowerShell	Python
Install	
Install-Module PowerShellProtect
pip install camelcase
Import	
Import-Module PowerShellProtect
import camelcase
List	
Get-Module -ListAvailable
pip list
```

|  | PowerShell | Python |
| :--- | :--- | :--- |
| Install |  |  |
| Import |  |  |
| List |  |  |

### Strings

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
        <p><code>a = 33</code>
        </p>
        <p><code>b = 200</code>
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
        <p><code>$a = 33</code>
        </p>
        <p><code>$b = 200</code>
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
{% endtab %}

{% tab title="CMD .bat" %}
TODO: this

| Switch | Code Examples |
| :--- | :--- |
| If / ElseIf / Else |  |
| Case |  |
{% endtab %}
{% endtabs %}

```text
	PowerShell	Python
String	
"Hello"
"Hello"
'Hello'
Multiline	
"Hello
World
"
"""Hello
World"""
Select Character	
$str = 'Hello'
$str[0]
# H
str = 'Hello'
str[0]
# 'H'
Length	
$str = 'Hello'
$str.Length
str = 'Hello'
len(str)
Remove whitespace at front and back	
$str = ' Hello '
$str.Trim()
# Hello
str = ' Hello '
str.strip()
# 'Hello'
To Lowercase	
$str = 'HELLO'
$str.ToLower()
# hello
str = 'HELLO'
str.lower()
# 'hello'
To Uppercase	
$str = 'hello'
$str.ToUpper()
# HELLO
str = 'hello'
str.upper()
# 'HELLO'
Replace	
$str = 'Hello'
$str.Replace('H', 'Y')
# Yello
str = 'Hello'
str.replace('H', 'Y')
# 'Yello'
Split	
'Hello, World' -split ','
# @('Hello', ' World')
str = 'Hello, World'
str.split(',')
# ['Hello', ' World']
Join	
$array = @("Hello", "World")
$array -join ", "
[String]::Join(', ', $array)
list = ["Hello", "World"]
", ".join(list)
Formatting	
$price = 49
$txt = "The price is {0} dollars"
$txt -f $price
price = 49
txt = "The price is {} dollars"
print(txt.format(price))
Formatting by Index	
$price = 49
$txt = "The price is {0} dollars"
$txt -f $price
price = 49
txt = "The price is {0} dollars"
print(txt.format(price))
Formatting Strings	
$price = 49
"The price is $price dollars"
price = 49
f"The price is {price} dollars"
```

|  | PowerShell | Python |
| :--- | :--- | :--- |
| String |  |  |
| Multiline |  |  |
| Select Character |  |  |
| Length |  |  |
| Remove whitespace at front and back |  |  |
| To Lowercase |  |  |
| To Uppercase |  |  |
| Replace |  |  |
| Split |  |  |
| Join |  |  |
| Formatting |  |  |
| Formatting by Index |  |  |
| Formatting Strings |  |  |

### Error Handling

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
        <p><code>a = 33</code>
        </p>
        <p><code>b = 200</code>
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
        <p><code>$a = 33</code>
        </p>
        <p><code>$b = 200</code>
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
{% endtab %}

{% tab title="CMD .bat" %}
TODO: this

| Switch | Code Examples |
| :--- | :--- |
| If / ElseIf / Else |  |
| Case |  |
{% endtab %}
{% endtabs %}

```text
	PowerShell	Python
try {
    Write-Host $x 
} catch {
    Write-Host "An exception ocurred"
}
try:
  print(x)
except:
  print("An exception occurred")
```

|  | PowerShell |
| :--- | :--- |
| Try/Catch |  |
| Exception |  |

