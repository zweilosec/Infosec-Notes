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
| Retrieving Variable Contents |  |
{% endtab %}

{% tab title="Bash" %}
TODO: this

| Type | Code Examples |
| :--- | :--- |
| Standard Variable |  |
| Global Variable |  |
| Retrieving Variable Contents |  |
{% endtab %}

{% tab title="CMD .bat" %}
TODO: this

| Type | Code Examples |
| :--- | :--- |
| Standard Variable |  |
| Global Variable |  |
| Retrieving Variable Contents |  |
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
{% endtab %}

{% tab title="CMD .bat" %}
TODO: this

| Method | Code Examples |
| :--- | :--- |
| Normal String |  |
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
{% endtab %}

{% tab title="CMD .bat" %}
TODO: this

| Switch | Code Examples |
| :--- | :--- |
| If / ElseIf / Else |  |
| Case |  |
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
      <td style="text-align:left">Try/Catch</td>
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
{% endtab %}

{% tab title="CMD .bat" %}
TODO: this

| Error Handling | Code Examples |
| :--- | :--- |
| Try/Catch |  |
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

