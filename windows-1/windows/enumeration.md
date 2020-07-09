# Enumeration

Windows enumeration

Get list of current user information:  `whoami /all` Includes: Username, SID, Groups \(including their descriptions!\), and user privileges.

`tasklist /v` \(verbose\) 

`netstat -an` 

`Get-WmiObject -class Win32_UserAccount [-filter "LocalAccount=True"]`

./winpeas.exe

