# Scripting

{% hint style="success" %}
Hack Responsibly.

Always ensure you have **explicit** permission to access any computer system **before** using any of the techniques contained in these documents.  You accept full responsibility for your actions by applying any knowledge gained here.  
{% endhint %}

TODO: Separate Bash and Python scripting pages...and add more

## Bash

### Check for root privileges

When user account created a user ID is assigned to each user. BASH shell stores the user ID in the $UID environment variable. The effective user ID is stored in the $EUID variable. 

You can easily add a simple check at the start of a script to make sure it is being run with root privileges.

### Old way to check for root privileges

```text
#!/bin/bash

# Make sure only the root user can run the script
# Or it is run with sudo
if [ "$(id -u)" != "0" ]; then
   echo "This script must be run as root." 1>&2
   exit 1
fi
```

### New way: Using EUID

```text
#!/bin/bash

# Make sure only the root user can run our script
# Or it is run with sudo
if [[ $EUID -ne 0 ]]; then
   echo "This script must be run as root." 1>&2
   exit 1
fi
```

### MISC

[https://www.techbrown.com/most-useful-bash-scripts-linux-sysadmin/](https://www.techbrown.com/most-useful-bash-scripts-linux-sysadmin/)

```text
wget https://raw.githubusercontent.com/sathisharthar/Admin-Scripts/master/sysinop
```

## Python

### Dealing with Sockets

[https://pequalsnp-team.github.io/cheatsheet/socket-basics-py-js-rb](https://pequalsnp-team.github.io/cheatsheet/socket-basics-py-js-rb)

### MISC

```text
#checks the output from crypto and sees if at least 60% is ascii letters and returns true for possible plaintext
def is_plaintext(ptext):
    num_letters = sum(map(lambda x : 1 if x in string.ascii_letters else 0, ptext))
    if num_letters / len(ptext) >= .6:
      return True
```

