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

#### Old way to check for root privileges

```text
#!/bin/bash

# Make sure only the root user can run the script
# Or it is run with sudo
if [ "$(id -u)" != "0" ]; then
   echo "This script must be run as root." 1>&2
   exit 1
fi
```

#### New way: Using EUID

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

Add to `multitool.sh`:create wordlists with cewl & Hashcat; add add options to use mangling rules; 

Add to `multitool.sh`: crack passwords with Hashcat

```text
#crack passwords with hashcat; 

#get user input for attack type - make attack type listing with numeric selections;

#get user input for hash type 

hashcat --help | grep -i $hash_selection 
#|>then prompt user to input the hash type # identifier; 

#Get user input for file with hashes to crack
#|>Check if hashlist includes usernames (in format username:hash)
#|>if so add --username to hashcat syntax

#Get user input for password list to use for cracking

#Ask user if they want to apply any mangling rules or a mask
#|>if mask is chosen display a short help screen of default mask types
#|>as well as describe -1 and -2 user masks
#|>make sure character escapes work properly and don't cause problems below

echo '\?l = abcdefghijklmnopqrstuvwxyz'
echo '\?u = ABCDEFGHIJKLMNOPQRSTUVWXYZ'
echo '\?d = 0123456789'
echo '\?s = \!\"\#\$\%\&\'\(\)\*\+\,\-\.\/\:\;\<\=\>\?\@\[\]\^\_\`\{\|\}\~'
echo '\?a = \?l\?u\?d\?s'
echo '\?b = 0x00 - 0xff'

#basic execution syntax: 
hashcat -D1,2 -O --force -a $attack_type -m $hash_id $hash_list $pass_list

#find out if hashcat has problems with blank variables
#|>if not then add variables for the proper flags + user input for mangling/masks
#|>ex: rules="-r $user_rules"
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

