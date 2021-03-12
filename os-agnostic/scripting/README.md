# Scripting

{% hint style="success" %}
Hack Responsibly.

Always ensure you have **explicit** permission to access any computer system **before** using any of the techniques contained in these documents.  You accept full responsibility for your actions by applying any knowledge gained here.  
{% endhint %}

TODO: Separate Bash and Python scripting pages...and add more

## Bash

### Bash Scripting Basics

\[+\] Shebang:

```markup
#!/bin/bash
```

\[+\] Variables

```markup
name=Bob
echo $name
user=$(whoami)
echo $user
echo 'Hello' $name. 'You are running as' $user.
```

\[+\] Simple script example

```bash
#!/bin/bash
clear
echo "Hello World"
name=Bob
ip=`ifconfig | grep "Bcast:" | cut -d":" -f2 | cut -d" " -f1`
echo "Hello" $name "Your IP address is:" $ip
```

\[+\] User Input

```bash
read -p "IP: " IP
```

Example script with `read`

```bash
#!/bin/bash
echo "Please input the IP address"
read -p "IP: " IP
ping -c 5 $IP
```

\[+\] Check For No User Input

```bash
if [ -z $domain ]; then
	echo
	echo "#########################"
	echo
	echo "Invalid choice."
	echo
	exit
fi
```

\[+\] For loops

```bash
#!/bin/bash
for host in $(cat hosts.txt)
do
	echo $host
done
```

\[+\] Port Scan one liner

```bash
for port in $(cat Ports.txt); do nc -nzv 192.168.0.1 $port & sleep 0.5; done
```

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

```bash
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

### Python Functions

* Files: [https://www.w3schools.com/python/python\_ref\_file.asp](https://www.w3schools.com/python/python_ref_file.asp)   
* Strings: [https://www.w3schools.com/python/python\_ref\_string.asp](https://www.w3schools.com/python/python_ref_string.asp)   
* Keyworks: [https://www.w3schools.com/python/python\_ref\_keywords.asp](https://www.w3schools.com/python/python_ref_keywords.asp)   
* Random: [https://www.w3schools.com/python/module\_random.asp](https://www.w3schools.com/python/module_random.asp)   

### Dealing with Sockets

[https://pequalsnp-team.github.io/cheatsheet/socket-basics-py-js-rb](https://pequalsnp-team.github.io/cheatsheet/socket-basics-py-js-rb)

### MISC

```python
#checks the output from crypto and sees if at least 60% is ascii letters and returns true for possible plaintext
def is_plaintext(ptext):
    num_letters = sum(map(lambda x : 1 if x in string.ascii_letters else 0, ptext))
    if num_letters / len(ptext) >= .6:
      return True
```

## PHP

### PHP Functions

* Files: [https://www.w3schools.com/php/php\_ref\_filesystem.asp](https://www.w3schools.com/php/php_ref_filesystem.asp)   
* Directories: [https://www.w3schools.com/php/php\_ref\_directory.asp](https://www.w3schools.com/php/php_ref_directory.asp)   
* Errors: [https://www.w3schools.com/php/php\_ref\_error.asp](https://www.w3schools.com/php/php_ref_error.asp)   
* Network: [https://www.w3schools.com/php/php\_ref\_network.asp](https://www.w3schools.com/php/php_ref_network.asp)   
* Misc: [https://www.w3schools.com/php/php\_ref\_misc.asp](https://www.w3schools.com/php/php_ref_misc.asp)

### PHP Server

[https://www.php.net/manual/en/features.commandline.webserver.php](https://www.php.net/manual/en/features.commandline.webserver.php) When starting php -S on a mac \(in my case macOS Sierra\) to host a local server, I had trouble with connecting from legacy Java. As it turned out, if you started the php server with `php -S localhost:80` the server will be started with ipv6 support only! To access it via ipv4, you need to change the start up command like so: `php -S 127.0.0.1:80` which starts server in ipv4 mode only.

It’s not mentioned directly, and may not be obvious, but you can also use this to create a virtual host. This, of course, requires the help of your hosts file. Here are the steps:

```text
1    /etc/hosts
    127.0.0.1    www.example.com
2    cd [root folder]
    php -S www.example.com:8000
3    Browser:
    http://www.example.com:8000/index.php
```

In order to set project specific configuration options, simply add a php.ini file to your project, and then run the built-in server with this flag: `php -S localhost:8000 -c php.ini`

Example \#6 Accessing the CLI Web Server From Remote Machines You can make the web server accessible on port 8000 to any interface with: `$ php -S 0.0.0.0:8000`

Example \#2 Starting with a specific document root directory

```text
$ cd ~/public_html
$ php -S localhost:8000 -t foo/
Listening on localhost:8000
Document root is /home/me/public_html/foo
```

### PHP Jail Escape

_With file\_get\_contents\(\)_

```php
print file_get_contents('flag.txt');
```

_With readfile\(\)_

```php
echo readfile("flag.txt");
```

_With popen\(\)_

```php
popen("vi", "w");

:r flag.txt
   or
:!/bin/bash
```

_With highlight\_file\(\)_

```php
highlight_file(glob("flag.txt")[0]);
   or
highlight_file(glob("fl*txt")[0]);
```

_With highlight\_source\(\)_

```php
highlight_source("flag.txt");
   or
highlight_source(glob("*")[4]);
```

_With Finfo\(\)_

```php
new Finfo(0,glob(hex2bin(hex2bin(3261)))[0]);
```

If you like this content and would like to see more, please consider [buying me a coffee](https://www.buymeacoffee.com/zweilosec)!

