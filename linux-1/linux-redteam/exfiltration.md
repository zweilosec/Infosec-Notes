# Exfiltration

Not much here yet...please feel free to contribute at [https://www.github.com/zweilosec](https://github.com/zweilosec)

## Python HTTP server

TODO: add --help to python file sharing scripts \(issue [\#14](https://github.com/zweilosec/Infosec-Notes/issues/14)\)

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

## Python FTP server

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

