---
description: 'Sorted Linux notes, need to separate to different pages and reorganize'
---

# Red Team Notes

{% hint style="success" %}
Hack Responsibly.

Always ensure you have **explicit** permission to access any computer system **before** using any of the techniques contained in these documents.  You accept full responsibility for your actions by applying any knowledge gained here.  
{% endhint %}

## Linux

Website for searching for shells through random programs such as '5KFB6' 'vi' "living off the land binaries": [GTFObins](https://gtfobins.github.io/)



## 

## Remote Code Execution

Run commands on remote system without a shell through SSH with a "Herefile". `HERE` can be anything, but it must begin and end with the same word. [https://www.cyberciti.biz/faq/linux-unix-osx-bsd-ssh-run-command-on-remote-machine-server/](https://www.cyberciti.biz/faq/linux-unix-osx-bsd-ssh-run-command-on-remote-machine-server/)

```text
ssh <user>@<server> << HERE
 <command1>
 <command2>
HERE
```

## Misc Linux

Raw memory location so no files on disk: `/dev/shm/`

list all running commands:

```bash
ps -eo command`
#change delimiter to \n instead of <space> (loop by line): 
IFS=$'\n'
#Then loop through each line in output: 
for i in $(ps -eo command); do echo $i; done
```

[https://unix.stackexchange.com/questions/211817/copy-the-contents-of-a-file-into-the-clipboard-without-displaying-its-contents](https://unix.stackexchange.com/questions/211817/copy-the-contents-of-a-file-into-the-clipboard-without-displaying-its-contents) script to copy contents of file directly to clipboard; Save in PATH location then enjoy!

```text
#! /bin/bash
xclip -selection clipboard -i $@
```

'new' netstat: `ss -lnp | grep 9001` \#check if any connections on port 9001

copy files to local machine without file transfer:

```bash
base64 -w 0 /path/of/file/name.file 
#copy base64 then: 
echo -n <base64material> | base64 -d > filename.file
```

pretty print JSON text in console \([https://www.howtogeek.com/529219/how-to-parse-json-files-on-the-linux-command-line-with-jq/](https://www.howtogeek.com/529219/how-to-parse-json-files-on-the-linux-command-line-with-jq/)\). Pipe the JSON output to `jq`. Example from NASA ISS API: `curl -s http://api.open-notify.org/iss-now.json | jq`

### Check encoding of a text file

`vi -c 'let $enc = &fileencoding | execute "!echo Encoding: $enc" | q' <file_to_check>` check encoding of a text file \(needed especially when doing crypto with python, or cracking passwords with `rockyou.txt` - _hint: needs latin encoding!_\) [https://vim.fandom.com/wiki/Bash\_file\_encoding\_alias](https://vim.fandom.com/wiki/Bash_file_encoding_alias) \(how to make an alias for the above command\)

