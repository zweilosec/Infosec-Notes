---
description: Pivoting Using SSH
---

# SSH

## SSH Tunneling 101

{% hint style="info" %}
The following are helpful options for creating port forwarding tunnels.
{% endhint %}

| Option | Description                                                                                                                                       |
| ------ | ------------------------------------------------------------------------------------------------------------------------------------------------- |
| `-N`   | Makes SSH not execute any commands (such as creating a shell)                                                                                     |
| `-T`   | Prevents a pseudo terminal from being allocated for the connection; however, commands can still be issued                                         |
| `-f`   | Forks the SSH client process into the background right after authentication; keeps the tunnel from blocking continued use of the current terminal |

### ▶ SSH local port forward

To forward traffic to an internal server via a reachable server

```bash
# From Attacker system
ssh -N $user1@$reachable_host -L $LPORT:$internal_host:$RPORT
```

Now `curl localhost:$LPORT` will fetch whatever is hosted on `$RPORT` which is only accessible from the "reachable server".

### ▶ SSH remote port forward

To create a remote port forward, pass the `-R` option to the ssh client:

```bash
ssh -R [REMOTE:]REMOTE_PORT:DESTINATION:DESTINATION_PORT [USER@]SSH_SERVER
```

The options used are as follows:

* `[REMOTE:]REMOTE_PORT` - The IP and the port number on the remote SSH server. An empty REMOTE means that the remote SSH server will bind on all interfaces.
* `DESTINATION:DESTINATION_PORT` - The IP or hostname and the port of the destination machine.
* `[USER@]SERVER_IP` - The remote SSH user and server IP address.

Remote port forwarding is mostly used to give access to an internal service to someone from the outside.

#### To send traffic back to our attack system's "remote" port from a "local" port of a reachable server:

```bash
# On Reachable system
ssh -N $attack_user@$attack_system -R $RPORT:localhost
```

This will open `$RPORT` on the attacker system and tunnel any traffic back to the reachable system.

#### Limit hackback with a dedicated account without shell

On your attack system, create a new user account that has no shell to be used solely for receiving the remote port forward.

```bash
#On our machine
sudo systemctl start sshd
sudo useradd sshpivot --no-create-home --shell /bin/false
sudo passwd sshpivot

#On the pivot machine
ssh sshpivot@192.168.2.149 -R 127.0.0.1:14000:10.42.42.2:80 -N
```

### ▶Listener plus reverse at same time (middle-man)

```bash
ssh -L 9999:host2:80 -R 9999:localhost:9999 host1
```

`-L 9999:host2:80` Means bind to localhost:9999 and any packet sent to localhost:9999 forward it to host2:80

`-R 9999:localhost:9999` Means any packet received by host1:9999 forward it back to localhost:9999

One way to make a tunnel so you can access the application on host2 directly from localhost:9999

```bash
ssh -L 6010:localhost:6010 user1@host1 \
-t ssh -L 6010:localhost:6010 user2@host2 \
-t ssh -L 6010:localhost:6010 user3@host3
```

### ▶ Use dynamic port forwarding to create a SOCKS proxy

To create a dynamic port forward (SOCKS proxy) pass the `-D` option to the ssh client:

```bash
ssh -D [LOCAL_IP:]LOCAL_PORT [USER@]SSH_SERVER
```

The options used are as follows:

* `[LOCAL_IP:]LOCAL_PORT` - The local machine IP address and port number. When LOCAL\_IP is omitted, the ssh client binds on localhost.
* `[USER@]SERVER_IP` - The remote SSH user and server IP address.

A typical example of a dynamic port forwarding is to tunnel the web browser traffic through an SSH server.

To send traffic bound for any remote port through `$LPORT`:

```bash
# On Attacker system
ssh -N $user1@$reachable_host -D $LPORT
```

Now you can configure proxychains to send all (TCP) traffic through this as a Socks5 proxy.

### ▶ Use ProxyJump (`-J`) to tunnel traffic through one host to another

```bash
# On Attacker system
ssh -N -J $user1@$reachable_host:$SSH_PORT $user2@$internal_host
# Using inline ssh_config (-o)
scp -oProxyJump=userB@hostB,userC@hostC infile.txt userD@hostD:"~/outfile.txt"
# With multiple hops use a comma (,) between, except for the last hop: put a space before it
scp -J userB@hostB,userC@hostC userD@hostD:~/infile.txt outfile.txt
```

These hops can be chained by using a comma (`,`) to separate them (no space!). This also works with SCP to pull or push files through multiple hops.

You can also combine this with Dynamic port forwarding to make your socks proxy reach the remote internal system.

#### Multiple pivots using ProxyJump & config file

* [https://medium.com/maverislabs/proxyjump-the-ssh-option-you-probably-never-heard-of-2d7e41d43464](https://medium.com/maverislabs/proxyjump-the-ssh-option-you-probably-never-heard-of-2d7e41d43464)

If you want to use a single ssh command to go from your PC to any of the hosts, you can use the `~/.ssh/config` configuration file which contains the details of each host and all identities needed to access each host from your system. The `ProxyJump` keyword is used to specify an intermediate host that is needed to arrive at the target host.

```
Host hop1
    User user1
    HostName host1
    Port 22
    IdentityFile ~/.ssh/pem/identity1.pem

Host hop2
    User user2
    HostName host2
    Port 22
    IdentityFile ~/.ssh/pem/identity2.pem
    ProxyJump hop1

Host hop3
    User user3
    HostName host3
    Port 22
    IdentityFile ~/.ssh/pem/identity3.pem
    ProxyJump hop2
```

From your computer, you can test each jump individually, i.e.

```bash
ssh hop1 # will go from your PC to host1
ssh hop2 # will go from your PC to host2 (via host1)
ssh hop3 # will go from your PC to host3 (via host1 and host2)
```

Another cool thing about the `~/.ssh/config` file is that this will also enable sftp file transfers via any series of hops, e.g.

```bash
sftp hop1 # for file transfers between your PC and host1
#Connected to hop1.
sftp hop2 # for file transfers between your PC and host2
#Connected to hop2.
sftp hop3 # for file transfers between your PC and host3
#Connected to hop3.
```

### ▶ Specify useful SSH configurations directly in the command line with (`-o`).

```bash
# bypass first time prompt when have non-interactive shell
ssh -o "UserKnownHostsFile=/dev/null" -o "StrictHostKeyChecking=no"
```

## SSH Configuration File

* [https://www.man7.org/linux/man-pages/man5/ssh\_config.5.html](https://www.man7.org/linux/man-pages/man5/ssh\_config.5.html)

The SSH Config File takes the following structure:

```
Host hostname1
    SSH_OPTION value
    SSH_OPTION value

Host hostname2
    SSH_OPTION value

Host *
    SSH_OPTION value
```

The contents of the SSH client config file is organized into stanzas (sections). Each stanza starts with the Host directive and contains specific SSH options used when establishing a connection with the remote SSH server.

Indentation is not required but is recommended since it makes the file easier to read.

The `Host` directive can contain one pattern or a whitespace-separated list of patterns. Each pattern can contain zero or more non-whitespace character or one of the following pattern specifiers:

* `*` - Matches zero or more characters. For example, Host \* matches all hosts, while `192.168.0.*` matches hosts in the 192.168.0.0/24 subnet.
* `?` - Matches exactly one character. The pattern, Host 10.10.0.? matches all hosts in `10.10.0.[0-9]` range.
* `!` - When used at the start of a pattern, it negates the match. For example, Host `10.10.0.* !10.10.0.5` matches any host in the 10.10.0.0/24 subnet except 10.10.0.5.

The SSH client reads the configuration file stanza by stanza, and if more than one patterns match, the options from the first matching stanza take precedence. Therefore, more host-specific declarations should be given at the beginning of the file, and more general overrides at the end of the file. You can find a full list of available SSH options by typing `man ssh_config` in your terminal.

The SSH config file is also read by other programs such as SCP , SFTP , and rsync.

#### SSH Config file locations

The SSH client reads its configuration in the following precedence order:

1. Options specified from the command line.
2. Options defined in the `~/.ssh/config`.
3. Options defined in the `/etc/ssh/ssh_config`.

If you want to override a single option, you can specify it on the command line. For example, if you have the following definition:

```
Host dev
    HostName dev.example.com
    User john
    Port 2322
```

and you want to use all other options but to connect as user root instead of john simply specify the user on the command line:

```bash
ssh -o "User=root" dev
```

The `-F (configfile)` option allows you to specify an alternative per-user configuration file.

To tell the ssh client to ignore all of the options specified in the ssh configuration file, use:

```bash
ssh -F /dev/null $user@$remote
```

## ssh-copy-id

Add SSH key to an `authorized_keys` file remotely using the `ssh-copy-id` command.

```bash
ssh-copy-id $user@$ip
```

## References

* [https://erev0s.com/blog/ssh-local-remote-and-dynamic-port-forwarding-explain-it-i-am-five/](https://erev0s.com/blog/ssh-local-remote-and-dynamic-port-forwarding-explain-it-i-am-five/)
* [https://en.wikibooks.org/wiki/OpenSSH/Cookbook/Proxies\_and\_Jump\_Hosts](https://en.wikibooks.org/wiki/OpenSSH/Cookbook/Proxies\_and\_Jump\_Hosts)
* [https://medium.com/maverislabs/proxyjump-the-ssh-option-you-probably-never-heard-of-2d7e41d43464](https://medium.com/maverislabs/proxyjump-the-ssh-option-you-probably-never-heard-of-2d7e41d43464)
* [https://serverfault.com/questions/361794/with-ssh-only-reverse-tunnel-web-access-via-ssh-socks-proxy](https://serverfault.com/questions/361794/with-ssh-only-reverse-tunnel-web-access-via-ssh-socks-proxy)
* [https://unix.stackexchange.com/questions/327802/how-to-scp-through-two-intermediate-servers-to-a-third-hop-server](https://unix.stackexchange.com/questions/327802/how-to-scp-through-two-intermediate-servers-to-a-third-hop-server)
* [https://notes.benheater.com/books/network-pivoting/page/ssh-port-forwarding](https://notes.benheater.com/books/network-pivoting/page/ssh-port-forwarding)
* [https://iximiuz.com/en/posts/ssh-tunnels/](https://iximiuz.com/en/posts/ssh-tunnels/)
* [https://www.ssh.com/academy/ssh/tunneling-example](https://www.ssh.com/academy/ssh/tunneling-example)

## Misc to sort

### Dynamic Port Forwarding (Single port to any remote port)

*   setup proxychains with socks5 on 127.0.0.1:1080

    * Or set up socks5 proxy on firefox

    > For nmap use `-Pn -sT` or use tcp scanner in msf

```
ssh -i bobs.key -p 2222 bob@10.10.10.123 -D1080
```

### Local

```bash
Fix this one
# SSH remote port forward to send traffic back to our local port from a port of server_ip
ssh whistler@server_ip -p 2222 -L 58671:localhost:1234 # 
# this will listen on port 58671 of server_ip and tunnel the traffic back to us on loclahost:1234; nc -nlvp 1234 to receive for example
```

### If you don't have an SSH session

First, SSH to your Kali from target machine

On Kali:

```bash
service ssh start 
# "add a user, give it /bin/false in /etc/passwd"
ssh - -R 12345:192.168.122.228:5986 test@10.1.1.1
```

### Use local forwarding on an ad hoc basis

* https://thegreycorner.com/2021/12/15/hackthebox\_dante-review.html

Use the ssh escape sequence (which by default is `<enter>`, then `~C` or `shift-~`then `shift-c`.) to access the ssh command line and create them as needed. If you’re not familiar with the ssh escape sequence, when the appropriate key combination is pressed at the regular ssh command prompt as the next keypress after Enter it drops you to a special prompt like so:

```
ssh>
```

At this prompt, you gain the ability to enable a number of ssh options without having to enable them from the command line when establishing a new session. You can, for example, create a local port forward from port 8888 to the remote host and port 172.16.1.1:8000 in the current session like so:

```
ssh> -L 8888:172.16.1.1:8000
```

### Forward UDP traffic through SSH tunnel with nc & mkfifo

* [https://www.adamcouch.co.uk/tunnel-snmp-check-udp-over-ssh/](https://www.adamcouch.co.uk/tunnel-snmp-check-udp-over-ssh/)

Begin on the Attack machine by creating an SSH port forward. Send TCP port 6666 on localhost to TCP 9999 on the remote pivot server:

```powershell
ssh -L 6666:localhost:9999 user@192.168.100.10
```

Then on the Pivot Server create a fifo file for netcat to talk to:

```powershell
mkfifo /tmp/fifo
nc -l -p 6666 < /tmp/fifo | nc -u 192.168.100.100 161 > /tmp/fifo
```

On the Attack machine do similar:

```powershell
mkfifo /tmp/fifo
nc -l -u -p 161 < /tmp/fifo | nc localhost 6666 > /tmp/fifo
```

Now tools that use UDP (such as nmap UDP scans or snmp\_check) can communicate through the tunnel!
