# SSH & SCP

{% hint style="success" %}
Hack Responsibly.

Always ensure you have **explicit** permission to access any computer system **before** using any of the techniques contained in these documents. You accept full responsibility for your actions by applying any knowledge gained here.
{% endhint %}

TODO: update and clean syntax and examples \(issue [\#18](https://github.com/zweilosec/Infosec-Notes/issues/18)\)

* Prep code examples for scripting \(as appropriate, descriptive examples may not need this\)
* Standardize variable names across examples
* Split up [SCP](https://github.com/zweilosec/Infosec-Notes/blob/master/os-agnostic/ssh-and-scp.md#scp) examples for readability
* Move links to "[References](https://github.com/zweilosec/Infosec-Notes/blob/master/os-agnostic/ssh-and-scp.md#resources)" section or make cleaner looking if belongs
* Expand "[Dynamic Reverse Tunnels](https://github.com/zweilosec/Infosec-Notes/blob/master/os-agnostic/ssh-and-scp.md#dynamic-reverse-tunnels)" section

## SSH/SCP into victim without password

1. From the attacker machine generate a keypair: `ssh-keygen -t ed25519`
2. Copy the contents from public key `$keyfile.pub` into the `.ssh/authorized_keys` file of the victim
3. Connect with the argument `-i $keyfile`

## SSH

### sshd

SSH should already be installed on most Linux-based computers, but you may need to start the SSH daemon \(sshd\) if the computer has never accepted incoming SSH connections before.

```bash
sudo systemctl start sshd
```

To have the SSH daemon start each time you reboot your computer, use this command:

```bash
sudo systemctl enable sshd
```

### SSH Config <a id="ssh-config"></a>

The `$HOME/.ssh/config` file allows for custom configurations and aliases to be specified for SSH connection profiles. The example below sets up `TCPKeepAlive` and `ServerAliveInterval` for all hosts, and sets up aliases for a few servers.

```text
Host *
    ServerAliveInterval 60
    TCPKeepAlive no

Host jumpBox-1
    HostName jumpbox-1.com
    User jumper
    IdentityFile /home/kali/.ssh/to_jumpbox-1.key

Host jumpBox-2
    HostName sup.er.long.complex.aws.dns.name.com
    User jumpboxAdmin
    IdentityFile /home/kali/.ssh/to_jumpbox-2.key
    ProxyJump jumpBox-1

Host raspPi-1
    HostName 192.168.221.32
    User piUser
    IdentityFile /home/kali/.ssh/to_raspPi-1.key
    ProxyJump jumpBox-2
```

In the case of the SSH server side, replace `ServerAliveInterval` with `ClientAliveInterval` and put it in the file `/etc/ssh/sshd_config`. This is especially useful for reverse tunnels.

The above configuration shows an example of allowing a user to use a simplified command such as`ssh jumpbox-1` in place of having to type out `user@hostName -i /path/to/keyfile` and supplies the relevant information automatically. This reduces the need for remembering usernames, IPs, or long and complex DNS names.

### ProxyJump <a id="proxyjump"></a>

By having SSH keys for each of our jump boxes and the target device on our local machine, we can simplify the process of logging in through each machine quite a bit. The `ProxyJump` directive signifies which machine you need to jump through to get to the next machine in the proxy chain.

This simple change allows a user to simply give the command `ssh raspPi-1`, wait a bit for all of the connections to be made, and pop a shell on the `raspPi-1` device.

### Keep Alive

If you want to set the keep alive [for the server](https://www.freebsd.org/cgi/man.cgi?sshd_config%285%29), add this to `/etc/ssh/sshd_config`:

```text
ClientAliveInterval 60
ClientAliveCountMax 2
```

> **ClientAliveInterval**: Sets a timeout interval in seconds after which if no data has been received from the client, sshd\(8\) will send a message through the encrypted channel to request a response from the client.
>
> **ClientAliveCountMax**: Sets the number of client alive messages \(see below\) which may be sent without sshd\(8\) receiving any messages back from the client. If this threshold is reached while client alive messages are being sent, sshd will disconnect the client, terminating the session.

* ... look in "man sshd\_config" for the server portion running the ssh daemon, not the client config. – [Jeff Davenport](https://stackoverflow.com/users/4756398/jeff-davenport) [Jul 29 '16 at 22:35](https://stackoverflow.com/questions/25084288/keep-ssh-session-alive#comment64717733_37330274)
* Should I use `ClientAliveInterval` to let the server check for client alive, or should I let the client "ping" the server with `ServerAliveInterval` repeatedly? Both seems not to make sense – [qrtLs](https://stackoverflow.com/users/4933053/qrtls) [Jun 2 '17 at 14:08](https://stackoverflow.com/questions/25084288/keep-ssh-session-alive#comment75665824_37330274)
* Only set the `ClientAliveInterval` on the server if you want the server to disconnect on dead connections that do not respond, and you can customize how often and when that happens. – [Jeff Davenport](https://stackoverflow.com/users/4756398/jeff-davenport) [Jul 25 '17 at 20:22](https://stackoverflow.com/questions/25084288/keep-ssh-session-alive#comment77588141_37330274) 

### SSH Keys

TODO: Clean and organize this section - issue [\#28](https://github.com/zweilosec/Infosec-Notes/issues/28)

To generate a new SSH key for remote access:

From [https://www.ssh.com/ssh/keygen/](https://www.ssh.com/ssh/keygen/):

```text
SSH supports several public key algorithms for authentication keys. These include:

rsa - an old algorithm based on the difficulty of factoring large numbers. A key size of at least 2048 bits is recommended for RSA; 4096 bits is better. RSA is getting old and significant advances are being made in factoring. Choosing a different algorithm may be advisable. It is quite possible the RSA algorithm will become practically breakable in the foreseeable future. All SSH clients support this algorithm.

dsa - an old US government Digital Signature Algorithm. It is based on the difficulty of computing discrete logarithms. A key size of 1024 would normally be used with it. DSA in its original form is no longer recommended.

ecdsa - a new Digital Signature Algorithm standarized by the US government, using elliptic curves. This is probably a good algorithm for current applications. Only three key sizes are supported: 256, 384, and 521 (sic!) bits. We would recommend always using it with 521 bits, since the keys are still small and probably more secure than the smaller keys (even though they should be safe as well). Most SSH clients now support this algorithm.

ed25519 - this is a new algorithm added in OpenSSH. Support for it in clients is not yet universal. Thus its use in general purpose applications may not yet be advisable.

The algorithm is selected using the -t option and key size using the -b option. The following commands illustrate:

ssh-keygen -t rsa -b 4096
ssh-keygen -t dsa
ssh-keygen -t ecdsa -b 521
ssh-keygen -t ed25519
```

### Log into remote server using SSH Key

```bash
ssh-keygen -f $key_file -t ed25519 #use the ed25519 algorithm, which is much smaller than default rsa, more secure than ECDSA
cat $key_file.pub
#copy public key to remote host
#if characters are a premium you can chop of the user@host portion, but all users will be able to use this key!
echo $pub_key > $victim_homeDir/.ssh/authorized_keys #on remote host in /home/<user>/
chmod 600 $key_file 
ssh -i $key_file $user@$remote_host
```

{% hint style="danger" %}
**Note**: AWS will _NOT_ accept this file. You have to strip off the `-----BEGIN PUBLIC KEY-----` and `-----END PUBLIC KEY-----` from the file. Save it and import and it should work in AWS.
{% endhint %}

and if you need to convert this format to ssh-rsa run : `ssh-keygen -f PublicKey.pub -i -mPKCS8`

Prior to using a new SSH key file it is necessary to change the permissions: `chmod 600 <keyfile>`

Using an SSH key to login to a remote computer: `ssh -i <keyfile> <username>@<IP>`

However, before you can use the key to login to a remote computer, the public key must be placed in the `AuthorizedKeys` file on the remote system. You can do this with the `ssh-copy-id` command.

```bash
ssh-copy-id $user@$remote_host -i $key_file
```

#### Key file details

For those interested in the details inside the key file \(generated as explained above\): `openssl rsa -noout -text -inform PEM -in key.pub -pubin`; or for the private key file: `openssl rsa -noout -text -in key.private` which outputs as text on the console the actual components of the key \(modulus, exponents, primes, etc.\)

### SSH Key Algorithms

OpenSSH 8.0 supports four different types of signatures:

* rsa; ssh-rsa
* dsa; ssh-dss
* ecdsa; ecdsa-sha2-nistp256, ecdsa-sha2-nistp384, ecdsa-sha2-nistp521
* ed25519; ssh-ed25519

TODO:Write number of characters, key strength, show algorithm name, default file name, give pros & cons; make this a table

* [https://goteleport.com/blog/comparing-ssh-keys/](https://goteleport.com/blog/comparing-ssh-keys/)
* [https://security.stackexchange.com/questions/131010/which-host-key-algorithm-is-best-to-use-for-ssh\#:~:text=SSH supports several public key algorithms for authentication,significant advances are being  made in factoring](https://security.stackexchange.com/questions/131010/which-host-key-algorithm-is-best-to-use-for-ssh#:~:text=SSH%20supports%20several%20public%20key%20algorithms%20for%20authentication,significant%20advances%20are%20being%20%20made%20in%20factoring).

#### RSA

id\_rsa - default, uses RSA 2048 bits \(double check to be sure\) Implementation RSA libraries can be found for all major languages, including in-depth libraries \(JS, Python, Go, Rust, C\). Compatibility Usage of SHA-1 \(OpenSSH\) or public keys under 2048-bits may be unsupported.

#### DSA

DSA is not considered secure any more and should not be used. Implementation DSA was adopted by FIPS-184 in 1994. It has ample representation in major crypto libraries, similar to RSA. Compatibility While DSA enjoys support for PuTTY-based clients, OpenSSH 7.0 disables DSA by default.

ECDSA - small and strong, eliptical curve digital signature algorithm; benefits, uses less characters when transferring on the wire ECDSA suffers from the same random number risk as DSA E...something TODO:look it up \(I used in recent HTB machines\); very short key, very useful for transferring when limited on characters to send TODO:research more

#### ECDSA & EdDSA

* [https://blog.peterruppel.de/ed25519-for-ssh/](https://blog.peterruppel.de/ed25519-for-ssh/)

  The two examples above are not entirely sincere. Both Sony and the Bitcoin protocol employ ECDSA, not DSA proper. ECDSA is an elliptic curve implementation of DSA. Functionally, where RSA and DSA require key lengths of 3072 bits to provide 128 bits of security, ECDSA can accomplish the same with only 256-bit keys. However, ECDSA relies on the same level of randomness as DSA, so the only gain is speed and length, not security.

In response to the desired speeds of elliptic curves and the undesired security risks, another class of curves has gained some notoriety. EdDSA solves the same discrete log problem as DSA/ECDSA, but uses a different family of elliptic curves known as the Edwards Curve \(EdDSA uses a Twisted Edwards Curve\). While offering slight advantages in speed over ECDSA, its popularity comes from an improvement in security. Instead of relying on a random number for the nonce value, EdDSA generates a nonce deterministically as a hash making it collision resistant.

Taking a step back, the use of elliptic curves does not automatically guarantee some level of security. Not all curves are the same. Only a few curves have made it past rigorous testing. Luckily, the PKI industry has slowly come to adopt Curve25519 in particular for EdDSA. Put together that makes the public-key signature algorithm, Ed25519.

Implementation EdDSA is fairly new. Crypto++ and cryptlib do not currently support EdDSA. Compatibility Compatible with newer clients, Ed25519 has seen the largest adoption among the Edward Curves, though NIST also proposed Ed448 in their recent draft of SP 800-186. Performance Ed25519 is the fastest performing algorithm across all metrics. As with ECDSA, public keys are twice the length of the desired bit security. Security EdDSA provides the highest security level compared to key length. It also improves on the insecurities found in ECDSA.

```text
ssh-keygen -t ed25519 -a 200 -C "you@host" -f ~/.ssh/my_new_id_ed25519
```

The parameter `-a` defines the number of rounds for the key derivation function. The higher this number, the harder it will be for someone trying to brute-force the password of your private key — but also the longer you will have to wait during the initialization of an SSH login session.

### Extract the public key from a private key

```text
openssl rsa -in $priv_key -pubout -out $pub_key_name
```

### Generate a public key from the private key

```bash
ssh-keygen -y -f ~/.ssh/id_rsa > ~/.ssh/id_rsa.pub

#As a side note, the comment of the public key is lost,
# so you need to edit ~/.ssh/id_rsa.pub 
#Append a comment to the first line with a space between the comment and key data.
#An example public key is shown truncated below.

"ssh-rsa <key_data AAAA..snipped../VqDjtS5> user@hostname"
```

### Troubleshooting SSH

If connection is dropped upon connect:

* Don't use bash for this session, try dash \(or /bin/sh\): `ssh 127.0.0.1 /bin/dash`
* Use bash with command options to disable processing startup files:

  ```bash
  ssh 127.0.0.1 "bash --noprofile --norc"
  ```

## Remote Code Execution

Run commands on remote system without a shell through SSH with a "Herefile". `HERE` can be anything, but it must begin and end with the same word.

```bash
ssh $user@$hostname << HERE
 $command1
 $command2
HERE
```

## SCP

There are three main uses of SCP: to pull files from a remote host, to push files to a remote host, and to copy files between two remote hosts.

### Copy from remote host to local file:

```bash
scp $username@ip:$remote_file $local_directory
```

### Copy local file to remote host:

```bash
$ scp $local_file $username@$ip:$directory
```

### Copy local directory to remote directory:

```bash
scp -r $local_directory $username@$ip:$remote_directory
```

### Copy a file from one remote host to another:

```bash
scp $username@$host1:$directory/$file $username@$host2:$directory2
```

### Improve scp performance \(using blowfish algorithm\):

```bash
scp -c blowfish $local_file $username@$ip:$directory
```

### Use keyfile to login to remote host

\(`-i` must be the first parameter\)

```text
scp -i $keyfile [other parameters]
```

## Reverse Tunnels

[https://medium.com/@ryanwendel/forwarding-reverse-shells-through-a-jump-box-using-ssh-7111f1d55e3a](https://medium.com/@ryanwendel/forwarding-reverse-shells-through-a-jump-box-using-ssh-7111f1d55e3a)

[https://0xdf.gitlab.io/2020/08/10/tunneling-with-chisel-and-ssf-update.html](https://0xdf.gitlab.io/2020/08/10/tunneling-with-chisel-and-ssf-update.html)

[https://www.howtoforge.com/reverse-ssh-tunneling](https://www.howtoforge.com/reverse-ssh-tunneling)

* Let's assume that Destination's IP is 192.168.20.55 \(Linux box that you want to access\).
* You want to access from Linux client with IP 178.27.99.99.
* Destination \(192.168.20.55\) &lt;- \|NAT\| &lt;- Source \(178.27.99.99\)
* SSH from the destination to the source \(with public IP\) using the command below:

```text
ssh -R 19999:localhost:22 sourceuser@178.27.99.99
```

{% hint style="info" %}
\* port 19999 can be any unused local port.
{% endhint %}

1. Now you can SSH from source to destination through SSH tunneling:

```text
ssh localhost -p 19999
```

1. 3rd party servers can also access 192.168.20.55 through Destination \(178.27.99.99\).

Destination \(192.168.20.55\) &lt;- \|NAT\| &lt;- Source \(178.27.99.99\) &lt;- Bob's server

3.1 From Bob's server:

```text
ssh sourceuser@178.27.99.99
```

3.2 After the successful login to Source:

```text
ssh localhost -p 19999
```

{% hint style="info" %}
\* the connection between destination and source must be alive at all times. Tip: you may run a command \(e.g. watch, top\) on Destination to keep the connection active.
{% endhint %}

### Dynamic Reverse Tunnels

[https://blog.benpri.me/blog/2019/05/25/dynamic-reverse-tunnels-in-ssh/](https://blog.benpri.me/blog/2019/05/25/dynamic-reverse-tunnels-in-ssh/)

## Resources

* [https://starkandwayne.com/blog/jumping-seamlessly-thorough-tunnels-a-guide-to-ssh-proxy/](https://starkandwayne.com/blog/jumping-seamlessly-thorough-tunnels-a-guide-to-ssh-proxy/)
* [https://stackoverflow.com/questions/25084288/keep-ssh-session-alive](https://stackoverflow.com/questions/25084288/keep-ssh-session-alive)
* [https://softeng.oicr.on.ca/chen\_chen/2017/06/27/Using-Jump-Servers-in-SSH/](https://softeng.oicr.on.ca/chen_chen/2017/06/27/Using-Jump-Servers-in-SSH/)
* [https://www.cyberciti.biz/faq/linux-unix-osx-bsd-ssh-run-command-on-remote-machine-server/](https://www.cyberciti.biz/faq/linux-unix-osx-bsd-ssh-run-command-on-remote-machine-server/)
* [https://blog.benpri.me/blog/2019/05/25/dynamic-reverse-tunnels-in-ssh/](https://blog.benpri.me/blog/2019/05/25/dynamic-reverse-tunnels-in-ssh/)

If you like this content and would like to see more, please consider [buying me a coffee](https://www.buymeacoffee.com/zweilosec)!

