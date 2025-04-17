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

1. From the `attacker_machine`, generate a keypair: `ssh-keygen -t ed25519`
2. Copy the contents from the public key `$keyfile.pub` into the `.ssh/authorized_keys` file of the `target_machine`
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

Host target-1
    HostName 192.168.221.32
    User piUser
    IdentityFile /home/kali/.ssh/to_target-1.key
    ProxyJump jumpBox-2
```

In the case of the SSH server side, replace `ServerAliveInterval` with `ClientAliveInterval` and put it in the file `/etc/ssh/sshd_config`. This is especially useful for reverse tunnels.

The above configuration shows an example of allowing a user to use a simplified command such as`ssh jumpbox-1` in place of having to type out `user@hostName -i /path/to/keyfile` and supplies the relevant information automatically. This reduces the need for remembering usernames, IPs, or long and complex DNS names.

### ProxyJump <a id="proxyjump"></a>

By having SSH keys for each of our jump boxes and the target device on our local machine, we can simplify the process of logging in through each machine quite a bit. The `ProxyJump` directive signifies which machine you need to jump through to get to the next machine in the proxy chain.

This simple change allows a user to simply give the command `ssh target-1`, wait a bit for all of the connections to be made, and pop a shell on the `target-1` device.

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

SSH keys are a secure way to authenticate to remote systems, either as a second authentication factor or as a replacement for passwords. Below is a guide to generating, using, and managing SSH keys effectively.

#### Generating SSH Keys

To generate a new SSH key for remote access, use the `ssh-keygen` command with the desired algorithm and key size:

```bash
# Generate an RSA key with 4096 bits
ssh-keygen -t rsa -b 4096

# Generate an ECDSA key with 521 bits
ssh-keygen -t ecdsa -b 521

# Generate an Ed25519 key (recommended for modern use)
ssh-keygen -t ed25519
```

#### Key Algorithms Comparison

| Algorithm   | Key Size (bits) | Strength         | Pros                          | Cons                          |
|-------------|-----------------|------------------|-------------------------------|-------------------------------|
| RSA         | 2048/4096       | Strong (4096 recommended) | Widely supported, secure    | Larger key size, slower      |
| DSA         | 1024            | Weak             | Legacy support               | Deprecated, insecure         |
| ECDSA       | 256/384/521     | Strong           | Smaller keys, faster         | Requires good randomness     |
| Ed25519     | Fixed (256)     | Very Strong      | Fast, secure, small key size | Limited client compatibility |

#### Using SSH Keys

1. **Generate a Key Pair**: Use `ssh-keygen` as shown above.
2. **Copy Public Key to Remote Host**:
   ```bash
   ssh-copy-id -i $key_file $user@$remote_host
   ```
3. **Connect Using the Key**:
   ```bash
   ssh -i $key_file $user@$remote_host
   ```

#### Key File Details

To inspect the details of a key file:

- Public key:
  ```bash
  openssl rsa -in $priv_key -pubout -out $pub_key_name
  ```
- Private key:
  ```bash
  openssl rsa -noout -text -in key.private
  ```

#### Notes on Key Usage

- **Permissions**: Ensure private keys have proper permissions:
  ```bash
  chmod 600 $key_file
  ```
- **AWS Compatibility**: AWS requires keys without `-----BEGIN PUBLIC KEY-----` and `-----END PUBLIC KEY-----` headers. Use:
  ```bash
  ssh-keygen -f PublicKey.pub -i -mPKCS8
  ```

#### Extracting Public Key from Private Key

To extract the public key from a private key:

```bash
openssl rsa -in $priv_key -pubout -out $pub_key_name
```

#### Generating Public Key from Private Key

To generate a public key from a private key:

```bash
ssh-keygen -y -f ~/.ssh/id_rsa > ~/.ssh/id_rsa.pub
```

> **Note**: The comment of the public key is lost during this process. You may need to manually append a comment to the first line of the public key file (ex: ~/.ssh/id_rsa.pub). Append a comment to the first line with a space between the comment and key data. An example public key is shown truncated below.

Example:
```bash
ssh-rsa <key_data AAAA..snipped../VqDjtS5> user@hostname
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

## Local Forward Tunnels

Local forward tunnels allow you to forward a port from your local machine to a remote server. This is useful for accessing services on a remote server that are not directly accessible from your local machine.

### Setting Up a Local Forward Tunnel

To set up a local forward tunnel, use the `-L` option with the `ssh` command. The syntax is as follows:

```bash
ssh -L [local_port]:[remote_host]:[remote_port] [user]@[remote_server]
```

- **local_port**: The port on your local machine that you want to forward.
- **remote_host**: The host on the remote server to which you want to forward traffic.
- **remote_port**: The port on the remote host to which you want to forward traffic.
- **user**: The username for the remote server.
- **remote_server**: The address of the remote server.

### Example

Suppose you want to access a web application running on port 8080 of a `target_machine` through an intermediate SSH server (`intermediate_server`). You can set up a local forward tunnel as follows:

```bash
ssh -L 8080:target_machine:8080 user@intermediate_server
```

After running this command, you can access the web application by navigating to `http://localhost:8080` in your web browser.

### Notes

- The local port (e.g., 8080) must not be in use on your local machine.
- You can use `-N` to prevent the SSH session from executing commands, keeping the tunnel open:

```bash
ssh -L 8080:target_machine:8080 user@intermediate_server -N
```

- Use `-f` to run the SSH session in the background:

```bash
ssh -L 8080:target_machine:8080 user@intermediate_server -N -f
```

Local forward tunnels are particularly useful for securely accessing internal services or databases on a remote network.

## Reverse Tunnels

[https://medium.com/@ryanwendel/forwarding-reverse-shells-through-a-jump-box-using-ssh-7111f1d55e3a](https://medium.com/@ryanwendel/forwarding-reverse-shells-through-a-jump-box-using-ssh-7111f1d55e3a)

[https://0xdf.gitlab.io/2020/08/10/tunneling-with-chisel-and-ssf-update.html](https://0xdf.gitlab.io/2020/08/10/tunneling-with-chisel-and-ssf-update.html)

[https://www.howtoforge.com/reverse-ssh-tunneling](https://www.howtoforge.com/reverse-ssh-tunneling)

* Let's assume that the `target_machine`'s IP is 192.168.20.55 (Linux box that you want to access).
* You want to access it from the `local_machine` with IP 178.27.99.99.
* `target_machine` <- |NAT| <- `local_machine`
* SSH from the `target_machine` to the `local_machine` (with public IP) using the command below:

```text
ssh -R 19999:localhost:22 sourceuser@local_machine
```

{% hint style="info" %}
\* port 19999 can be any unused local port.
{% endhint %}

1. Now you can SSH from `local_machine` to `target_machine` through SSH tunneling:

```text
ssh localhost -p 19999
```

1. 3rd party servers can also access `target_machine` through `local_machine`.

`target_machine` <- |NAT| <- `local_machine` <- Target web server

3.1 From the Target web server:

```text
ssh sourceuser@local_machine
```

3.2 After the successful login to `local_machine`:

```text
ssh localhost -p 19999
```

{% hint style="info" %}
\* the connection between `target_machine` and `local_machine` must be alive at all times. Tip: you may run a command \(e.g. watch, top\) on `target_machine` to keep the connection active.
{% endhint %}

### Dynamic Reverse Tunnels

[https://blog.benpri.me/blog/2019/05/25/dynamic-reverse-tunnels-in-ssh/](https://blog.benpri.me/blog/2019/05/25/dynamic-reverse-tunnels-in-ssh/)

## Troubleshooting

#### Troubleshooting Connection Drops

- If connection drops immediately after connecting:
  - Don't use bash for this session, try another shell such as dash \(or /bin/sh\):
    ```bash
    ssh 127.0.0.1 /bin/dash
    ```
  - Use bash with command options to disable processing startup files (.profile, .bashrc):
    ```bash
    ssh 127.0.0.1 "bash --noprofile --norc"
    ```

- **Permission Denied Errors**:
  - **Issue**: Encountering "Permission denied" when trying to SSH or SCP.
  - **Workaround**: Ensure the private key file has the correct permissions:
    ```bash
    chmod 600 ~/.ssh/id_rsa
    ```
    Verify the username and hostname are correct, and ensure the public key is added to the `~/.ssh/authorized_keys` file on the remote server.

- **Connection Timeout**:
  - **Issue**: SSH connection times out.
  - **Workaround**: Check if the remote server is reachable using `ping` or `traceroute`. Ensure the SSH port (default 22) is open and not blocked by a firewall. Use the `-v` flag with SSH for verbose output to debug:
    ```bash
    ssh -v user@hostname
    ```

- **Host Key Verification Failed**:
  - **Issue**: SSH fails due to a changed host key.
  - **Workaround**: This usually happens if the server's SSH key has changed. Remove the old key from the `~/.ssh/known_hosts` file:
    ```bash
    ssh-keygen -R hostname
    ```
    Then reconnect to add the new key.

- **Too Many Authentication Failures**:
  - **Issue**: SSH fails with "Too many authentication failures".
  - **Workaround**: This can occur if the SSH client tries multiple keys before the correct one. Use the `-i` option to specify the correct key explicitly:
    ```bash
    ssh -i ~/.ssh/id_rsa user@hostname
    ```

- **Broken Pipe Errors**:
  - **Issue**: SSH session disconnects with a "broken pipe" error.
  - **Workaround**: Increase the `ServerAliveInterval` and `ServerAliveCountMax` settings in your SSH config to keep the connection alive:
    ```text
    Host *
        ServerAliveInterval 60
        ServerAliveCountMax 5
    ```

#### Additional Common Issues and Workarounds

- **SCP File Transfer Fails**:
  - **Issue**: SCP fails with "No such file or directory".
  - **Workaround**: Double-check the file paths on both the local and remote systems. Use absolute paths to avoid ambiguity.

- **SSH Hangs on Connection**:
  - **Issue**: SSH hangs indefinitely when trying to connect.
  - **Workaround**: Use the `-vvv` flag for detailed debugging output. Check for DNS resolution issues and try connecting using the server's IP address instead of the hostname.

- **Key Mismatch Errors**:
  - **Issue**: Public key authentication fails due to a key mismatch.
  - **Workaround**: Ensure the correct private key is being used and that the corresponding public key is present in the `~/.ssh/authorized_keys` file on the remote server. Verify the key format and regenerate the key pair if necessary.

## Resources

* [https://starkandwayne.com/blog/jumping-seamlessly-thorough-tunnels-a-guide-to-ssh-proxy/](https://starkandwayne.com/blog/jumping-seamlessly-thorough-tunnels-a-guide-to-ssh-proxy/)
* [https://stackoverflow.com/questions/25084288/keep-ssh-session-alive](https://stackoverflow.com/questions/25084288/keep-ssh-session-alive)
* [https://softeng.oicr.on.ca/chen\_chen/2017/06/27/Using-Jump-Servers-in-SSH/](https://softeng.oicr.on.ca/chen_chen/2017/06/27/Using-Jump-Servers-in-SSH/)
* [https://www.cyberciti.biz/faq/linux-unix-osx-bsd-ssh-run-command-on-remote-machine-server/](https://www.cyberciti.biz/faq/linux-unix-osx-bsd-ssh-run-command-on-remote-machine-server/)
* [https://blog.benpri.me/blog/2019/05/25/dynamic-reverse-tunnels-in-ssh/](https://blog.benpri.me/blog/2019/05/25/dynamic-reverse-tunnels-in-ssh/)
* [Comparing SSH Keys](https://goteleport.com/blog/comparing-ssh-keys/)
* [Which Host Key Algorithm is Best?](https://security.stackexchange.com/questions/131010/which-host-key-algorithm-is-best-to-use-for-ssh)


If you like this content and would like to see more, please consider [buying me a coffee](https://www.buymeacoffee.com/zweilosec)!

