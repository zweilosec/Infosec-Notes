# SSH & SCP

## SSH

generate ssh key for remote access:

```bash
ssh-keygen -f <filename>; cat <filename>;
#copy to remote host
echo <copied_key> > ./.ssh/authorized_keys #on remote host in /home/<user>/
chmod 600 <filename>; 
ssh -i <filename> <remotehost>
```

generate public key from private key:

```bash
ssh-keygen -y -f ~/.ssh/id_rsa > ~/.ssh/id_rsa.pub

#As a side note, the comment of the public key is lost,so you need to edit ~/.ssh/id_rsa.pub 
#append a comment to the first line with a space between the comment and key data. An example public key is shown truncated below.

"ssh-rsa AAAA..../VqDjtS5 ubuntu@ubuntu"
```

If connection is dropped upon connect:

* Don't use bash for this session, try dash \(or /bin/sh\): `ssh 127.0.0.1 /bin/dash`
* Use bash with command options to disable processing startup files:

  ```bash
  ssh 127.0.0.1 "bash --noprofile --norc"
  ```

