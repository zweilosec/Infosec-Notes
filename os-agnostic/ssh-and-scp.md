# SSH & SCP

{% hint style="success" %}
Hack Responsibly.

Always ensure you have **explicit** permission to access any computer system **before** using any of the techniques contained in these documents.  You accept full responsibility for your actions by applying any knowledge gained here.  
{% endhint %}

## SSH

### SSH Keys

To generate a new SSH key for remote access:

```bash
ssh-keygen -f <filename>; cat <filename>;
#copy to remote host
echo <copied_key> > ./.ssh/authorized_keys #on remote host in /home/<user>/
chmod 600 <filename>; 
ssh -i <filename> <remotehost>
```

{% hint style="danger" %}
**Note**: AWS will _NOT_ accept this file. You have to strip off the `-----BEGIN PUBLIC KEY-----` and `-----END PUBLIC KEY-----` from the file. Save it and import and it should work in AWS.
{% endhint %}

and if you need to convert this format to ssh-rsa run : `ssh-keygen -f PublicKey.pub -i -mPKCS8`

To generate a public key from the private key:

```bash
ssh-keygen -y -f ~/.ssh/id_rsa > ~/.ssh/id_rsa.pub

#As a side note, the comment of the public key is lost,so you need to edit ~/.ssh/id_rsa.pub 
#append a comment to the first line with a space between the comment and key data. An example public key is shown truncated below.

"ssh-rsa <key data AAAA..../VqDjtS5> ubuntu@ubuntu"
```

Prior to using a new SSH key file it is necessary to change the permissions: `chmod 600 <keyfile>`

Using an SSH key to login to a remote computer: `ssh -i <keyfile> <username>@<IP>`

For those interested in the details inside the key file \(generated as explained above\): `openssl rsa -noout -text -inform PEM -in key.pub -pubin`; or for the private key file: `openssl rsa -noout -text -in key.private` which outputs as text on the console the actual components of the key \(modulus, exponents, primes, etc.\)

 To extract the public key from a private key: `openssl rsa -in privkey.pem -pubout -out key.pub`\`

### Troubleshooting SSH

If connection is dropped upon connect:

* Don't use bash for this session, try dash \(or /bin/sh\): `ssh 127.0.0.1 /bin/dash`
* Use bash with command options to disable processing startup files:

  ```bash
  ssh 127.0.0.1 "bash --noprofile --norc"
  ```

