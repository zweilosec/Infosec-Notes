# Persistence

{% hint style="success" %}
Hack Responsibly.

Always ensure you have **explicit** permission to access any computer system **before** using any of the techniques contained in these documents.  You accept full responsibility for your actions by applying any knowledge gained here.  
{% endhint %}

## Cron

## Startup Scripts

Add script to run at startup: `update-rc.d </path/to/the/script> defaults` \(needs 755 permissions\)

## Accounts

### Add Account and/or Password to /etc/passwd

Generate password:

`openssl passwd -1 -salt <username> <password>`

Then add to `/etc/passwd` file.  The format is:`<username>:<generated_password>:<UID>:<GUID>:root:/root:/bin/bash`

