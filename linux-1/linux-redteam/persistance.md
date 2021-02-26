# Persistence

Not much here yet...please feel free to contribute at [https://www.github.com/zweilosec](https://github.com/zweilosec)

{% hint style="success" %}
Hack Responsibly.

Always ensure you have **explicit** permission to access any computer system **before** using any of the techniques contained in these documents.  You accept full responsibility for your actions by applying any knowledge gained here.  
{% endhint %}

## Cron

## Startup Scripts

Add script to run at startup: `update-rc.d </path/to/the/script> defaults` \(needs 755 permissions\)

## Accounts

### Add Account & Password to /etc/passwd

* Generate password with `openssl passwd -1 -salt $username $password` 
* Add to `/etc/passwd` file which is in the format: 
  * `$UserName:$generated_password:$UID:$GUID:$comment:$home_dir:$default_shell` 
  * `$comment` is usually the user's Full Name.  Check the `/etc/passwd` file to ensure you match local standards.
  * \(assumes you have write privilege to this file!\). 

