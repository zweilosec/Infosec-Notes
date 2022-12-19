# Persistence

{% hint style="success" %}
Hack Responsibly.

Always ensure you have **explicit** permission to access any computer system **before** using any of the techniques contained in these documents.  You accept full responsibility for your actions by applying any knowledge gained here. &#x20;
{% endhint %}

{% hint style="danger" %}
Not much here yet...please feel free to contribute at [my GitHub page](https://github.com/zweilosec/Infosec-Notes).
{% endhint %}

## Cron

## Startup Scripts

Add script to run at startup: `update-rc.d </path/to/the/script> defaults` (needs 755 permissions)

## Accounts

### Add Account & Password to /etc/passwd

* Generate password with `openssl passwd -1 -salt $username $password`&#x20;
* Add to `/etc/passwd` file which is in the format:&#x20;
  * `$UserName:$generated_password:$UID:$GUID:$comment:$home_dir:$default_shell`&#x20;
  * `$comment` is usually the user's Full Name.  Check the `/etc/passwd` file to ensure you match local standards.
  * (assumes you have write privilege to this file!).&#x20;

If you like this content and would like to see more, please consider [buying me a coffee](https://www.buymeacoffee.com/zweilosec)!
