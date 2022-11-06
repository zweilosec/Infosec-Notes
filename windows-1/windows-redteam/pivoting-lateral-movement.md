# Pivoting/Lateral Movement

{% hint style="success" %}
Hack Responsibly.

Always ensure you have **explicit** permission to access any computer system **before** using any of the techniques contained in these documents. You accept full responsibility for your actions by applying any knowledge gained here.
{% endhint %}

Not much here yet...please feel free to contribute at [https://www.github.com/zweilosec](https://github.com/zweilosec)

## Forward ports using built-in firewall

### Using netsh

To set up a port forwarder using `netsh` run the below commands as an administrator.

```batch
netsh interface portproxy add v4tov4 listenport=$lport connectport=$rport connectaddress=$ip
```

Substitute **`$lport`**, **`$rport`**, and **`$ip`** with the local port, remote port, and IP to forward to, respectively.
