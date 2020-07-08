# DNS

## DNS

DNS reverse lookup recon: `dnsrecon -r <ip/subnet[127.0.0.0/24]> -n <ip_to_check>`

DNS zone transfer: `dig axfr <hostname> @<ip>` or `host -l <domain> <nameserver>`

add DNS server - Linux: `/etc/resolv.conf {nameserver <ip>}`

#### Add to hosts file for... TODO: add more

{% tabs %}
{% tab title="Linux" %}
`/etc/hosts`

```text
example here
```
{% endtab %}

{% tab title="Windows" %}
`C:\Windows\System32\drivers\etc\hosts`

```text
example here
```
{% endtab %}
{% endtabs %}





