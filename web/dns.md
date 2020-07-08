# DNS

## DNS

DNS reverse lookup recon: `dnsrecon -r <ip/subnet[127.0.0.0/24]> -n <ip_to_check>`

DNS zone transfer: `dig axfr <hostname> @<ip>` or `host -l <domain> <nameserver>`

add DNS server - Linux: `/etc/resolv.conf {nameserver <ip>}`

add to Hosts - Linux: `/etc/hosts`

add to Hosts - Windows: `C:\Windows\System32\drivers\etc\hosts`

