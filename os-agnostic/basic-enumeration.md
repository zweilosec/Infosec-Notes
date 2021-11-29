# Basic Enumeration

## Nmap

```bash
#!/bin/bash
cat ip_list.txt | while read ip
do
nmap -sCV -p- -vvv -oA $ip.map $ip
done
```

The options I regularly use are:&#x20;

| `Flag`      | Purpose                                                                                                                     |
| ----------- | --------------------------------------------------------------------------------------------------------------------------- |
| `-p-`       | A shortcut which tells nmap to scan all ports                                                                               |
| `-vvv`      | Gives very verbose output so I can see the results as they are found, and also includes some information not normally shown |
| `-sC`       | Equivalent to `--script=default` and runs a collection of nmap enumeration scripts against the target                       |
| `-sV`       | Does a service version scan                                                                                                 |
| `-oA $name` | Saves all three formats (standard, greppable, and XML) of output with a filename of `$name`                                 |

### Host enumeration with cmd

```bash
for /L %i in (1,1,255) do @ping -n 1 10.10.10.%i | find "TTL="
```
