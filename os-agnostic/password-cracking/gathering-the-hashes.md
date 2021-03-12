# Gathering the Hashes

{% hint style="success" %}
Hack Responsibly.

Always ensure you have **explicit** permission to access any computer system **before** using any of the techniques contained in these documents.  You accept full responsibility for your actions by applying any knowledge gained here.  
{% endhint %}

## Extracting hashes from text files

### Extract md5 hashes

Using egrep:

```bash
egrep -oE '(^|[^a-fA-F0-9])[a-fA-F0-9]{32}([^a-fA-F0-9]|$)' $hash_directory/* | egrep -o '[a-fA-F0-9]{32}' > $out_hash_file
```

Alternatively, with sed:

```bash
sed -rn 's/.*[^a-fA-F0-9]([a-fA-F0-9]{32})[^a-fA-F0-9].*/1/p' $hash_directory/* > $out_hash_file
```

{% hint style="info" %}
The two regular expressions above can be used for SHA1, SHA256 and other unsalted hashes represented in hex. The only thing you need to do is change the value**`{32}`**to the corresponding length for your desired hash type.
{% endhint %}

### Extract MySQL-Old hashes

```bash
grep -e "[0-7][0-9a-f]{7}[0-7][0-9a-f]{7}" $hash_directory/* > $out_hash_file
```

### Extract blowfish hashes

```bash
grep -e "$2a\$\08\$(.){75}" $hash_directory/* > $out_hash_file
```

### Extract Joomla hashes

```bash
egrep -o "([0-9a-zA-Z]{32}):(w{16,32})" $hash_directory/* > $out_hash_file
```

### Extract Vbulletin hashes

```bash
egrep -o "([0-9a-zA-Z]{32}):(S{3,32})" $hash_directory/* > $out_hash_file
```

### Extract phpBB3-MD5

```bash
egrep -o '$H$S{31}' $hash_directory/* > $out_hash_file
```

### Extract Wordpress-MD5

```bash
egrep -o '$P$S{31}' $hash_directory/* > $out_hash_file
```

### Extract Drupal 7

```bash
egrep -o '$S$S{52}' $hash_directory/* > $out_hash_file
```

### Extract 'old' Unix-MD5

```bash
egrep -o '$1$w{8}S{22}' $hash_directory/* > $out_hash_file
```

### Extract MD5-APR1

```bash
egrep -o '$apr1$w{8}S{22}' $hash_directory/* > $out_hash_file
```

### Extract sha512crypt, SHA512 \(Unix\)

```bash
egrep -o '$6$w{8}S{86}' $hash_directory/* > $out_hash_file
```

## Extracting non-hash strings from text files

### Extract e-mails

```bash
grep -E -o "\b[a-zA-Z0-9.#?$*_-]+@[a-zA-Z0-9.#?$*_-]+.[a-zA-Z0-9.-]+\b" $text_directory/* > $email_list
```

### Extract URLs \(HTTP only\)

```bash
grep http | grep -shoP 'http.*?[" >]' $text_directory/* > $HTTP_URL_list
```

### Extract URLs \(HTTP, HTTPS, Gopher, FTP, mailto, etc\)

```bash
grep -E '(((http|https|ftp|gopher)|mailto)[.:][^ >" ]*|www.[-a-z0-9.]+)[^ .,; >">):]' $text_directory/* > $HTTP_URL_list
```

{% hint style="info" %}
**Note**: if grep returns "Binary file \(standard input\) matches" use the following approaches:

**`tr '[\000-\011\013-\037177-377]' '.' < *.log | grep -E $REGEX`** 

or

**`cat -v *.log | egrep -o $REGEX`**
{% endhint %}

### Extract Floating point numbers

`# grep -E -o "^[-+]?[0-9]*.?[0-9]+([eE][-+]?[0-9]+)?$" *.txt > floats.txt`

### Extract credit card data

Visa `# grep -E -o "4[0-9]{3}[ -]?[0-9]{4}[ -]?[0-9]{4}[ -]?[0-9]{4}" *.txt > visa.txt`

MasterCard `# grep -E -o "5[0-9]{3}[ -]?[0-9]{4}[ -]?[0-9]{4}[ -]?[0-9]{4}" *.txt > mastercard.txt`

American Express `# grep -E -o "\b3[47][0-9]{13}\b" *.txt > american-express.txt`

Diners Club `# grep -E -o "\b3(?:0[0-5]|[68][0-9])[0-9]{11}\b" *.txt > diners.txt`

Discover `# grep -E -o "6011[ -]?[0-9]{4}[ -]?[0-9]{4}[ -]?[0-9]{4}" *.txt > discover.txt`

JCB `# grep -E -o "\b(?:2131|1800|35d{3})d{11}\b" *.txt > jcb.txt`

AMEX `# grep -E -o "3[47][0-9]{2}[ -]?[0-9]{6}[ -]?[0-9]{5}" *.txt > amex.txt`

### Extract Social Security Number \(SSN\)

`# grep -E -o "[0-9]{3}[ -]?[0-9]{2}[ -]?[0-9]{4}" *.txt > ssn.txt`

### Extract Indiana Driver License Number

`# grep -E -o "[0-9]{4}[ -]?[0-9]{2}[ -]?[0-9]{4}" *.txt > indiana-dln.txt`

### Extract US Passport Cards

`# grep -E -o "C0[0-9]{7}" *.txt > us-pass-card.txt`

### Extract US Passport Number

`# grep -E -o "[23][0-9]{8}" *.txt > us-pass-num.txt`

### Extract US Phone Numberss

`# grep -Po 'd{3}[s-_]?d{3}[s-_]?d{4}' *.txt > us-phones.txt`

### Extract ISBN Numbers

`# egrep -a -o "\bISBN(?:-1[03])?:? (?=[0-9X]{10}$|(?=(?:[0-9]+[- ]){3})[- 0-9X]{13}$|97[89][0-9]{10}$|(?=(?:[0-9]+[- ]){4})[- 0-9]{17}$)(?:97[89][- ]?)?[0-9]{1,5}[- ]?[0-9]+[- ]?[0-9]+[- ]?[0-9X]\b" *.txt > isbn.txt`



If you like this content and would like to see more, please consider [buying me a coffee](https://www.buymeacoffee.com/zweilosec)!

