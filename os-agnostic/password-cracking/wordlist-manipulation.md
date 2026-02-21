# Wordlist Manipulation

{% hint style="success" %}
Hack Responsibly.

Always ensure you have **explicit** permission to access any computer system **before** using any of the techniques contained in these documents.  You accept full responsibility for your actions by applying any knowledge gained here. &#x20;
{% endhint %}

## Wordlist Manipulation

### Password file merge, sort by unique entries:

Sorts all passwords in all files in a directory, removes duplicates, and writes them to a single file

```bash
find . -maxdepth 1 -type f ! -name ".*" -exec cat {} + | sort -u -o $out_file
```

[https://unix.stackexchange.com/questions/365114/efficiently-merge-sort-unique-large-number-of-text-files](https://unix.stackexchange.com/questions/365114/efficiently-merge-sort-unique-large-number-of-text-files)

### Remove the space character with sed

`# sed -i 's/ //g' file.txt` OR `# egrep -v "^[[:space:]]*$" file.txt`

### Remove the last space character with sed

`# sed -i s/.$// file.txt`

### Sorting Wordlists by Length

`# awk '{print length, $0}' rockyou.txt | sort -n | cut -d " " -f2- > rockyou_length-list.txt`

### Convert uppercase to lowercase and the opposite

```
# tr [A-Z] [a-z] < file.txt > lower-case.txt
# tr [a-z] [A-Z] < file.txt > upper-case.txt
```

### Remove blank lines with sed

```bash
sed -i '/^$/d' $text_file
```

### Remove a specific character with sed

```bash
sed -i "s/$char//" $text_file
```

### Delete all instances of a string with sed

```bash
cat $text_file | sed -e "s/$string//g" > $out_text_file
```

### Replace characters with tr

`# tr '@' '#' < emails.txt` OR `# sed 's/@/#' file.txt`

### Print specific columns with awk or cut

`# awk -F "," '{print $3}' infile.csv > outfile.csv` OR `# cut -d "," -f 3 infile.csv > outfile.csv`

> **Note:** if you want to isolate all columns after column 3 put a `-` (dash) after the number: `# cut -d "," -f 3- infile.csv > outfile.csv`

### Generate Random Passwords with /dev/urandom

```
tr -dc 'a-zA-Z0-9._!@#$%^&*()' < /dev/urandom | fold -w 8 | head -n 500000 > wordlist.txt
tr -dc 'a-zA-Z0-9-_!@#$%^&*()_+{}|:<>?=' < /dev/urandom | fold -w 12 | head -n 4
base64 /dev/urandom | tr -d '[^:alnum:]' | cut -c1-10 | head -2
tr -dc 'a-zA-Z0-9' < /dev/urandom | fold -w 10 | head -n 4
tr -dc 'a-zA-Z0-9-_!@#$%^&*()_+{}|:<>?=' < /dev/urandom | fold -w 12 | head -n 4 | grep -i '[!@#$%^&*()_+{}|:<>?=]'
tr -dc '[:print:]' < /dev/urandom | fold -w 10| head -n 10
tr -cd '[:alnum:]' < /dev/urandom | fold -w30 | head -n2
```

### Remove Parenthesis with tr

`# tr -d '()' < in_file > out_file`

### Generate wordlists from your file names

`# ls -A | sed 's/regexp/& /g'`

### Process text files when cat is unable to handle strange characters

`# sed 's/([[:alnum:]]*)[[:space:]]*(.)(..*)/12/' *.txt`

### Generate length based wordlists with awk

`# awk 'length == 10' file.txt > 10-length.txt`

### Merge two different txt files

`# paste -d' ' file1.txt file2.txt > new-file.txt`

### Faster sorting

`# export alias sort='sort --parallel=<number_of_cpu_cores> -S <amount_of_memory>G ' && export LC_ALL='C' && cat file.txt | sort -u > new-file.txt`

### Mac to unix

`# tr '\015' '\012' < in_file > out_file`

### Dos to Unix

`# dos2unix file.txt`

### Unix to Dos

`# unix2dos file.txt`

### Extract the difference between two files

`# grep -F -v -f file1.txt -w file2.txt > file3.txt`

### Isolate specific line numbers with sed

`# sed -n '1,100p' test.file > file.out`

### Create Wordlists from PDF files

`# pdftotext file.pdf file.txt`

### Find the line number of a string inside a file

`# awk '{ print NR, $0 }' file.txt | grep "string-to-grep"`

## **Create your own Dictionaries**

Find as much information about the target as you can and generate a custom dictionary. Tools that may help:

### Crunch

Create a wordlist with lengths from 4 to 6 using a specified character set

```bash
crunch 4 6 0123456789ABCDEF -o crunch1.txt
```

Create a list of 4 character "words" using the character set mixalpha (inside file charset.lst)

```bash
crunch 4 4 -f /usr/share/crunch/charset.lst mixalpha
```

Character set examples:

```
@ Lower case alpha characters
, Upper case alpha characters
% Numeric characters
^ Special characters including spaces
```

Using this you can make wordlists using custom character sets with shortcuts

```
crunch 6 8 -t ,@@^^%%
```

### Cewl

Generate a wordlist based on a target website

```bash
cewl example.com -m 5 -w words.txt
```

### CUPP

Generate passwords based on your knowledge of the victim (names, significant dates, etc...)

```
python3 cupp.py -h
```

* [https://github.com/Mebus/cupp](https://github.com/Mebus/cupp)

### [pydictor](https://github.com/LandGrey/pydictor)

### Hashcat

Hashcat is a powerful password recovery tool that can also be used to generate wordlists using rules and masks.

#### Generate wordlists with masks

Create passwords matching a specific pattern (e.g., 8 characters with uppercase, lowercase, and numbers):

```bash
hashcat --stdout -a 3 ?u?l?l?l?l?l?l?l > wordlist.txt
```

Mask character sets:
- `?l` - lowercase letters
- `?u` - uppercase letters
- `?d` - digits
- `?s` - special characters
- `?a` - all characters

#### Apply rules to existing wordlists

Generate variations of passwords using rule-based attacks:

```bash
hashcat --stdout -a 0 wordlist.txt -r rules/best64.rule > mutated_wordlist.txt
```

#### Combine multiple wordlists

```bash
hashcat --stdout -a 1 wordlist1.txt wordlist2.txt > combined_wordlist.txt
```

#### Rule examples

- `c` - capitalize first letter
- `l` - lowercase all letters
- `u` - uppercase all letters
- `r` - reverse the word
- `d` - duplicate
- `$X` - append character X
- `^X` - prepend character X

Common rule files located in `/usr/share/hashcat/rules/`:
- `best64.rule`
- `dive.rule`
- `OneRuleToRuleThemAll.rule`

## Rules

* TODO: add more
* [https://github.com/NotSoSecure/password\_cracking\_rules/blob/master/OneRuleToRuleThemAll.rule](https://github.com/NotSoSecure/password\_cracking\_rules/blob/master/OneRuleToRuleThemAll.rule)

If you like this content and would like to see more, please consider [buying me a coffee](https://www.buymeacoffee.com/zweilosec)!
