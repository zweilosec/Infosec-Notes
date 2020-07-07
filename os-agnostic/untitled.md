---
description: >-
  Misc notes that still need to be sorted through and sent to their proper
  homes.
---

# Unsorted

## Markdown

```text
{% hint style="warning" %} Warning box. Looks nice! {% endhint %}
```

{% hint style="danger" %}
Text between these will show up in a warning box. Looks nice! 

Can click on the icon to change it to something appropriate.
{% endhint %}

## MISC

### Check encoding of a text file

`vi -c 'let $enc = &fileencoding | execute "!echo Encoding: $enc" | q' <file_to_check>` check encoding of a text file \(needed especially when doing crypto with python, or cracking passwords with rockyou.txt\) [https://vim.fandom.com/wiki/Bash\_file\_encoding\_alias](https://vim.fandom.com/wiki/Bash_file_encoding_alias) \(make an alias for the above command\)

## Web

## WAF Bypass

## Reverse Engineering

find location of a string to manipulate and its offset `strings -t d <file> | grep <string to locate in ELF>`

## Windows

[https://resources.infosecinstitute.com/exploiting-nfs-share/](https://resources.infosecinstitute.com/exploiting-nfs-share/)

```text
showmount -e <ip>
<list of mounts>
mkdir /tmp/<foldername?
mount -t nfs <ip>:/<mount-folder> /tmp/<foldername>
```

## Linux

`apt-file search <binary name>` or `apt search <keyword>` to try to find packages on repositories

----------------------------------Added-below [https://www.maketecheasier.com/schedule-commands-linux-with-at/](https://www.maketecheasier.com/schedule-commands-linux-with-at/)

[https://github.com/Hackplayers/PsCabesha-tools/tree/master/Privesc](https://github.com/Hackplayers/PsCabesha-tools/tree/master/Privesc)

sudo rm --force $\(which stegcracker\) &lt;-- remove all instances of a certain program. Could be used with `find` instead of `which`. dangerous with --force!!

dd if=/dev/random of=/dev/sda1 bs=4M

[https://www.cyberciti.biz/faq/linux-unix-osx-bsd-ssh-run-command-on-remote-machine-server/](https://www.cyberciti.biz/faq/linux-unix-osx-bsd-ssh-run-command-on-remote-machine-server/)

```text
ssh server1 << HERE
 command1
 command2
HERE
```

[https://unix.stackexchange.com/questions/211817/copy-the-contents-of-a-file-into-the-clipboard-without-displaying-its-contents](https://unix.stackexchange.com/questions/211817/copy-the-contents-of-a-file-into-the-clipboard-without-displaying-its-contents) script to copy contents of file directly to clipboard

```text
#! /bin/bash
xclip -selection clipboard -i $@
```

add $PATH to: ~/.profile, then source ~/.profile

[https://stackoverflow.com/questions/305035/how-to-use-ssh-to-run-a-shell-script-on-a-remote-machine](https://stackoverflow.com/questions/305035/how-to-use-ssh-to-run-a-shell-script-on-a-remote-machine)

## Sockets

[https://pequalsnp-team.github.io/cheatsheet/socket-basics-py-js-rb](https://pequalsnp-team.github.io/cheatsheet/socket-basics-py-js-rb)

## Cryptography

[https://pequalsnp-team.github.io/cheatsheet/crypto-101](https://pequalsnp-team.github.io/cheatsheet/crypto-101)

checks to see if output is mostly ascii, if so then prints as a possible valid output

```text
char_count = sum(map(lambda x : 1 if x in string.ascii_letters else 0, dec))
    if char_count / len(dec) >= .6:
        print(dec)
```

## Password cracking

[https://md5decrypt.net/en/Password-cracking-wordlist-download/](https://md5decrypt.net/en/Password-cracking-wordlist-download/)

## steganography

StegCracker - [https://pypi.org/project/stegcracker/](https://pypi.org/project/stegcracker/) - bruteforce tool for finding `steghide`n passwords and extract \(works well using rockyou.txt as default wordlist\)

[http://bigwww.epfl.ch/demo/ip/demos/FFT/](http://bigwww.epfl.ch/demo/ip/demos/FFT/) - fast fourier transfor online tool. Test this for stego images that cant be found with other stuff

[https://0xrick.github.io/lists/stego/](https://0xrick.github.io/lists/stego/) [https://github.com/DominicBreuker/stego-toolkit/blob/master/README.md\#tools](https://github.com/DominicBreuker/stego-toolkit/blob/master/README.md#tools) [https://pequalsnp-team.github.io/cheatsheet/steganography-101](https://pequalsnp-team.github.io/cheatsheet/steganography-101)

[https://georgeom.net/StegOnline/checklist](https://georgeom.net/StegOnline/checklist) 1. File

Just to be sure what file you are facing with, check its type with type filename.

1. Strings

View all strings in the file with strings -n 7 -t x filename.png.

We use -n 7 for strings of length 7+, and -t x to view- their position in the file.

Alternatively, you can view strings on this site once an image has been uploaded.

Custom Example

1. Exif

Check all image metadata. I would recommend Jeffrey's Image Metadata Viewer for in-depth analysis.

Custom Example

1. Binwalk

We use binwalk to check image's for hidden embedded files.

My preferred syntax is binwalk -Me filename.png. -Me is used to recursively extract any files.

Custom Example

1. pngcheck

We can use pngcheck to look for optional/correct broken chunks. This is vital if the image appears corrupt.

Run pngcheck -vtp7f filename.png to view all info.

v is for verbose, t and 7 display tEXt chunks, p displays contents of some other optional chunks and f forces continuation after major errors are encountered. Related write-ups:

```text
PlaidCTF 2015
SECCON Quals 2015
```

1. Explore Colour & Bit Planes

Images can be hidden inside of the colour/bit planes. Upload your image to this site here. On the image menu page, explore all options in the top panel \(i.e. Full Red, Inverse, LSB etc\).

Go to "Browse Bit Planes", and browse through all available planes.

If there appears to be some static at the top of any planes, try extracting the data from them in the "Extract Files/Data" menu. Related write-ups:

```text
MicroCTF 2017
CSAW Quals 2016
ASIS Cyber Security Contest Quals 2014
Cybersocks Regional 2016
```

1. Extract LSB Data

As mentioned in step 5, there could be some static in bit planes. If so, navigate to the "Extract Files/Data" page, and select the relevant bits.

Custom Example

1. Check RGB Values

ASCII Characters/other data can be hidden in the RGB\(A\) values of an image.

Upload your image here, and preview the RGBA values. Try converting them to text, and see if any flag is found. It might be worth looking at just the R/G/B/A values on their own. Related write-ups:

```text
MMA-CTF-2015
```

1. Found a password? \(Or not\)

If you've found a password, the goto application to check should be steghide. Bear in mind that steghide can be used without a password, too.

You can extract data by running steghide extract -sf filename.png.

It might also be worth checking some other tools:

```text
OpenStego
Stegpy
Outguess
jphide
```

Related write-ups:

```text
Pragyan CTF 2017
Xiomara 2019
CSAW Quals 2015
BlackAlps Y-NOT-CTF (JFK Challenge)
```

1. Browse Colour Palette

If the PNG is in type 3, you should look through the colour palette.

This site has a feature for randomizing the colour palette, which may reveal the flag. You can also browse through each colour in the palette, if the flag is the same colour.

It may also be worth looking at the palette indexes themselves, as a string may be visible from there. Related write-ups:

```text
Plain CTF 2014
```

1. Pixel Value Differencing \(PVD/MPVD\)

It would be rare to have a case of PVD where you're not explicitly told that this is the steganographic method, as it's very niche.

However, this is a method where the differences between pixel pairs are measured slightly adjusted in order to hide data.

A full paper on this process can be found here. A PVD feature to this site would be appreciated! Related write-ups:

```text
TJCTF 2019
MMA-CTF 2015
```

