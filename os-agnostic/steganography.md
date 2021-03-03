# Steganography

{% hint style="success" %}
Hack Responsibly.

Always ensure you have **explicit** permission to access any computer system **before** using any of the techniques contained in these documents.  You accept full responsibility for your actions by applying any knowledge gained here.  
{% endhint %}

## Steganography Checklist

TODO: clean up steganography CTF checklist (issue [#17](https://github.com/zweilosec/Infosec-Notes/issues/17))
* Properly link all tools and attributions
* Add description for what the checklist is for
* Make sure all tools still exist
* Check author's site for updates
* Add "Resources" section at bottom
* Find link for "feature for randomizing the color palette" (section 10.ii) on author's site

* credit to [Ge0rg3](https://github.com/Ge0rg3) for this great checklist.  His site also has custom examples for each situation below.

1. File
   1. Just to be sure what filetype you are facing, check with `type <filename>`.
   2. If something seems strange, the next step would be to open the file with `GHex` and check the files "magic bytes". Sometimes they are missing, or have been corrupted or obscured.
2. Strings
   1. View all strings in the file with `strings -n 6 -t x <filename>`.
      1. I typically use `-n 6` to find strings of length 6+, and `-t x` to view their position in the file.
   2. Alternatively, you can view strings on [this site](https://georgeom.net/StegOnline/upload) once an image has been uploaded.
3. Exif
   1. Check all image metadata. I would recommend [Jeffrey's Image Metadata Viewer](http://exif.regex.info/exif.cgi) for in-depth analysis. `Exiftool` is another common one.
4. Binwalk
   1. Next you can use `binwalk` to check images for hidden embedded files.
   2. My preferred syntax is `binwalk -Me <filename>`. `-Me` is used to recursively extract any files.
5. pngcheck
   1. We can use `pngcheck` to look for optional/correct broken chunks. This is vital if the image appears corrupt.
   2. Run `pngcheck -vtp7f <filename>` to view all info.
   3. `-v` is for verbose, `-t` and `-7` display tEXt chunks, `-p` displays contents of some other optional chunks and `-f` forces continuation if major errors are encountered. 
   4. Related write-ups: PlaidCTF 2015, SECCON Quals 2015
6. Explore Color & Bit Planes
   1. Images can be hidden inside of the color/bit planes. Upload your image to [this site](https://georgeom.net/StegOnline/upload), then on the image menu page explore all options in the top panel \(i.e. Full Red, Inverse, LSB etc\).
   2. Go to "Browse Bit Planes", and browse through all available planes.
   3. If there appears to be some static at the top of any planes, try extracting the data from them in the "Extract Files/Data" menu. 
   4. Related write-ups: MicroCTF 2017, CSAW Quals 2016, ASIS Cyber Security Contest Quals 2014, Cybersocks Regional 2016
7. Extract Least Significant Bit \(LSB\) Data
   1. As mentioned in step 6.3, there could be some static in bit planes. If so, navigate to the "Extract Files/Data" page, and select the relevant bits.
8. Check RGB Values
   1. ASCII Characters/other data can be hidden in the RGB\(A\) values of an image.
   2. Upload your image [here](https://georgeom.net/StegOnline/upload) and preview the RGBA values. Try converting them to text, and see if any flag is found. It might be worth looking at just the R/G/B/A values on their own. 
   3. Related write-ups: MMA-CTF-2015
9. Steghide
   1. Found a password? \(Or not?\)
   2. If you've found a password, the go-to application to check should be `steghide`. Bear in mind that this can sometimes be used without a password, too.
   3. You can extract data by running `steghide extract -sf <filename>`.
   4. Other stego tools \(may need passwords to retrieve information\):
      1. OpenStego, 
      2. Stegpy
      3. Outguess
      4. jphide
   5. Associated writeups: Pragyan CTF 2017, Xiomara 2019, CSAW Quals 2015, BlackAlps Y-NOT-CTF \(JFK Challenge\)
10. Browse Color Palette
    1. If the PNG is in type 3, you should look through the color palette.
    2. This site \(TODO: find site link\) has a feature for randomizing the color palette, which may reveal the flag. You can also browse through each color in the palette, if the flag is the same color.
    3. It may also be worth looking at the palette indexes themselves, as a string may be visible from there. 
    4. Related write-ups: Plain CTF 2014
11. Pixel Value Differencing \(PVD/MPVD\)
    1. This is a method where the differences between pixel pairs are measured slightly adjusted in order to hide data.
    2. It would be rare to have a case of PVD where you're not explicitly told \(or perhaps hinted at\) that this is the steganographic method, as it's very niche.
    3.  Related write-ups: TJCTF 2019, MMA-CTF 2015

## Misc

`StegCracker` - [https://pypi.org/project/stegcracker/](https://pypi.org/project/stegcracker/) - bruteforce tool for finding `steghide` passwords and extract \(works well, uses `rockyou.txt` as default wordlist\)

extract files from stego'd files: `binwalk -Me <filename>`

[http://bigwww.epfl.ch/demo/ip/demos/FFT/](http://bigwww.epfl.ch/demo/ip/demos/FFT/) - Fast Fourier Transform online tool. Check this to test stego images that cant be solved with other stuff

[https://0xrick.github.io/lists/stego/](https://0xrick.github.io/lists/stego/) [https://github.com/DominicBreuker/stego-toolkit/blob/master/README.md\#tools](https://github.com/DominicBreuker/stego-toolkit/blob/master/README.md#tools) [https://pequalsnp-team.github.io/cheatsheet/steganography-101](https://pequalsnp-team.github.io/cheatsheet/steganography-101)

## References
* [https://georgeom.net/StegOnline/checklist](https://georgeom.net/StegOnline/checklist)
