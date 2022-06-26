# Cryptography & Encryption

## Cryptography

{% embed url="https://pequalsnp-team.github.io/cheatsheet/crypto-101" %}

## Ciphers

* [https://www.boxentriq.com/code-breaking](https://www.boxentriq.com/code-breaking) <-- useful site which can help identify type of cipher.&#x20;
* [https://www.dcode.fr](https://www.dcode.fr) <-- one of the best sites I have found with many decoders for many types of ciphers.
* [Cyber Chef](https://gchq.github.io/CyberChef/) <-- very useful for chained ciphers which require different steps to solve. Can decrypt certificates.

### Fernet

Fernet (symmetric encryption) - **looks like base64** but decodes to garbage, in two parts. First part (32 bytes) is the key. Uses 128-bit AES in CBC mode and PKCS7 padding, with HMAC using SHA256 for authentication. IV is created from `os.random()`.

Decode fernet @ [https://asecuritysite.com/encryption/ferdecode](https://asecuritysite.com/encryption/ferdecode) <-- Will also give the IV and timestamp (could be useful!) more info about this @ [https://cryptography.io/en/latest/fernet](https://cryptography.io/en/latest/fernet)

```python
from cryptography.fernet import Fernet

key = Fernet.generate_key()
f = Fernet(key)
token = f.encrypt(b"this is my key")
print('the key is ' + key + '/nThe cipher text is ' + token)
==========decrypt
from cryptography.fernet import Fernet
key = 'input key here'
f = Fernet(key)
token = 'cipher text here'
print(f.decrypt(token))
```

### Malbolge

Esoteric inferno encryption. Used in some CTF challenges. Malbolge programming language - **text from base64 looks like random text**, but complete garbage (much of it unprintable.) . Read for at [https://en.wikipedia.org/wiki/Malbolge](https://en.wikipedia.org/wiki/Malbolge) and [https://www.tutorialspoint.com/execute\_malbolge\_online.php](https://www.tutorialspoint.com/execute\_malbolge\_online.php)

### BrainFuck

A programming language that uses a series of only `+-.[]<>` characters.

\++++++++++\[>+>+++>+++++++>++++++++++<<<<-]>>>----.>++++++++++++++.-----------------.++++++++.+++++.--------.+++++++++++++++.------------------.++++++++.  = BrainFuck&#x20;

Decode using [https://www.dcode.fr/brainfuck-language](https://www.dcode.fr/brainfuck-language)

### OOK!

Uses only the word `ook` paired with punctuation marks (`.!?`).  Shorthand leaves out `ook`.

....................!?.?...?.......?...............?....................?.?.?.?.!!?!.?.?.?..................!.!.!!!!!!!!!.?.......!. = OOK!&#x20;

Decode using [https://www.dcode.fr/ook-language](https://www.dcode.fr/ook-language)

## Test for Plaintext Output from a (Python) Script

```python
#checks the output from crypto and sees if at least 60% is ascii letters and returns true for possible plaintext
def is_plaintext(ptext):
    num_letters = sum(map(lambda x : 1 if x in string.ascii_letters else 0, ptext))
    if num_letters / len(ptext) >= .6:
      return True
```

If this function is giving false positives/negatives, it can be tweaked by altering the number in the line:&#x20;

```python
if num_letters / len(ptext) >= .6:
```

`0.6` has been tested as working for simple CTF usage.

## Digital Certificates

X.509

[https://8gwifi.org/PemParserFunctions.jsp](https://8gwifi.org/PemParserFunctions.jsp) -- extract information from various digital certificates

## SSH Keys

For those interested in the details - you can see what's inside the public key file (generated as explained above), by doing this:- \`\`\`openssl rsa -noout -text -inform PEM -in key.pub -pubin or for the private key file, this:- openssl rsa -noout -text -in key.private which outputs as text on the console the actual components of the key (modulus, exponents, primes, ...)

` `` extract public key from private key: `openssl rsa -in privkey.pem -pubout -out key.pub\`

## Encryption/Decryption

[https://www.devglan.com/online-tools/aes-encryption-decryption](https://www.devglan.com/online-tools/aes-encryption-decryption)

[CyberChef](https://gchq.github.io/CyberChef/): Website for encryption/decryption of many different types at same time

good cipher tools: [http://rumkin.com/](http://rumkin.com/)

one time pad: `pt - ct = key`

decrypt rsa private key: `openssl rsautl -decrypt -inkey $key_file < $pass.crypt` ($pass.crypt is hex file? encrypted contents of pub key?)

* [Ippsec:HacktheBox - Charon](https://www.youtube.com/watch?v=\_csbKuOlmdE)

### Decrypt LDAP Passwords

[https://dotnetfiddle.net/2RDoWz](https://dotnetfiddle.net/2RDoWz)

```csharp
using System;
using System.IO;
using System.Security.Cryptography;
using System.Text;
					
public class Program
{
	public static void Main()
	{
	  //Change these three variables to decode your own; need a key and IV to decode!
		string ciphertext = "BQO5l5Kj9MdErXx6Q6AGOw==";
		string key = "c4scadek3y654321";
		string iv = "1tdyjCbY1Ix49842";
		
		string plaintext = string.Empty;
		plaintext = DecryptString(ciphertext, key, iv);
		Console.WriteLine(plaintext);
	}
	
	public static string DecryptString(string EncryptedString, string Key, string iv)
    {
      byte[] buffer = Convert.FromBase64String(EncryptedString);
      Aes aes = Aes.Create();
      ((SymmetricAlgorithm) aes).KeySize = 128;
      ((SymmetricAlgorithm) aes).BlockSize = 128;
      ((SymmetricAlgorithm) aes).IV = Encoding.UTF8.GetBytes(iv);
      ((SymmetricAlgorithm) aes).Mode = CipherMode.CBC;
      ((SymmetricAlgorithm) aes).Key = Encoding.UTF8.GetBytes(Key);
      using (MemoryStream memoryStream = new MemoryStream(buffer))
      {
        using (CryptoStream cryptoStream = new CryptoStream((Stream) memoryStream, ((SymmetricAlgorithm) aes).CreateDecryptor(), CryptoStreamMode.Read))
        {
          byte[] numArray = new byte[checked (buffer.Length - 1 + 1)]; //not sure why this has -1+1 here, example works without it though...
          cryptoStream.Read(numArray, 0, numArray.Length);
          return Encoding.UTF8.GetString(numArray);
        }
      }
    }
}
```

Decodes to: `w3lc0meFr31nd`



If you like this content and would like to see more, please consider [buying me a coffee](https://www.buymeacoffee.com/zweilosec)!
