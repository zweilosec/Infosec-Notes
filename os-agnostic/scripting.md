# Scripting

{% hint style="success" %}
Hack Responsibly.

Always ensure you have **explicit** permission to access any computer system **before** using any of the techniques contained in these documents.  You accept full responsibility for your actions by applying any knowledge gained here.  
{% endhint %}

## Dealing with Sockets

[https://pequalsnp-team.github.io/cheatsheet/socket-basics-py-js-rb](https://pequalsnp-team.github.io/cheatsheet/socket-basics-py-js-rb)

## MISC

```text
#checks the output from crypto and sees if at least 60% is ascii letters and returns true for possible plaintext
def is_plaintext(ptext):
    num_letters = sum(map(lambda x : 1 if x in string.ascii_letters else 0, ptext))
    if num_letters / len(ptext) >= .6:
      return True
```

