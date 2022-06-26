# Command Injection

## Command Injection

{% embed url="https://owasp.org/www-community/attacks/Command_Injection" %}

### PHP Command Injection

The following PHP code snippet is vulnerable to a command injection attack:

```php
<?php
print("Please specify the name of the file to delete");
print("<p>");
$file=$_GET['filename'];
system("rm $file");
?>
```

The following request is an example of that will successful attack on the previous PHP code, and will output the results of the `id` command: `http://127.0.0.1/delete.php?filename=bob.txt;id`.  Look for exposed `$_GET['filename']` type variables that take input from the user, or can be injected into from the URL.  This combined with `system("<command>")` will allow for command injection.

