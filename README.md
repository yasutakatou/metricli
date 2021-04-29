# metricli

**Realize metric monitoring even in terminals.**

# solution

　In case of you want to monitor servers metrics easily, implementing a tool like datadog requires a lot of work and convincing your team. Wouldn't it be nice if you could check it every morning between you go to make your coffee like do execute commands? **This tool will make that feeling come true**.

# feature

　Basicly, The tool get the server to be monitored to execute a command via SSH, and check difference.The tool compares the results of past runs using a set of rules. Detects items that spike or exceed the average value. Threshold crossings will be reported with a set action.<br>
(For example, If you want to use the slack, you can do.)

　In other words, this tool will be useful for SRE-like metric monitoring for teams that can't use SaaS monitoring tools and are operating and monitoring legacy systems. When you come back with your coffee brewed, **you're ready to do a metrics assessment with your team at the morning meeting!**

# installation

If you want to put it under the path, you can use the following.

```
go get github.com/yasutakatou/metricli
```

If you want to create a binary and copy it yourself, use the following.

```
git clone https://github.com/yasutakatou/metricli
cd metricli
go build .
```

[or download binary from release page](https://github.com/yasutakatou/metricli/releases).<br>
save binary file, copy to entryed execute path directory.

# uninstall

delete that binary. del or rm command. (it's simple!)

# description

　The tool triggered by what changes and how much, so it works regardless of the importance of the message content. Make sure you understand the nature of the rules you set. It is necessary to set consideration the transition of resources, not the error messages.

## The major rules are as follows

### COUNT
**Check the difference between the oldest value and the newest value**.<br>
Since this is a comparison of old and new, values in the middle will not be evaluated.<br>
Therefore, it is advisable to set it to a resource that will increase steadily, for example, disk empty space.<br>

### AVERAGE
**Check the difference from the mean**. In other words, it is useful for checking items whose values are likely to change extremely.<br>
Obtains the average value by seted rule and evaluates the difference from the latest value.<br>
It can be used to monitor things like the number of connections that suddenly become high.<br>

### EXSITS
**If it is not an empty value**, the action will be performed. It exists for alert message monitoring.<br>

Based on the characteristics of these checking methods, consider the detection commands to be executed on the OS.<br>
So, OS knowledge is required.　:)

# config file

Configs format is **tab split values**. The definition is ignored if you put sharp(#) at the beginning.

## [SERVER]

Defines access to the server.

```
[SERVER]
local 127.0.0.1	22	fzk01	myPasswd	cmd /C
```

1. define name
2. IP address
3. Port number
4. Username
5. Plain password, encrypted password string or private key filename.
6. Shebang

note) If you want to use plain password, when run set option "-plainpassword".

## [DEFINE]

Bind server and rules.

```
[DEFINE]
local	RULE1	RULE2
```

1. define name by [SERVER] section.
2. define name by [METRIC] section.

note) not only single but can write **plural rules** by tsv.

## METRIC

Defines get for metric value.

```
[METRIC]
RULE1	STDIN	AVERAGE	3	ls | wc | awk "{print $1}"
```

1. define name
2. define name by [ACTION] section.
3. metric type(**COUNT, AVERAGE or EXSITS**)
4. metric count value
5. execute command

note) metric count is generations number. If you set "AVERAGE" and "4",  evaluate 4 generations.
note) If metric type is "COUNT" or "AVERAGE", execute command output must be **integer value**.

## [ACTION]

If metric rule is over threshold, this actions will do.

```
[ACTION]
STDIN	echo Alert! {}
```

1. define name
2. execute command

note) replace string by seted "-replace" option is **replaced evaluated metric value**.

exmample:

```
[SERVER]
local	127.0.0.1	22	fzk01	myPasswd	cmd /C
[DEFINE]
local	RULE1
#192.168.0.220	RULE1	RULE3
[METRIC]
RULE1	STDIN	AVERAGE	3	ls | wc | awk "{print $1}"
RULE2	LOG	COUNT	grep /var/messages | error
RULE3	LOG	AVERAGE	10	dk -k /tmp
RULE4	SLACK	EXSITS	1	grep -v INFO /var/log/messages
[ACTION]
STDIN	echo Alert! {}
LOG	echo "{}" >> /tmp/log.log
#SLACK	curl http://slac.com/xxxx {}
```

# options

```
  -check
        [-check=check rules. if connect fail to not use rule. (true is enable)]
  -config string
        [-config=config file] (default ".metricli")
  -debug
        [-debug=debug mode (true is enable)]
  -decrypt string
        [-decrypt=password decrypt key string]
  -encrypt string
        [-encrypt=password encrypt key string ex) pass:key (JUST ENCRYPT EXIT!)]
  -log
        [-log=logging mode (true is enable)]
  -noDel
        [-noDel=not delete old metrics (true is enable)] (default true)
  -path string
        [-path=metric data path] (default ".")
  -plainpassword
        [-plainpassword=use plain text password (true is enable)]
  -replace string
        [-replace=replace string for action commands] (default "{}")
  -retry int
        [-retry=retry counts.] (default 10)
  -scp
        [-scp=need scp mode (true is enable)] (default true)
  -shell string
        [-shell=shell path at Linux (windows: cmd /C)] (default "/bin/bash")
  -timeout int
        [-timeout=timeout count (second). ] (default 10)
```

### -check

Check the host rules. Host rules that fail to access will be excluded from the check.

### -config

Specify the configuration file.

### -debug

Run in the mode that outputs various logs.

### -decrypt

Specifies the password for compounding when the password is encrypted.<br>

example: Specifies the decryption string generated by the encrypt option.

```
>metricli -decrypt=test
```

### -encrypt

Output the cryptographic keywords.<br>

note) If this option is specified, the program will exit after outputting the keywords.<br>

example: Gives the decryption string and the encrypted string separated by colon(:). Write the output string in the password field of the configuration file.

```
>metricli -encrypt=test:myPassword
Encrypt: lG8GjWd3-f803B6AHVb8SDSj5IdVmhzGs10VgjJPOIo=
```

### -log

Specify the log file name.

### -noDel

This mode does not delete logs that are not in the check range.<br>

note) Since it only erases the log one generation ago, it is better to combine it with other methods such as cron for accurate rotation.

### -path

The path to output the log.

### -plainpassword

This is the mode in which the password field in the configuration is not compounded and the string is used as the password.<br>

note) Of course, being able to see the configuration means that the password will be leaked.

### -replace

Define the string to be replaced by the execution result at actions.

### -retry

The number of retries for SSH commands.

### -scp

This is the mode to send batches via SCP. When this is turned on, the monitoring command is executed after the batch is sent, which slows down the operation.<br>
In exchange, The disadvantage of turning it off is that **double quotation marks cannot be specified** in the monitoring command.

### -shell

Specifies the shell prompt to be used for locally run actions

note) On Windows, **auto select "cmd /C"**.

### -timeout

Specify the timeout period after throwing a command via SSH.

# FYIs

[Data encryption and decryption with a secret key example in Golang](http://www.inanzzz.com/index.php/post/f3pe/data-encryption-and-decryption-with-a-secret-key-in-golang)<br>
[Go言語で文字コード変換](https://qiita.com/uchiko/items/1810ddacd23fd4d3c934)<br>
[Golangで、ファイル一覧取得（最新順出力）](https://qiita.com/shinofara/items/e5e78e6864a60dc851a6)<br>
[Goで標準出力をキャプチャする](https://journal.lampetty.net/entry/capturing-stdout-in-golang)<br>

# license

Apache License Version 2.0<br>
ICU License<br>
ISC License<br>
