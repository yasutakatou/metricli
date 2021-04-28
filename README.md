# metricli

Realize metric monitoring even in terminals.

(WIP..)

For example, you want to do metric monitoring easily.
However, implementing a tool like datadog requires a lot of work and convincing your team.
Wouldn't it be nice if you could check it every morning when you go to make your coffee like do execute commands?
This tool will make that feeling come true.

--

The tool asks the server to be monitored to execute a command via SSH.
The tool compares the results of past runs using a set of rules.
Detects items that spike or exceed the average value.
Threshold crossings will be reported with a set action.
In other words, this tool will be useful for SRE-like metric monitoring for teams that can't use SaaS monitoring tools and are operating and monitoring legacy systems!
When you come back with your coffee brewed, you're ready to do a metrics assessment with your team at the morning meeting.

-- 

The tool will only check the number of times the rule is matched.
In other words, it is triggered by what changes and how much, so it works regardless of the importance of the message content.
Make sure you understand the nature of the rules you set.
It is necessary to check the transition of resources, not the error messages.

The major rules are as follows

COUNT
	Check the difference between the oldest value and the newest value.
	Since this is a comparison of old and new, values in the middle will not be evaluated.
	Therefore, it is advisable to set it to a resource that will increase steadily, disk empty space.
AVERAGE
	Check the difference from the mean. In other words, it is useful for checking items whose values are likely to change extremely.
	Obtains the average value within a set period and evaluates the difference from the latest value.
	It can be used to monitor things like the number of connections that suddenly become high.
EXSITS
	If it is not an empty value, the action will be performed. It exists as a replacement for the old message monitor.

Based on the characteristics of these checking methods, consider the detection commands to be executed on the OS.
OS knowledge is required. For certainty of used technology.　:)

--

optiions

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

Specifies the password for compounding when the password is encrypted.

### -encrypt

Output the cryptographic keywords.

note) If this option is specified, the program will exit after outputting the keywords.

### -log

Make it log output. Specify the file name.

### -noDel

This mode does not delete logs that are not in the check range.

note) Since it only erases the log one period ago, it is better to combine it with other methods such as cron for accurate rotation.

### -path

The path to output the log.

### -plainpassword

This is the mode in which the password field in the configuration is not compounded and the string is used as the password.

note) Of course, being able to see the configuration means that the password will be leaked.

### -replace

In the action, define the string to be replaced by the execution result.

### -retry

The number of retries for SSH commands.

### -scp

This is the mode to send batches via SCP. When this is turned on, the monitoring command is executed after the batch is sent, which slows down the operation.
The disadvantage of turning it off is that double quotation marks cannot be specified in the monitoring command.

### -shell

Specifies the shell prompt to be used for locally run actions

### -timeout

Specify the timeout period after throwing a command via SSH.

# FYIs

[Data encryption and decryption with a secret key example in Golang](http://www.inanzzz.com/index.php/post/f3pe/data-encryption-and-decryption-with-a-secret-key-in-golang)<br>
[Go言語で文字コード変換](https://qiita.com/uchiko/items/1810ddacd23fd4d3c934)<br>
[Golangで、ファイル一覧取得（最新順出力）](https://qiita.com/shinofara/items/e5e78e6864a60dc851a6)<br>
[Goで標準出力をキャプチャする](https://journal.lampetty.net/entry/capturing-stdout-in-golang)<br>

# License

Apache License Version 2.0<br>
ICU License<br>
ISC License<br>
