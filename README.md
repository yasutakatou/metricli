# metricli

Realize metric monitoring even in terminals.

(WIP..)

For example, you want to do metric monitoring easily.
However, implementing a tool like datadog requires a lot of work and convincing your team.
Wouldn't it be nice if you could check it every morning when you go to make your coffee?
This tool will make that feeling come true.

--

The tool asks the server to be monitored to execute a command via SSH.
The tool compares the results of past runs using a set of rules.
Detects items that spike or exceed the average value.
Threshold crossings will be reported with a set action.
In other words, this tool will be useful for SRE-like metric monitoring for teams that can't use SaaS monitoring tools and are operating and monitoring legacy systems!

-- 

The tool will only check the number of times the rule is matched.
In other words, it is triggered by what changes and how much, so it works regardless of the importance of the message content.
Make sure you understand the nature of the rules you set.
It is necessary to check the transition of resources, not the error messages.

The major rules are as follows

COUNT
	Check the difference between the oldest value and the newest value.
	Since this is a comparison of old and new, values in the middle will not be evaluated.
	Therefore, it is advisable to set it to a resource that will increase steadily, such as disk space.
AVERAGE
	Check the difference from the mean. In other words, it is useful for checking items whose values are likely to change extremely.
	Obtains the average value within a set period and evaluates the difference from the latest value.
EXSITS
	If it is not an empty value, the action will be performed. It exists as a replacement for the old message monitor.

--

optiions

```
Usage of C:\Users\fzk01\AppData\Local\Temp\go-build1412382980\b001\exe\metricli.exe:
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
### -config
### -debug
### -decrypt
### -encrypt
### -log
### -noDel
### -path
### -plainpassword
### -replace
### -retry
### -scp
### -shell
### -timeout

# FYIs

[Data encryption and decryption with a secret key example in Golang](http://www.inanzzz.com/index.php/post/f3pe/data-encryption-and-decryption-with-a-secret-key-in-golang)<br>
[Go言語で文字コード変換](https://qiita.com/uchiko/items/1810ddacd23fd4d3c934)<br>
[Golangで、ファイル一覧取得（最新順出力）](https://qiita.com/shinofara/items/e5e78e6864a60dc851a6)<br>
[Goで標準出力をキャプチャする](https://journal.lampetty.net/entry/capturing-stdout-in-golang)<br>

# License

Apache License Version 2.0<br>
ICU License<br>
ISC License<br>
