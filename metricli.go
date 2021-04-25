/*
 * Realize metric monitoring even in terminals.
 *
 * @author    yasutakatou
 * @copyright 2021 yasutakatou
 * @license   xxx
 */
package main

import (
	"bufio"
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	crt "crypto/rand"
	"encoding/base64"
	"flag"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"os"
	"os/exec"
	"regexp"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/appleboy/easyssh-proxy"
	"github.com/saintfish/chardet"
	"github.com/tmc/scp"
	"golang.org/x/crypto/ssh"
	"golang.org/x/text/encoding/japanese"
	"golang.org/x/text/transform"
	"gopkg.in/ini.v1"
)

//FYI: https://journal.lampetty.net/entry/capturing-stdout-in-golang
type Capturer struct {
	saved         *os.File
	bufferChannel chan string
	out           *os.File
	in            *os.File
}

type serverData struct {
	LABEL   string
	IP      string
	PORT    string
	USER    string
	PASSWD  string
	SHEBANG string
}

type defineData struct {
	HOST    string
	METRICS []string
}

type metricData struct {
	LABEL   string
	ACTION  string
	TYPE    string
	VALUE   int
	COMMAND string
}

type actionData struct {
	LABEL   string
	COMMAND string
}

var (
	debug, logging, linux, needSCP, noDel bool
	hosts                                 []serverData
	defines                               []defineData
	metrics                               []metricData
	actions                               []actionData
	path                                  string
	sshTimeout, RETRY                     int
)

func main() {
	_Debug := flag.Bool("debug", false, "[-debug=debug mode (true is enable)]")
	_Config := flag.String("config", ".metricli", "[-config=config file]")
	_Logging := flag.Bool("log", false, "[-log=logging mode (true is enable)]")
	_path := flag.String("path", ".", "[-path=metric data path]")
	_replaceStr := flag.String("replace", "{}", "[-replace=replace string for action commands]")
	_plainpassword := flag.Bool("plainpassword", false, "[-plainpassword=use plain text password (true is enable)]")
	_decryptkey := flag.String("decrypt", "", "[-decrypt=password decrypt key string]")
	_encrypt := flag.String("encrypt", "", "[-encrypt=password encrypt key string ex) pass:key (JUST ENCRYPT EXIT!)]")
	_checkRules := flag.Bool("check", false, "[-check=check rules. if connect fail to not use rule. (true is enable)]")
	_useShell := flag.String("shell", "/bin/bash", "[-shell=shell path at Linux (windows: cmd /C)]")
	_sshTimeout := flag.Int("timeout", 10, "[-timeout=timeout count (second). ]")
	_needSCP := flag.Bool("scp", true, "[-scp=need scp mode (true is enable)]")
	_RETRY := flag.Int("retry", 10, "[-retry=retry counts.]")
	_noDel := flag.Bool("noDel", true, "[-noDel=not delete old metrics (true is enable)]")

	flag.Parse()

	debug = bool(*_Debug)
	logging = bool(*_Logging)
	path = string(*_path)
	sshTimeout = int(*_sshTimeout)
	needSCP = bool(*_needSCP)
	RETRY = int(*_RETRY)
	noDel = bool(*_noDel)

	if len(*_encrypt) > 0 && strings.Index(*_encrypt, ":") != -1 {
		strs := strings.Split(*_encrypt, ":")
		enc, err := encrypt(strs[0], []byte(addSpace(strs[1])))
		if err == nil {
			fmt.Println("Encrypt: " + enc)
			os.Exit(0)
		} else {
			fmt.Println(err)
			os.Exit(1)
		}
	}

	if Exists(*_Config) == true {
		loadConfig(*_Config, *_decryptkey, *_plainpassword, *_checkRules)
	} else {
		fmt.Printf("Fail to read config file: %v\n", *_Config)
		os.Exit(1)
	}

	switch runtime.GOOS {
	case "linux":
		linux = true
	case "windows":
		linux = false
	}

	do(*_replaceStr, *_useShell)
	os.Exit(0)
}

func do(replaceStr, useShell string) {
	for i := 0; i < len(defines); i++ {
		debugLog(" -- [DEFINE] -- " + defines[i].HOST + " --")
		mkdir(defines[i].HOST)
		for r := 0; r < len(defines[i].METRICS); r++ {
			debugLog(" -- -- [METRIC] -- " + defines[i].METRICS[r] + " --")

			var locate string
			if linux == true {
				locate = path + "/" + defines[i].HOST + "/" + defines[i].METRICS[r]
			} else {
				locate = path + "\\" + defines[i].HOST + "\\" + defines[i].METRICS[r]
			}
			mkdir(locate)

			if result := doMetric(locate, defines[i].HOST, defines[i].METRICS[r]); result != "" {
				if actionStr := actionCheck(defines[i].METRICS[r]); actionStr != "" {
					doAction(actionStr, replaceStr, result, useShell)
				}
			}
		}
	}
}

func actionCheck(metricName string) string {
	for i := 0; i < len(metrics); i++ {
		if metrics[i].LABEL == metricName {
			return metrics[i].ACTION
		}
	}
	return ""
}

func doAction(command, replaceStr, strs, useShell string) {
	var cmd *exec.Cmd
	var out string
	var err error

	command = strings.Replace(command, replaceStr, strs, 1)
	debugLog("command: " + command)

	switch linux {
	case true:
		cmd = exec.Command(useShell, "-c", command)
	case false:
		cmd = exec.Command("cmd", "/C", command)
	}

	c := &Capturer{}
	c.StartCapturingStdout()
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	cmd.Stdin = os.Stdin
	cmd.Run()

	out = c.StopCapturingStdout()

	detector := chardet.NewTextDetector()
	result, err := detector.DetectBest([]byte(out))
	if err == nil {
		if result.Charset == "Shift_JIS" {
			out = sjis_to_utf8(out)
		}
	}

	debugLog("output: " + out)
}

func mkdir(dir string) {
	if Exists(dir) == false {
		if err := os.Mkdir(dir, 0777); err != nil {
			fmt.Println(err)
			os.Exit(-1)
		}
	}
}

func loadConfig(configFile, decryptstr string, plainpassword, checkRules bool) {
	loadOptions := ini.LoadOptions{}
	loadOptions.UnparseableSections = []string{"SERVER", "DEFINE", "METRIC", "ACTION"}

	cfg, err := ini.LoadSources(loadOptions, configFile)
	if err != nil {
		fmt.Printf("Fail to read config file: %v", err)
		os.Exit(1)
	}

	setStructs("SERVER", cfg.Section("SERVER").Body(), decryptstr, 0, plainpassword, checkRules)
	setStructs("DEFINE", cfg.Section("DEFINE").Body(), "", 1, false, false)
	setStructs("METRIC", cfg.Section("METRIC").Body(), "", 2, false, false)
	setStructs("ACTION", cfg.Section("ACTION").Body(), "", 3, false, false)
}

func setStructs(configType, datas, decryptstr string, flag int, plainpassword, checkRules bool) {
	var metricStrs []string
	debugLog(" -- " + configType + " --")

	for _, v := range regexp.MustCompile("\r\n|\n\r|\n|\r").Split(datas, -1) {
		if len(v) > 0 {
			if strings.Index(v, "\t") != -1 {
				strs := strings.Split(v, "\t")

				switch flag {
				case 0:
					pass := ""
					if plainpassword == true || Exists(strs[4]) == true {
						pass = strs[4]
					} else {
						passTmp, err := decrypt(strs[4], []byte(decryptstr))
						if err != nil {
							fmt.Println("WARN: not password decrypt!: ", strs[4])
							fmt.Println(err)
						}
						pass = passTmp
					}

					if checkRules == true {
						_, done, err := sshDo(strs[3], strs[1], pass, strs[2], "cd")
						if done == false || err != nil {
							debugLog("RULE: " + strs[0] + " connect fail! " + strs[3] + " " + strs[1] + " " + pass + " " + strs[2])
						} else {
							debugLog("add RULE: " + strs[0] + " " + strs[3] + " " + strs[1] + " " + pass + " " + strs[2])
							hosts = append(hosts, serverData{LABEL: strs[0], IP: strs[1], PORT: strs[2], USER: strs[3], PASSWD: pass, SHEBANG: strs[5]})
							debugLog(v)
						}
					} else {
						debugLog("add RULE: " + strs[0] + " " + strs[3] + " " + strs[1] + " " + pass + " " + strs[2])
						hosts = append(hosts, serverData{LABEL: strs[0], IP: strs[1], PORT: strs[2], USER: strs[3], PASSWD: pass, SHEBANG: strs[5]})
						debugLog(v)
					}
				case 1:
					if len(strs) > 1 {
						for i := 1; i < len(strs); i++ {
							metricStrs = append(metricStrs, strs[i])
						}
					}
					defines = append(defines, defineData{HOST: strs[0], METRICS: metricStrs})
					debugLog(v)
				case 2:
					convInt, err := strconv.Atoi(strs[3])

					if err == nil {
						metrics = append(metrics, metricData{LABEL: strs[0], ACTION: strs[1], TYPE: strs[2], VALUE: convInt, COMMAND: strs[4]})
					}
					debugLog(v)
				case 3:
					actions = append(actions, actionData{LABEL: strs[0], COMMAND: strs[1]})
					debugLog(v)
				}

			}
		}
	}
}

func debugLog(message string) {
	var file *os.File
	var err error

	if debug == true {
		fmt.Println(message)
	}

	if logging == false {
		return
	}

	const layout = "2006-01-02_15"
	t := time.Now()
	filename := "metricli_" + t.Format(layout) + ".log"

	if Exists(filename) == true {
		file, err = os.OpenFile(filename, os.O_WRONLY|os.O_APPEND, 0666)
	} else {
		file, err = os.OpenFile(filename, os.O_WRONLY|os.O_CREATE, 0666)
	}

	if err != nil {
		log.Fatal(err)
		return
	}
	defer file.Close()
	fmt.Fprintln(file, message)
}

func Exists(filename string) bool {
	_, err := os.Stat(filename)
	return err == nil
}

// FYI: http://www.inanzzz.com/index.php/post/f3pe/data-encryption-and-decryption-with-a-secret-key-in-golang
// encrypt encrypts plain string with a secret key and returns encrypt string.
func encrypt(plainData string, secret []byte) (string, error) {
	cipherBlock, err := aes.NewCipher(secret)
	if err != nil {
		return "", err
	}

	aead, err := cipher.NewGCM(cipherBlock)
	if err != nil {
		return "", err
	}

	nonce := make([]byte, aead.NonceSize())
	if _, err = io.ReadFull(crt.Reader, nonce); err != nil {
		return "", err
	}

	return base64.URLEncoding.EncodeToString(aead.Seal(nonce, nonce, []byte(plainData), nil)), nil
}

// decrypt decrypts encrypt string with a secret key and returns plain string.
func decrypt(encodedData string, secret []byte) (string, error) {
	encryptData, err := base64.URLEncoding.DecodeString(encodedData)
	if err != nil {
		return "", err
	}

	cipherBlock, err := aes.NewCipher(secret)
	if err != nil {
		return "", err
	}

	aead, err := cipher.NewGCM(cipherBlock)
	if err != nil {
		return "", err
	}

	nonceSize := aead.NonceSize()
	if len(encryptData) < nonceSize {
		return "", err
	}

	nonce, cipherText := encryptData[:nonceSize], encryptData[nonceSize:]
	plainData, err := aead.Open(nil, nonce, cipherText, nil)
	if err != nil {
		return "", err
	}

	return string(plainData), nil
}

func addSpace(strs string) string {
	for i := 0; len(strs) < 16; i++ {
		strs += "0"
	}
	return strs
}

//FYI: https://qiita.com/uchiko/items/1810ddacd23fd4d3c934
// ShiftJIS から UTF-8
func sjis_to_utf8(str string) string {
	ret, err := ioutil.ReadAll(transform.NewReader(strings.NewReader(str), japanese.ShiftJIS.NewDecoder()))
	if err != nil {
		fmt.Printf("Convert Error: %s\n", err)
		return ""
	}
	return string(ret)
}

func sshDo(User, Host, Passwd, Port, Command string) (string, bool, error) {
	ssh := &easyssh.MakeConfig{
		User:     User,
		Server:   Host,
		Password: Passwd,
		Port:     Port,
		Timeout:  time.Duration(sshTimeout) * time.Second,
	}

	if Exists(Passwd) == true {
		ssh = &easyssh.MakeConfig{
			User:       User,
			Server:     Host,
			KeyPath:    Passwd,
			Port:       Port,
			Timeout:    time.Duration(sshTimeout) * time.Second,
			Passphrase: "",
		}
	}

	debugLog("ssh: " + Command)

	stdout, stderr, done, err := ssh.Run(Command, time.Duration(sshTimeout)*time.Second)

	debugLog("stdout is :" + stdout + ";   stderr is :" + stderr)

	if done == true {
		if len(stdout) > 0 {
			return stdout, done, err
		} else if len(stderr) > 0 {
			return stderr, done, err
		} else {
			return " ", done, err
		}
	}
	return " ", done, err
}

// 標準出力をキャプチャする
func (c *Capturer) StartCapturingStdout() {
	c.saved = os.Stdout
	var err error
	c.in, c.out, err = os.Pipe()
	if err != nil {
		panic(err)
	}

	os.Stdout = c.out
	c.bufferChannel = make(chan string)
	go func() {
		var b bytes.Buffer
		io.Copy(&b, c.in)
		c.bufferChannel <- b.String()
	}()
}

// キャプチャを停止する
func (c *Capturer) StopCapturingStdout() string {
	c.out.Close()
	os.Stdout = c.saved
	return <-c.bufferChannel
}

func metricCheck(metricName string) int {
	for i := 0; i < len(metrics); i++ {
		if metrics[i].LABEL == metricName {
			return i
		}
	}
	return -1
}

func hostCheck(hostName string) int {
	for i := 0; i < len(hosts); i++ {
		if hosts[i].LABEL == hostName {
			return i
		}
	}
	return -1
}

func writeFile(filename, stra string) bool {
	file, err := os.Create(filename)
	if err != nil {
		fmt.Println(err)
		return false
	}
	defer file.Close()

	_, err = file.WriteString(stra + "\n")
	if err != nil {
		fmt.Println(err)
		return false
	}
	return true
}

func scpDo(hostInt int, tmpFile, path string) bool {
	config := &ssh.ClientConfig{
		User:            hosts[hostInt].USER,
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
		Auth: []ssh.AuthMethod{
			ssh.Password(hosts[hostInt].PASSWD),
		},
	}

	if Exists(hosts[hostInt].PASSWD) == true {
		buf, err := ioutil.ReadFile(hosts[hostInt].PASSWD)
		if err != nil {
			fmt.Println(err)
			return false
		}
		key, err := ssh.ParsePrivateKey(buf)
		if err != nil {
			fmt.Println(err)
			return false
		}

		config = &ssh.ClientConfig{
			User:            hosts[hostInt].USER,
			HostKeyCallback: ssh.InsecureIgnoreHostKey(),
			Auth: []ssh.AuthMethod{
				ssh.PublicKeys(key),
			},
		}
	}

	client, err := ssh.Dial("tcp", hosts[hostInt].IP+":"+hosts[hostInt].PORT, config)
	if err != nil {
		fmt.Print(err.Error())
		return false
	}

	session, err := client.NewSession()
	if err != nil {
		fmt.Print(err.Error())
		return false
	}
	err = scp.CopyPath(tmpFile, path, session)
	if err != nil {
		fmt.Print(err.Error())
		return false
	}
	defer session.Close()
	return true
}

//FYI: https://qiita.com/shinofara/items/e5e78e6864a60dc851a6
type FileInfos []os.FileInfo
type ByName struct{ FileInfos }

func (fi ByName) Len() int {
	return len(fi.FileInfos)
}
func (fi ByName) Swap(i, j int) {
	fi.FileInfos[i], fi.FileInfos[j] = fi.FileInfos[j], fi.FileInfos[i]
}
func (fi ByName) Less(i, j int) bool {
	return fi.FileInfos[j].ModTime().Unix() < fi.FileInfos[i].ModTime().Unix()
}

func fileLists(currentdir string, maxCnt int) []string {
	var files []string
	fileInfos, err := ioutil.ReadDir(currentdir)

	if err != nil {
		fmt.Errorf("Directory cannot read %s\n", err)
		os.Exit(1)
	}

	cnt := 0
	sort.Sort(ByName{fileInfos})
	for _, fileInfo := range fileInfos {
		var findName = (fileInfo).Name()
		files = append(files, currentdir+findName)
		cnt = cnt + 1
		if cnt > maxCnt {
			break
		}
	}

	return files
}

func sshExec(metricInt, hostInt int) string {
	sshCommand := metrics[metricInt].COMMAND
	tmpFile := "tmp." + metrics[metricInt].LABEL
	if needSCP == true {
		writeFile(tmpFile+".bat", sshCommand)

		scpFlag := false
		for i := 0; i < RETRY; i++ {
			if scpDo(hostInt, tmpFile+".bat", ".") == true {
				scpFlag = true
				break
			}
		}
		if scpFlag == false {
			return ""
		}
		sshCommand = hosts[hostInt].SHEBANG + " " + tmpFile + ".bat"
	}

	var err error

	done := false
	strs := ""
	for i := 0; i < RETRY; i++ {
		strs, done, err = sshDo(hosts[hostInt].USER, hosts[hostInt].IP, hosts[hostInt].PASSWD, hosts[hostInt].PORT, sshCommand)
		if done == true && len(strs) > 0 {
			break
		}
	}
	if done == false {
		return ""
	}
	if err != nil {
		fmt.Println(err)
		return ""
	}
	return strs
}

func doMetric(locate, host, metric string) string {
	metricInt := metricCheck(metric)
	if metricInt == -1 {
		return ""
	}
	hostInt := hostCheck(host)
	if hostInt == -1 {
		return ""
	}

	if linux == true {
		locate = locate + "/"
	} else {
		locate = locate + "\\"
	}

	debugLog("locate: " + locate + " host: " + host + " metric: " + metric)

	result := sshExec(metricInt, hostInt)
	const layout = "2006-01-02_15_04_05"
	t := time.Now()
	filename := "metricli_" + t.Format(layout)
	writeFile(locate+filename, result)

	files := fileLists(locate, metrics[metricInt].VALUE)

	if noDel == false && len(files) > metrics[metricInt].VALUE {
		if err := os.Remove(files[len(files)]); err != nil {
			fmt.Println(err)
		}
	}

	switch metrics[metricInt].TYPE {
	case "COUNT":
		if checkCounts(files[0], files[len(files)-1], metricInt) == false {
			return result
		}
	case "AVERAGE":
		if checkAverges(files, metricInt) == false {
			return result
		}
	case "EXSITS":
		if result != "" {
			return result
		}
	}
	return ""
}

func fileRead(fileName string, metricInt int) string {
	data, _ := os.Open(fileName)
	defer data.Close()

	commandStr := strings.Replace(metrics[metricInt].COMMAND, " ", "", -1)

	scanner := bufio.NewScanner(data)
	for scanner.Scan() {
		strs := strings.Replace(scanner.Text(), " ", "", -1)

		if strings.Index(strs, commandStr) == -1 {
			return strs
		}
	}
	return ""
}

func checkCounts(aftFile, preFile string, metricInt int) bool {
	valAft := fileRead(aftFile, metricInt)
	debugLog("After val: " + valAft)
	aftInt, err := strconv.Atoi(valAft)

	if err != nil {
		return false
	}

	valPre := fileRead(preFile, metricInt)
	debugLog("Pre val: " + valPre)
	preInt, err := strconv.Atoi(valPre)

	if err != nil {
		return false
	}

	if aftInt > preInt+metrics[metricInt].VALUE {
		return false
	}

	if aftInt < preInt-metrics[metricInt].VALUE {
		return false
	}

	return true
}

func checkAverges(files []string, metricInt int) bool {
	ave := 0
	preInt := 0

	for i := 0; i < len(files); i++ {
		val := fileRead(files[i], metricInt)
		valInt, err := strconv.Atoi(val)

		if err != nil {
			ave = ave + valInt
			if preInt == 0 {
				preInt = valInt
			}
		}
	}

	ave = ave / len(files)

	if ave > preInt+metrics[metricInt].VALUE {
		return false
	}

	if ave < preInt-metrics[metricInt].VALUE {
		return false
	}

	return true
}
