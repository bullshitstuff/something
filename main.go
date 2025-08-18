package main

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/naser-989/xray-knife/v3/pkg"
	"github.com/naser-989/xray-knife/v3/pkg/singbox"
	"github.com/naser-989/xray-knife/v3/pkg/xray"
	"github.com/oschwald/geoip2-golang"
)

// Simplified Result struct
type Result struct {
	Config    string
	SpeedMbps float64
	Country   string
}

const (
	sanityCheckURL    = "https://googleads.g.doubleclick.net/mads/static/mad/sdk/native/production/sdk-core-v40-impl.html"
	speedTestURL      = "http://cachefly.cachefly.net/10mb.test"
	speedTestFileSize = 10 * 1024 * 1024
	ipCheckURL        = "https://api.ifconfig.me/ip"
	minSpeedMbps      = 80.0
	topNFastest       = 20
)

var geoDB *geoip2.Reader

// --- Structs for Generating Xray Outbounds ---
type Outbound struct {
	Tag            string          `json:"tag"`
	Protocol       string          `json:"protocol"`
	Settings       json.RawMessage `json:"settings"`
	StreamSettings *StreamSettings `json:"streamSettings,omitempty"`
	Mux            *Mux            `json:"mux,omitempty"`
}
type VmessSettings struct {
	VNext []*VmessServer `json:"vnext"`
}
type VmessServer struct {
	Address string       `json:"address"`
	Port    int          `json:"port"`
	Users   []*VmessUser `json:"users"`
}
type VmessUser struct {
	ID       string `json:"id"`
	AlterID  int    `json:"alterId"`
	Security string `json:"security,omitempty"`
}
type VlessSettings struct {
	VNext []*VlessServer `json:"vnext"`
}
type VlessServer struct {
	Address string       `json:"address"`
	Port    int          `json:"port"`
	Users   []*VlessUser `json:"users"`
}
type VlessUser struct {
	ID         string `json:"id"`
	Encryption string `json:"encryption"`
	Flow       string `json:"flow,omitempty"`
}
type StreamSettings struct {
	Network         string           `json:"network,omitempty"`
	Security        string           `json:"security,omitempty"`
	TLSSettings     *TLSSettings     `json:"tlsSettings,omitempty"`
	RealitySettings *RealitySettings `json:"realitySettings,omitempty"`
	WSSettings      *WSSettings      `json:"wsSettings,omitempty"`
	GRPCSettings    *GRPCSettings    `json:"grpcSettings,omitempty"`
	Sockopt         *Sockopt         `json:"sockopt,omitempty"`
}
type TLSSettings struct {
	ServerName    string   `json:"serverName,omitempty"`
	AllowInsecure bool     `json:"allowInsecure"`
	ALPN          []string `json:"alpn,omitempty"`
	Fingerprint   string   `json:"fingerprint,omitempty"`
}
type RealitySettings struct {
	ServerName  string `json:"serverName,omitempty"`
	Fingerprint string `json:"fingerprint,omitempty"`
	PublicKey   string `json:"publicKey,omitempty"`
	ShortID     string `json:"shortId,omitempty"`
	SpiderX     string `json:"spiderX,omitempty"`
}
type WSSettings struct {
	Path    string            `json:"path,omitempty"`
	Headers map[string]string `json:"headers,omitempty"`
}
type GRPCSettings struct {
	ServiceName string `json:"serviceName,omitempty"`
	MultiMode   bool   `json:"multiMode,omitempty"`
}
type Sockopt struct {
	DialerProxy string `json:"dialerProxy,omitempty"`
}
type Mux struct {
	Enabled     bool `json:"enabled"`
	Concurrency int  `json:"concurrency"`
}
type VmessLink struct {
	PS   string          `json:"ps"`
	Add  string          `json:"add"`
	Port json.RawMessage `json:"port"`
	ID   string          `json:"id"`
	Aid  json.RawMessage `json:"aid"`
	Net  string          `json:"net"`
	Type string          `json:"type"`
	Host string          `json:"host"`
	Path string          `json:"path"`
	TLS  string          `json:"tls"`
	SNI  string          `json:"sni"`
	ALPN string          `json:"alpn"`
	FP   string          `json:"fp"`
	Scy  string          `json:"scy"`
}

// SSHServer represents an SSH server configuration
type SSHServer struct {
	User     string
	Host     string
	Port     string
	Identity string
}

// SOCKS5Proxy manages SSH tunnel and proxy connection
type SOCKS5Proxy struct {
	sshCmd   *exec.Cmd
	proxyURL *url.URL
	closed   bool
	mu       sync.Mutex
}

// NewSOCKS5Proxy creates a new SSH tunnel and returns a proxy URL
func NewSOCKS5Proxy(server SSHServer) (*SOCKS5Proxy, error) {
	// Find available local port
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return nil, fmt.Errorf("failed to find free port: %w", err)
	}
	port := listener.Addr().(*net.TCPAddr).Port
	listener.Close()

	// Build SSH command
	sshArgs := []string{
		"-o", "ConnectTimeout=10",
		"-o", "ServerAliveInterval=60",
		"-D", fmt.Sprintf("127.0.0.1:%d", port),
		"-N", // Do not execute remote command
	}

	if server.Identity != "" {
		sshArgs = append(sshArgs, "-i", server.Identity)
	}

	sshArgs = append(sshArgs, fmt.Sprintf("%s@%s", server.User, server.Host))
	if server.Port != "" {
		sshArgs = append(sshArgs, "-p", server.Port)
	}

	cmd := exec.Command("ssh", sshArgs...)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr

	if err := cmd.Start(); err != nil {
		return nil, fmt.Errorf("failed to start SSH: %w", err)
	}

	// Verify tunnel is ready
	if !waitForPort(port, 5*time.Second) {
		cmd.Process.Kill()
		return nil, fmt.Errorf("timeout waiting for SSH tunnel to start")
	}

	proxyURL, _ := url.Parse(fmt.Sprintf("socks5://127.0.0.1:%d", port))
	return &SOCKS5Proxy{
		sshCmd:   cmd,
		proxyURL: proxyURL,
	}, nil
}

// Close terminates the SSH tunnel
func (p *SOCKS5Proxy) Close() {
	p.mu.Lock()
	defer p.mu.Unlock()

	if p.closed {
		return
	}

	if p.sshCmd != nil && p.sshCmd.Process != nil {
		p.sshCmd.Process.Kill()
		p.sshCmd.Wait()
	}
	p.closed = true
}

// waitForPort checks if a port becomes available
func waitForPort(port int, timeout time.Duration) bool {
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		conn, err := net.DialTimeout("tcp", fmt.Sprintf("127.0.0.1:%d", port), 500*time.Millisecond)
		if err == nil {
			conn.Close()
			return true
		}
		time.Sleep(100 * time.Millisecond)
	}
	return false
}

// parseSSHServer parses server string into SSHServer struct
func parseSSHServer(spec string) (SSHServer, error) {
	re := regexp.MustCompile(`^(?:(?P<user>[^@]+)@)?(?P<host>[^:]+)(?::(?P<port>\d+))?$`)
	matches := re.FindStringSubmatch(spec)
	if matches == nil {
		return SSHServer{}, fmt.Errorf("invalid SSH server format: %s", spec)
	}

	result := make(map[string]string)
	for i, name := range re.SubexpNames() {
		if i != 0 && name != "" {
			result[name] = matches[i]
		}
	}

	port := "22"
	if result["port"] != "" {
		port = result["port"]
	}

	return SSHServer{
		User:     result["user"],
		Host:     result["host"],
		Port:     port,
		Identity: "",
	}, nil
}

// getTransportWithProxy creates HTTP transport with proxy support
func getTransportWithProxy(proxyURL *url.URL) *http.Transport {
	return &http.Transport{
		Proxy: http.ProxyURL(proxyURL),
		DialContext: (&net.Dialer{
			Timeout:   30 * time.Second,
			KeepAlive: 30 * time.Second,
			DualStack: true,
		}).DialContext,
		MaxIdleConns:          100,
		IdleConnTimeout:       90 * time.Second,
		TLSHandshakeTimeout:   10 * time.Second,
		ExpectContinueTimeout: 1 * time.Second,
	}
}

// --- CORE LOGIC: Replicates Python Script ---
func parseLinkToOutboundJSON(link, tag string) (json.RawMessage, error) {
	u, err := url.Parse(link)
	if err != nil {
		return nil, fmt.Errorf("invalid link format: %w", err)
	}

	out := Outbound{Tag: tag, Mux: &Mux{Enabled: false, Concurrency: 8}}

	switch u.Scheme {
	case "vless":
		out.Protocol = "vless"
		port, _ := strconv.Atoi(u.Port())
		if port == 0 {
			port = 443
		}
		queryParams := u.Query()
		encryption := queryParams.Get("encryption")
		if encryption == "" {
			encryption = "none"
		}
		networkType := queryParams.Get("type")
		if networkType == "" {
			networkType = "tcp"
		}

		settings := VlessSettings{
			VNext: []*VlessServer{{
				Address: u.Hostname(), Port: port,
				Users: []*VlessUser{{
					ID: u.User.Username(), Encryption: encryption, Flow: queryParams.Get("flow"),
				}},
			}},
		}
		settingsJSON, _ := json.Marshal(settings)
		out.Settings = json.RawMessage(settingsJSON)

		ss := &StreamSettings{Network: networkType, Security: queryParams.Get("security"), Sockopt: &Sockopt{DialerProxy: "dialer"}}
		if ss.Security == "tls" || ss.Security == "reality" {
			sni := queryParams.Get("sni")
			if sni == "" {
				sni = queryParams.Get("host")
			}
			if ss.Security == "tls" {
				ss.TLSSettings = &TLSSettings{
					ServerName:    sni,
					Fingerprint:   queryParams.Get("fp"),
					AllowInsecure: true,
					ALPN:          strings.Split(queryParams.Get("alpn"), ","),
				}
			} else {
				ss.RealitySettings = &RealitySettings{
					ServerName:  sni,
					PublicKey:   queryParams.Get("pbk"),
					ShortID:     queryParams.Get("sid"),
					SpiderX:     queryParams.Get("spx"),
					Fingerprint: queryParams.Get("fp"),
				}
			}
		}
		switch ss.Network {
		case "ws":
			ss.WSSettings = &WSSettings{
				Path:    queryParams.Get("path"),
				Headers: map[string]string{"Host": queryParams.Get("host")},
			}
		case "grpc":
			ss.GRPCSettings = &GRPCSettings{
				ServiceName: queryParams.Get("serviceName"),
				MultiMode:   queryParams.Get("mode") == "multi",
			}
		}
		out.StreamSettings = ss

	case "vmess":
		out.Protocol = "vmess"
		b64 := strings.TrimPrefix(link, "vmess://")
		if len(b64)%4 != 0 {
			b64 += strings.Repeat("=", 4-len(b64)%4)
		}
		decoded, err := base64.StdEncoding.DecodeString(b64)
		if err != nil {
			return nil, fmt.Errorf("invalid vmess base64: %w", err)
		}

		var vmessData VmessLink
		if err := json.Unmarshal(decoded, &vmessData); err != nil {
			return nil, fmt.Errorf("invalid vmess json: %w", err)
		}
		var port int
		if err := json.Unmarshal(vmessData.Port, &port); err != nil {
			var portStr string
			if err := json.Unmarshal(vmessData.Port, &portStr); err == nil {
				port, _ = strconv.Atoi(portStr)
			}
		}
		if port == 0 {
			port = 443
		}
		var aid int
		if err := json.Unmarshal(vmessData.Aid, &aid); err != nil {
			var aidStr string
			if err := json.Unmarshal(vmessData.Aid, &aidStr); err == nil {
				aid, _ = strconv.Atoi(aidStr)
			}
		}
		security := vmessData.Scy
		if security == "" || security == "auto" {
			security = "none"
		}

		settings := VmessSettings{
			VNext: []*VmessServer{{
				Address: vmessData.Add, Port: port,
				Users: []*VmessUser{{
					ID: vmessData.ID, AlterID: aid, Security: security,
				}},
			}},
		}
		settingsJSON, _ := json.Marshal(settings)
		out.Settings = json.RawMessage(settingsJSON)
		ss := &StreamSettings{
			Network:  vmessData.Net,
			Security: vmessData.TLS,
			Sockopt:  &Sockopt{DialerProxy: "dialer"},
		}
		if ss.Security == "tls" {
			sni := vmessData.SNI
			if sni == "" {
				sni = vmessData.Host
			}
			ss.TLSSettings = &TLSSettings{
				ServerName:    sni,
				Fingerprint:   vmessData.FP,
				AllowInsecure: true,
				ALPN:          strings.Split(vmessData.ALPN, ","),
			}
		}
		switch ss.Network {
		case "ws":
			ss.WSSettings = &WSSettings{
				Path:    vmessData.Path,
				Headers: map[string]string{"Host": vmessData.Host},
			}
		case "grpc":
			ss.GRPCSettings = &GRPCSettings{
				ServiceName: vmessData.Path,
				MultiMode:   vmessData.Type == "multi",
			}
		}
		out.StreamSettings = ss
	default:
		return nil, fmt.Errorf("unsupported link scheme: %s", u.Scheme)
	}
	return json.Marshal(out)
}

func main() {
	urls := flag.String("urls", "", "Comma-separated list of subscription URLs")
	timeout := flag.Duration("timeout", 10*time.Second, "Timeout for each network request")
	concurrency := flag.Int("concurrency", 20, "Number of concurrent workers to test configs")
	geoDBPath := flag.String("geoip-db", "GeoLite2-Country.mmdb", "Path to the GeoIP MMDB file")
	outputFile := flag.String("output", "v2rayng_profiles.json", "Name of the final output JSON file")
	sshServers := flag.String("ssh-servers", "", "Comma-separated list of SSH servers (user@host:port)")
	sshIdentity := flag.String("ssh-identity", "", "Path to SSH private key (default: ~/.ssh/id_rsa)")

	flag.Parse()

	if *urls == "" {
		log.Println("Error: -urls flag is required.")
		flag.Usage()
		os.Exit(1)
	}

	log.SetOutput(os.Stderr)
	log.Println("Starting proxy tester...")

	var err error
	geoDB, err = geoip2.Open(*geoDBPath)
	if err != nil {
		log.Fatalf("FATAL: Could not load GeoIP database from '%s'. Please download it from MaxMind. Error: %v", *geoDBPath, err)
	}
	defer geoDB.Close()

	// Parse SSH servers
	var sshServerList []SSHServer
	if *sshServers != "" {
		for _, spec := range strings.Split(*sshServers, ",") {
			server, err := parseSSHServer(strings.TrimSpace(spec))
			if err != nil {
				log.Printf("Skipping invalid SSH server '%s': %v", spec, err)
				continue
			}

			// Set identity file
			if *sshIdentity != "" {
				server.Identity = *sshIdentity
			} else {
				// Default to ~/.ssh/id_rsa
				homeDir, _ := os.UserHomeDir()
				defaultKey := filepath.Join(homeDir, ".ssh", "id_rsa")
				if _, err := os.Stat(defaultKey); err == nil {
					server.Identity = defaultKey
				}
			}

			sshServerList = append(sshServerList, server)
		}
	}

	// Add local as a test location if no SSH servers specified
	if len(sshServerList) == 0 {
		sshServerList = append(sshServerList, SSHServer{User: "local", Host: "127.0.0.1"})
	}

	var allProfiles []json.RawMessage

	// Process each test location
	for _, server := range sshServerList {
		var proxy *SOCKS5Proxy
		var client *http.Client

		// Set up SSH tunnel if not local
		if server.User != "local" {
			log.Printf("Setting up SSH tunnel for %s@%s:%s", server.User, server.Host, server.Port)
			proxy, err = NewSOCKS5Proxy(server)
			if err != nil {
				log.Printf("Failed to create SSH tunnel for %s: %v", server.Host, err)
				continue
			}
			defer proxy.Close()

			// Create HTTP client using the SOCKS5 proxy
			client = &http.Client{
				Transport: getTransportWithProxy(proxy.proxyURL),
				Timeout:   30 * time.Second,
			}
			log.Printf("SSH tunnel established: %s", proxy.proxyURL)
		} else {
			// Local testing - no proxy
			client = &http.Client{Timeout: 30 * time.Second}
		}

		// Determine test location country
		testLocationIP, testLocationCountry := getTestLocationCountry(client)
		log.Printf("Test location: %s (IP: %s, Country: %s)", server.Host, testLocationIP, testLocationCountry)

		// Fetch configs using the client (with proxy if applicable)
		subscriptionURLs := strings.Split(*urls, ",")
		allConfigs := fetchConfigsFromSubscriptions(subscriptionURLs, client)
		if len(allConfigs) == 0 {
			log.Printf("No proxy configurations found from %s", server.Host)
			continue
		}
		log.Printf("[%s] Found %d configs. Starting tests...", server.Host, len(allConfigs))

		// Test configs using the client (with proxy if applicable)
		results := testConfigs(*concurrency, allConfigs, *timeout, client)

		// Filter and sort results
		var fastProxies []Result
		for _, p := range results {
			if p.SpeedMbps >= minSpeedMbps {
				fastProxies = append(fastProxies, p)
			}
		}
		if len(fastProxies) == 0 {
			log.Printf("[%s] No proxies met the required speed of %.2f Mbps", server.Host, minSpeedMbps)
			continue
		}

		sort.SliceStable(fastProxies, func(i, j int) bool {
			return fastProxies[i].SpeedMbps > fastProxies[j].SpeedMbps
		})
		numTopProxies := topNFastest
		if len(fastProxies) < topNFastest {
			numTopProxies = len(fastProxies)
		}
		topProxies := fastProxies[:numTopProxies]
		log.Printf("[%s] Found %d fast proxies (top %d)", server.Host, len(fastProxies), numTopProxies)

		// Generate profile for this location
		profileName := fmt.Sprintf("%s (%s)", getCountryInfo(testLocationCountry).Name, server.Host)
		profile, err := generateSingleProfileConfig(profileName, testLocationCountry, topProxies)
		if err != nil {
			log.Printf("Failed to generate profile for %s: %v", server.Host, err)
			continue
		}
		allProfiles = append(allProfiles, profile)
	}

	if len(allProfiles) == 0 {
		log.Println("Warning: No valid profiles could be generated.")
		os.WriteFile(*outputFile, []byte("[]"), 0644)
		log.Printf("\nSUCCESS! An empty profile list has been written to %s", *outputFile)
		return
	}

	// Write all profiles to output file
	finalJSON, err := json.MarshalIndent(allProfiles, "", "  ")
	if err != nil {
		log.Fatalf("Failed to marshal the final list of profiles: %v", err)
	}
	if err := os.WriteFile(*outputFile, finalJSON, 0644); err != nil {
		log.Fatalf("Failed to write the final config file: %v", err)
	}
	log.Printf("\nSUCCESS! All profiles have been written to %s", *outputFile)
}

func generateSingleProfileConfig(profileName, countryCode string, proxies []Result) (json.RawMessage, error) {
	templateBytes, err := os.ReadFile("template.json")
	if err != nil {
		return nil, fmt.Errorf("could not read template.json: %w", err)
	}
	var config map[string]interface{}
	if err := json.Unmarshal(templateBytes, &config); err != nil {
		return nil, fmt.Errorf("could not parse template.json: %w", err)
	}

	var proxyOutbounds []interface{}
	for i, p := range proxies {
		tag := fmt.Sprintf("proxy%d", i+1)
		outboundJSON, err := parseLinkToOutboundJSON(p.Config, tag)
		if err != nil {
			log.Printf("Skipping invalid config link: %v", err)
			continue
		}
		var obj map[string]interface{}
		json.Unmarshal(outboundJSON, &obj)
		proxyOutbounds = append(proxyOutbounds, obj)
	}

	if len(proxyOutbounds) == 0 {
		return nil, fmt.Errorf("no valid proxies to generate profile for %s", profileName)
	}
	countryInfo := getCountryInfo(countryCode)
	config["remarks"] = fmt.Sprintf("%s %s", countryInfo.Emoji, countryInfo.Name)

	currentOutbounds, ok := config["outbounds"].([]interface{})
	if !ok {
		return nil, fmt.Errorf("template.json 'outbounds' is not an array")
	}
	config["outbounds"] = append(currentOutbounds, proxyOutbounds...)

	return json.Marshal(config)
}

type CountryInfo struct {
	Name  string
	Emoji string
}

func getCountryInfo(code string) CountryInfo {
	countryMap := map[string]CountryInfo{
		"FAST": {"Fastest Location", "⚡️"}, "US": {"United States", "🇺🇸"}, "DE": {"Germany", "🇩🇪"}, "GB": {"United Kingdom", "🇬🇧"},
		"FR": {"France", "🇫🇷"}, "JP": {"Japan", "🇯🇵"}, "KR": {"South Korea", "🇰🇷"}, "CA": {"Canada", "🇨🇦"}, "AU": {"Australia", "🇦🇺"},
		"NL": {"Netherlands", "🇳🇱"}, "HK": {"Hong Kong", "🇭🇰"}, "SG": {"Singapore", "🇸🇬"}, "TW": {"Taiwan", "🇹🇼"}, "FI": {"Finland", "🇫🇮"},
	}
	if info, ok := countryMap[code]; ok {
		return info
	}
	return CountryInfo{Name: code, Emoji: "🌐"}
}

// getTestLocationCountry determines the country of the test location
func getTestLocationCountry(client *http.Client) (string, string) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, "GET", ipCheckURL, nil)
	if err != nil {
		return "", "XX"
	}

	resp, err := client.Do(req)
	if err != nil {
		return "", "XX"
	}
	defer resp.Body.Close()

	ipBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", "XX"
	}

	ipStr := strings.TrimSpace(string(ipBytes))
	ip := net.ParseIP(ipStr)
	if ip == nil {
		return "", "XX"
	}

	record, err := geoDB.Country(ip)
	if err != nil {
		return ipStr, "XX"
	}

	return ipStr, record.Country.IsoCode
}

func fetchConfigsFromSubscriptions(urls []string, client *http.Client) []string {
	var wg sync.WaitGroup
	var mu sync.Mutex
	var allConfigs []string

	for _, url := range urls {
		wg.Add(1)
		go func(u string) {
			defer wg.Done()
			log.Printf("Fetching from %s...", u)
			resp, err := client.Get(u)
			if err != nil {
				log.Printf("Failed to fetch subscription from %s: %v", u, err)
				return
			}
			defer resp.Body.Close()
			if resp.StatusCode != http.StatusOK {
				log.Printf("Received non-200 status code from %s: %s", u, resp.Status)
				return
			}
			body, err := io.ReadAll(resp.Body)
			if err != nil {
				log.Printf("Failed to read response body from %s: %v", u, err)
				return
			}
			decodedBody, err := base64.StdEncoding.DecodeString(string(body))
			var content string
			if err != nil {
				content = string(body)
			} else {
				content = string(decodedBody)
			}
			configs := strings.Split(content, "\n")
			mu.Lock()
			for _, config := range configs {
				trimmed := strings.TrimSpace(config)
				if trimmed != "" {
					allConfigs = append(allConfigs, trimmed)
				}
			}
			mu.Unlock()
		}(url)
	}
	wg.Wait()
	return allConfigs
}

func testConfigs(numWorkers int, configs []string, timeout time.Duration, client *http.Client) []Result {
	jobs := make(chan string, len(configs))
	resultsChan := make(chan Result, len(configs))
	var wg sync.WaitGroup

	for i := 0; i < numWorkers; i++ {
		wg.Add(1)
		go worker(i+1, &wg, jobs, resultsChan, timeout, client)
	}

	for _, config := range configs {
		jobs <- config
	}
	close(jobs)

	go func() {
		wg.Wait()
		close(resultsChan)
	}()

	var finalResults []Result
	for result := range resultsChan {
		finalResults = append(finalResults, result)
	}
	return finalResults
}

func worker(id int, wg *sync.WaitGroup, jobs <-chan string, results chan<- Result, timeout time.Duration, client *http.Client) {
	defer wg.Done()
	for config := range jobs {
		var core pkg.Core
		if strings.HasPrefix(config, "hy") {
			core = singbox.NewSingboxService(false, true)
		} else {
			core = xray.NewXrayService(false, false)
		}
		proto, err := core.CreateProtocol(config)
		if err != nil || proto.Parse() != nil {
			continue
		}

		// Create HTTP client for proxy testing
		httpClient, instance, err := core.MakeHttpClient(proto, timeout)
		if err != nil {
			continue
		}
		defer instance.Close()

		// Check if proxy is reachable
		if !checkReachability(httpClient, timeout) {
			continue
		}
		log.Printf("[Worker %d] Sanity check PASSED for %s", id, proto.ConvertToGeneralConfig().Address)

		// Test download speed
		speed, err := testDownloadSpeed(httpClient, timeout*3)
		if err != nil {
			continue
		}
		log.Printf("[Worker %d] Speed test PASSED for %s | Speed: %.2f Mbps", id, proto.ConvertToGeneralConfig().Address, speed)

		// Get country of proxy server
		ipCheckClient, ipCheckInstance, err := core.MakeHttpClient(proto, timeout)
		if err != nil {
			continue
		}
		_, country := getIPAndCountry(ipCheckClient, timeout)
		ipCheckInstance.Close()

		if country == "" {
			log.Printf("[Worker %d] Geo-location FAILED for %s", id, proto.ConvertToGeneralConfig().Address)
			continue
		}
		log.Printf("[Worker %d] SUCCESS: %s | Country: %s", id, proto.ConvertToGeneralConfig().Address, country)

		results <- Result{
			Config:    config,
			SpeedMbps: speed,
			Country:   country,
		}
	}
}

func getIPAndCountry(client *http.Client, timeout time.Duration) (string, string) {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, "GET", ipCheckURL, nil)
	if err != nil {
		return "", ""
	}
	resp, err := client.Do(req)
	if err != nil {
		return "", ""
	}
	defer resp.Body.Close()
	ipBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", ""
	}
	ipStr := strings.TrimSpace(string(ipBytes))
	ip := net.ParseIP(ipStr)
	if ip == nil {
		return "", ""
	}
	record, err := geoDB.Country(ip)
	if err != nil {
		return ipStr, "XX"
	}
	return ipStr, record.Country.IsoCode
}

func checkReachability(client *http.Client, timeout time.Duration) bool {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, "HEAD", sanityCheckURL, nil)
	if err != nil {
		return false
	}
	resp, err := client.Do(req)
	if err != nil {
		return false
	}
	defer resp.Body.Close()
	return resp.StatusCode >= 200 && resp.StatusCode < 400
}

func testDownloadSpeed(client *http.Client, timeout time.Duration) (float64, error) {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, "GET", speedTestURL, nil)
	if err != nil {
		return 0, err
	}
	start := time.Now()
	resp, err := client.Do(req)
	if err != nil {
		return 0, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return 0, fmt.Errorf("received non-200 status: %s", resp.Status)
	}
	_, err = io.Copy(io.Discard, resp.Body)
	if err != nil {
		return 0, err
	}
	duration := time.Since(start).Seconds()
	if duration == 0 {
		return 0, fmt.Errorf("download took zero time")
	}
	speedMbps := (float64(speedTestFileSize) * 8) / duration / 1_000_000
	return speedMbps, nil
}
