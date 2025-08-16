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

// Simplified Result struct from your base code
type Result struct {
	Config    string
	SpeedMbps float64
	Country   string
	// The protocol.Protocol is no longer needed here as we parse from the raw string
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

// --- CORE LOGIC: Replicates Python Script ---
func parseLinkToOutboundJSON(link, tag string) (json.RawMessage, error) {
	u, err := url.Parse(link)
	if err != nil {
		return nil, fmt.Errorf("invalid link format: %w", err)
	}

	out := Outbound{Tag: tag, Mux: &Mux{Enabled: true, Concurrency: 8}}

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
				ss.TLSSettings = &TLSSettings{ServerName: sni, Fingerprint: queryParams.Get("fp"), AllowInsecure: true, ALPN: strings.Split(queryParams.Get("alpn"), ",")}
			} else {
				ss.RealitySettings = &RealitySettings{ServerName: sni, PublicKey: queryParams.Get("pbk"), ShortID: queryParams.Get("sid"), SpiderX: queryParams.Get("spx"), Fingerprint: queryParams.Get("fp")}
			}
		}
		switch ss.Network {
		case "ws":
			ss.WSSettings = &WSSettings{Path: queryParams.Get("path"), Headers: map[string]string{"Host": queryParams.Get("host")}}
		case "grpc":
			ss.GRPCSettings = &GRPCSettings{ServiceName: queryParams.Get("serviceName"), MultiMode: queryParams.Get("mode") == "multi"}
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
				Users: []*VmessUser{{ID: vmessData.ID, AlterID: aid, Security: security}},
			}},
		}
		settingsJSON, _ := json.Marshal(settings)
		out.Settings = json.RawMessage(settingsJSON)
		ss := &StreamSettings{Network: vmessData.Net, Security: vmessData.TLS, Sockopt: &Sockopt{DialerProxy: "dialer"}}
		if ss.Security == "tls" {
			sni := vmessData.SNI
			if sni == "" {
				sni = vmessData.Host
			}
			ss.TLSSettings = &TLSSettings{ServerName: sni, Fingerprint: vmessData.FP, AllowInsecure: true, ALPN: strings.Split(vmessData.ALPN, ",")}
		}
		switch ss.Network {
		case "ws":
			ss.WSSettings = &WSSettings{Path: vmessData.Path, Headers: map[string]string{"Host": vmessData.Host}}
		case "grpc":
			ss.GRPCSettings = &GRPCSettings{ServiceName: vmessData.Path, MultiMode: vmessData.Type == "multi"}
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

	subscriptionURLs := strings.Split(*urls, ",")
	allConfigs := fetchConfigsFromSubscriptions(subscriptionURLs)
	if len(allConfigs) == 0 {
		log.Fatal("No proxy configurations were found from the provided URLs.")
	}
	log.Printf("Found a total of %d configs. Starting tests...\n", len(allConfigs))
	results := testConfigs(*concurrency, allConfigs, *timeout)

	var fastProxies []Result
	for _, p := range results {
		if p.SpeedMbps >= minSpeedMbps {
			fastProxies = append(fastProxies, p)
		}
	}
	if len(fastProxies) == 0 {
		log.Println("Warning: No proxies met the required speed of %.2f Mbps.", minSpeedMbps)
		os.WriteFile(*outputFile, []byte("[]"), 0644)
		log.Printf("\nSUCCESS! An empty profile list has been written to %s", *outputFile)
		return
	}
	log.Printf("Found %d proxies faster than %.2f Mbps.", len(fastProxies), minSpeedMbps)

	var allProfiles []json.RawMessage
	sort.SliceStable(fastProxies, func(i, j int) bool { return fastProxies[i].SpeedMbps > fastProxies[j].SpeedMbps })
	numTopProxies := topNFastest
	if len(fastProxies) < topNFastest {
		numTopProxies = len(fastProxies)
	}
	topProxies := fastProxies[:numTopProxies]
	log.Printf("Generating 'Fastest Location' profile with top %d proxies...", len(topProxies))
	fastestProfile, err := generateSingleProfileConfig("Fastest Location", "FAST", topProxies)
	if err == nil {
		allProfiles = append(allProfiles, fastestProfile)
	}

	groupedByCountry := make(map[string][]Result)
	for _, res := range fastProxies {
		groupedByCountry[res.Country] = append(groupedByCountry[res.Country], res)
	}
	for countryCode, countryResults := range groupedByCountry {
		countryInfo := getCountryInfo(countryCode)
		log.Printf("Generating '%s' profile with %d proxies...", countryInfo.Name, len(countryResults))
		countryProfile, err := generateSingleProfileConfig(countryInfo.Name, countryCode, countryResults)
		if err == nil {
			allProfiles = append(allProfiles, countryProfile)
		}
	}

	if len(allProfiles) == 0 {
		log.Println("Warning: No valid profiles could be generated.")
		os.WriteFile(*outputFile, []byte("[]"), 0644)
		log.Printf("\nSUCCESS! An empty profile list has been written to %s", *outputFile)
		return
	}

	finalJSON, err := json.MarshalIndent(allProfiles, "", "  ")
	if err != nil {
		log.Fatalf("Failed to marshal the final list of profiles: %v", err)
	}
	err = os.WriteFile(*outputFile, finalJSON, 0644)
	if err != nil {
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
		// *** This now uses the new, simplified tagging scheme ***
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
	// Append the newly generated proxies
	config["outbounds"] = append(currentOutbounds, proxyOutbounds...)

	// No longer need to modify selectors, the template handles it!
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
func fetchConfigsFromSubscriptions(urls []string) []string {
	var wg sync.WaitGroup
	var mu sync.Mutex
	var allConfigs []string
	for _, url := range urls {
		wg.Add(1)
		go func(u string) {
			defer wg.Done()
			log.Printf("Fetching from %s...", u)
			client := http.Client{Timeout: 15 * time.Second}
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
func testConfigs(numWorkers int, configs []string, timeout time.Duration) []Result {
	jobs := make(chan string, len(configs))
	resultsChan := make(chan Result, len(configs))
	var wg sync.WaitGroup
	for i := 0; i < numWorkers; i++ {
		wg.Add(1)
		go worker(i+1, &wg, jobs, resultsChan, timeout)
	}
	for _, config := range configs {
		jobs <- config
	}
	close(jobs)
	go func() { wg.Wait(); close(resultsChan) }()
	var finalResults []Result
	for result := range resultsChan {
		finalResults = append(finalResults, result)
	}
	return finalResults
}
func worker(id int, wg *sync.WaitGroup, jobs <-chan string, results chan<- Result, timeout time.Duration) {
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
		httpClient, instance, err := core.MakeHttpClient(proto, timeout)
		if err != nil {
			continue
		}
		isReachable := checkReachability(httpClient, timeout)
		instance.Close()
		if !isReachable {
			continue
		}
		log.Printf("Sanity check PASSED for %s. Proceeding to speed test.", proto.ConvertToGeneralConfig().Address)
		speedTestClient, speedTestInstance, err := core.MakeHttpClient(proto, timeout*3)
		if err != nil {
			continue
		}
		speed, err := testDownloadSpeed(speedTestClient, timeout*3)
		speedTestInstance.Close()
		if err != nil {
			continue
		}
		log.Printf("Speed test PASSED for %s | Speed: %.2f Mbps", proto.ConvertToGeneralConfig().Address, speed)
		ipCheckClient, ipCheckInstance, err := core.MakeHttpClient(proto, timeout)
		if err != nil {
			continue
		}
		ip, country := getIPAndCountry(ipCheckClient, timeout)
		ipCheckInstance.Close()
		if country == "" {
			log.Printf("Geo-location FAILED for %s", proto.ConvertToGeneralConfig().Address)
			continue
		}
		log.Printf("SUCCESS: %s | Outbound IP: %s | Country: %s", proto.ConvertToGeneralConfig().Address, ip, country)
		results <- Result{Config: config, SpeedMbps: speed, Country: country}
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
