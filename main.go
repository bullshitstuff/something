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
	"os"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/naser-989/xray-knife/v3/pkg"
	"github.com/naser-989/xray-knife/v3/pkg/protocol"
	"github.com/naser-989/xray-knife/v3/pkg/singbox"
	"github.com/naser-989/xray-knife/v3/pkg/xray"
	"github.com/oschwald/geoip2-golang"
)

// Result holds the extended outcome of a successful test for a single config.
type Result struct {
	Config    string
	SpeedMbps float64
	Country   string
	protocol.Protocol
}

const (
	sanityCheckURL    = "https://googleads.g.doubleclick.net/mads/static/mad/sdk/native/production/sdk-core-v40-impl.html"
	speedTestURL      = "http://cachefly.cachefly.net/10mb.test"
	speedTestFileSize = 10 * 1024 * 1024
	ipCheckURL        = "https://api.ifconfig.me/ip"
	minSpeedMbps      = 80.0 // Minimum speed in Mbps to be included in the config
	topNFastest       = 20   // Number of proxies to include in the "Fastest" group
)

// Global GeoIP database reader
var geoDB *geoip2.Reader

// --- Structs for Xray Config Template (Unchanged) ---
type XrayConfig struct {
	Log              map[string]string        `json:"log"`
	DNS              map[string]interface{}   `json:"dns"`
	FakeDNS          []interface{}            `json:"fakedns"`
	Routing          RoutingConfig            `json:"routing"`
	Policy           map[string]interface{}   `json:"policy"`
	Inbounds         []map[string]interface{} `json:"inbounds"`
	Outbounds        []json.RawMessage        `json:"outbounds"`
	Observatory      ObservatoryConfig        `json:"observatory"`
	BurstObservatory BurstObservatoryConfig   `json:"burstObservatory"`
	Stats            map[string]interface{}   `json:"stats"`
	Remarks          string                   `json:"remarks"`
}

type RoutingConfig struct {
	Balancers      []BalancerRule `json:"balancers"`
	DomainStrategy string         `json:"domainStrategy"`
	Rules          []Rule         `json:"rules"`
}

type BalancerRule struct {
	Tag      string                 `json:"tag"`
	Selector []string               `json:"selector"`
	Strategy map[string]interface{} `json:"strategy"`
}

type Rule struct {
	Type        string `json:"type"`
	BalancerTag string `json:"balancerTag"`
	Network     string `json:"network"`
}

type ObservatoryConfig struct {
	SubjectSelector   []string `json:"subjectSelector"`
	ProbeURL          string   `json:"probeURL"`
	ProbeInterval     string   `json:"probeInterval"`
	EnableConcurrency bool     `json:"enableConcurrency"`
}

type BurstObservatoryConfig struct {
	SubjectSelector []string               `json:"subjectSelector"`
	PingConfig      map[string]interface{} `json:"pingConfig"`
}

func main() {
	// --- Command-Line Flags ---
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

	// --- 0. Load GeoIP Database ---
	var err error
	geoDB, err = geoip2.Open(*geoDBPath)
	if err != nil {
		log.Fatalf("FATAL: Could not load GeoIP database from '%s'. Please download it from MaxMind. Error: %v", *geoDBPath, err)
	}
	defer geoDB.Close()

	// --- 1. Fetch and Test ---
	subscriptionURLs := strings.Split(*urls, ",")
	allConfigs := fetchConfigsFromSubscriptions(subscriptionURLs)
	if len(allConfigs) == 0 {
		log.Fatal("No proxy configurations were found from the provided URLs.")
	}
	log.Printf("Found a total of %d configs. Starting tests...\n", len(allConfigs))
	results := testConfigs(*concurrency, allConfigs, *timeout)

	// --- 2. Filter Proxies by Speed ---
	var fastProxies []Result
	for _, p := range results {
		if p.SpeedMbps >= minSpeedMbps {
			fastProxies = append(fastProxies, p)
		}
	}
	if len(fastProxies) == 0 {
		log.Fatal("No proxies met the required speed of %.2f Mbps. Exiting.", minSpeedMbps)
	}
	log.Printf("Found %d proxies faster than %.2f Mbps.", len(fastProxies), minSpeedMbps)

	// --- 3. Generate All Profiles ---
	var allProfiles []XrayConfig

	// 3.1 Generate "Fastest Location" profile
	sort.SliceStable(fastProxies, func(i, j int) bool {
		return fastProxies[i].SpeedMbps > fastProxies[j].SpeedMbps
	})
	numTopProxies := topNFastest
	if len(fastProxies) < topNFastest {
		numTopProxies = len(fastProxies)
	}
	topProxies := fastProxies[:numTopProxies]
	log.Printf("Generating 'Fastest Location' profile with top %d proxies...", len(topProxies))
	fastestProfile := generateSingleProfileConfig("Fastest Location", "FAST", topProxies)
	allProfiles = append(allProfiles, fastestProfile)

	// 3.2 Generate Per-Country profiles
	groupedByCountry := make(map[string][]Result)
	for _, res := range fastProxies {
		groupedByCountry[res.Country] = append(groupedByCountry[res.Country], res)
	}

	for countryCode, countryResults := range groupedByCountry {
		countryInfo := getCountryInfo(countryCode)
		log.Printf("Generating '%s' profile with %d proxies...", countryInfo.Name, len(countryResults))
		countryProfile := generateSingleProfileConfig(countryInfo.Name, countryCode, countryResults)
		allProfiles = append(allProfiles, countryProfile)
	}

	// --- 4. Write Final Multi-Profile JSON File ---
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

// generateSingleProfileConfig creates one complete Xray config object.
func generateSingleProfileConfig(profileName, countryCode string, proxies []Result) XrayConfig {
	var proxyOutbounds []json.RawMessage
	var proxyTags []string

	for i, p := range proxies {
		proxyJSON, err := json.Marshal(p.Protocol)
		if err != nil {
			continue
		}

		var proxyMap map[string]interface{}
		if err := json.Unmarshal(proxyJSON, &proxyMap); err != nil {
			continue
		}

		// Use the profile name in the tag to ensure uniqueness within the config
		tag := fmt.Sprintf("proxy-%s-%d", strings.ReplaceAll(profileName, " ", ""), i)
		proxyMap["tag"] = tag
		proxyTags = append(proxyTags, tag)

		taggedProxyJSON, err := json.Marshal(proxyMap)
		if err != nil {
			continue
		}

		proxyOutbounds = append(proxyOutbounds, json.RawMessage(taggedProxyJSON))
	}

	countryInfo := getCountryInfo(countryCode)
	remarks := fmt.Sprintf("%s %s", countryInfo.Emoji, countryInfo.Name)

	// Create the final config from the template structure
	config := XrayConfig{
		Log:     map[string]string{"loglevel": "warning"},
		DNS:     map[string]interface{}{"queryStrategy": "UseIPv4", "servers": []string{"https://1.0.0.1/dns-query"}, "tag": "dns_out"},
		FakeDNS: []interface{}{},
		Routing: RoutingConfig{
			DomainStrategy: "IPIfNonMatch",
			Balancers: []BalancerRule{{
				Tag:      "balancer",
				Selector: proxyTags,
				Strategy: map[string]interface{}{"type": "leastPing"},
			}},
			Rules: []Rule{{Type: "field", BalancerTag: "balancer", Network: "tcp,udp"}},
		},
		Policy: map[string]interface{}{"system": map[string]bool{"statsOutboundDownlink": true, "statsOutboundUplink": true}},
		Inbounds: []map[string]interface{}{
			{"port": 10808, "protocol": "socks", "settings": map[string]interface{}{"auth": "noauth", "udp": true, "userLevel": 8}, "sniffing": map[string]interface{}{"destOverride": []string{"http", "tls"}, "enabled": true}, "tag": "socks"},
			{"port": 10809, "protocol": "http", "settings": map[string]interface{}{"userLevel": 8}, "tag": "http"},
		},
		Outbounds: []json.RawMessage{
			json.RawMessage(`{"tag":"dialer","protocol":"freedom","settings":{"fragment":{"packets":"tlshello","length":"1-10","interval":"0-1"}}}`),
			json.RawMessage(`{"tag":"direct","protocol":"freedom","settings":{"domainStrategy":"UseIPv4"}}`),
			json.RawMessage(`{"tag":"block","protocol":"blackhole"}`),
			json.RawMessage(`{"tag":"dns-out","protocol":"dns"}`),
		},
		Observatory: ObservatoryConfig{
			SubjectSelector:   proxyTags,
			ProbeURL:          "http://www.google.com/gen_204",
			ProbeInterval:     "5m",
			EnableConcurrency: true,
		},
		BurstObservatory: BurstObservatoryConfig{
			SubjectSelector: proxyTags,
			PingConfig:      map[string]interface{}{"destination": "http://www.google.com/gen_204", "interval": "5m", "timeout": "10s", "sampling": 3},
		},
		Stats:   map[string]interface{}{},
		Remarks: remarks,
	}
	config.Outbounds = append(config.Outbounds, proxyOutbounds...)

	return config
}

// --- Helper Functions (Identical to previous version) ---

type CountryInfo struct {
	Name  string
	Emoji string
}

func getCountryInfo(code string) CountryInfo {
	countryMap := map[string]CountryInfo{
		"FAST": {"Fastest Location", "⚡️"},
		"US":   {"United States", "🇺🇸"},
		"DE":   {"Germany", "🇩🇪"},
		"GB":   {"United Kingdom", "🇬🇧"},
		"FR":   {"France", "🇫🇷"},
		"JP":   {"Japan", "🇯🇵"},
		"KR":   {"South Korea", "🇰🇷"},
		"CA":   {"Canada", "🇨🇦"},
		"AU":   {"Australia", "🇦🇺"},
		"NL":   {"Netherlands", "🇳🇱"},
		"HK":   {"Hong Kong", "🇭🇰"},
		"SG":   {"Singapore", "🇸🇬"},
		"TW":   {"Taiwan", "🇹🇼"},
		"FI":   {"Finland", "🇫🇮"},
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
		results <- Result{Config: config, SpeedMbps: speed, Country: country, Protocol: proto}
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
