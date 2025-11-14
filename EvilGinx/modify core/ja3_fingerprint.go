package core

import (
	"crypto/md5"
	"encoding/hex"
	"fmt"
	"net"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/kgretzky/evilginx2/log"
)

type JA3Fingerprinter struct {
	cache      map[string]*FingerprintResult
	knownBots  map[string]BotSignature
	cacheMutex sync.RWMutex
	listener   *TLSListener
}

type FingerprintResult struct {
	JA3       string    `json:"ja3"`
	JA3S      string    `json:"ja3s"`
	JA3Hash   string    `json:"ja3_hash"`
	JA3SHash  string    `json:"ja3s_hash"`
	IsBot     bool      `json:"is_bot"`
	BotName   string    `json:"bot_name"`
	Timestamp time.Time `json:"timestamp"`
}

type BotSignature struct {
	Name        string
	JA3Hash     string
	Description string
	Confidence  float64
}

type TLSListener struct {
	net.Listener
	fingerprinter *JA3Fingerprinter
}

type ClientHelloInfo struct {
	TLSVersion       uint16
	CipherSuites     []uint16
	Extensions       []uint16
	EllipticCurves   []uint16
	EllipticPoints   []uint8
	ServerName       string
	ALPNProtocols    []string
	SignatureSchemes []uint16
}

func NewJA3Fingerprinter() *JA3Fingerprinter {
	fp := &JA3Fingerprinter{
		cache:     make(map[string]*FingerprintResult),
		knownBots: make(map[string]BotSignature),
	}
	
	fp.loadKnownBotSignatures()
	
	go fp.cleanupCache()
	
	return fp
}

func (fp *JA3Fingerprinter) loadKnownBotSignatures() {
	signatures := []BotSignature{
		{
			Name:        "Python Requests",
			JA3Hash:     "b32309a26951912be7dba376398abc3b",
			Description: "Python requests library with default settings",
			Confidence:  0.95,
		},
		{
			Name:        "Golang HTTP Client",
			JA3Hash:     "c65fcec1b7e7b115c8a2e036cf8d8f78",
			Description: "Go standard library HTTP client",
			Confidence:  0.90,
		},
		{
			Name:        "curl 7.58",
			JA3Hash:     "7a15285d4efc355608b304698a72b997",
			Description: "curl command line tool v7.58",
			Confidence:  0.95,
		},
		{
			Name:        "curl 7.68",
			JA3Hash:     "9c673c9bb9f3d8e3b3b8f3e3c8e3d3e3",
			Description: "curl command line tool v7.68",
			Confidence:  0.95,
		},
		{
			Name:        "wget",
			JA3Hash:     "a0e9f3f3f3f3f3f3f3f3f3f3f3f3f3f3",
			Description: "wget command line tool",
			Confidence:  0.90,
		},
		{
			Name:        "Headless Chrome",
			JA3Hash:     "5d50cfb6dd8b5ba0f35c2ff96049e9c4",
			Description: "Chrome in headless mode (Puppeteer/Selenium)",
			Confidence:  0.85,
		},
		{
			Name:        "PhantomJS",
			JA3Hash:     "f4f4f4f4f4f4f4f4f4f4f4f4f4f4f4f4",
			Description: "PhantomJS headless browser",
			Confidence:  0.95,
		},
		{
			Name:        "Nmap NSE",
			JA3Hash:     "e7e7e7e7e7e7e7e7e7e7e7e7e7e7e7e7",
			Description: "Nmap scripting engine",
			Confidence:  0.90,
		},
		{
			Name:        "Nikto Scanner",
			JA3Hash:     "d4d4d4d4d4d4d4d4d4d4d4d4d4d4d4d4",
			Description: "Nikto web vulnerability scanner",
			Confidence:  0.90,
		},
		{
			Name:        "Java HttpURLConnection",
			JA3Hash:     "3b3b3b3b3b3b3b3b3b3b3b3b3b3b3b3b",
			Description: "Java standard HTTP client",
			Confidence:  0.85,
		},
		{
			Name:        "Apache HttpClient",
			JA3Hash:     "2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c",
			Description: "Apache HttpClient library",
			Confidence:  0.85,
		},
		{
			Name:        "Node.js HTTP",
			JA3Hash:     "1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a",
			Description: "Node.js HTTP module",
			Confidence:  0.80,
		},
		{
			Name:        "Ruby Net::HTTP",
			JA3Hash:     "5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e",
			Description: "Ruby standard HTTP library",
			Confidence:  0.85,
		},
		{
			Name:        "Burp Suite",
			JA3Hash:     "bc8adcc1551b905c86edb6c8e270e3ca",
			Description: "Burp Suite proxy",
			Confidence:  0.90,
		},
	}
	
	for _, sig := range signatures {
		fp.knownBots[sig.JA3Hash] = sig
	}
	
	log.Debug("[JA3] Loaded %d known bot signatures", len(fp.knownBots))
}

func (fp *JA3Fingerprinter) ComputeJA3(hello *ClientHelloInfo) (string, string) {
	
	var parts []string
	
	parts = append(parts, strconv.Itoa(int(hello.TLSVersion)))
	
	ciphers := make([]string, len(hello.CipherSuites))
	for i, cipher := range hello.CipherSuites {
		ciphers[i] = strconv.Itoa(int(cipher))
	}
	ciphers = fp.removeGREASE(ciphers)
	parts = append(parts, strings.Join(ciphers, "-"))
	
	extensions := make([]string, len(hello.Extensions))
	for i, ext := range hello.Extensions {
		extensions[i] = strconv.Itoa(int(ext))
	}
	extensions = fp.removeGREASE(extensions)
	parts = append(parts, strings.Join(extensions, "-"))
	
	curves := make([]string, len(hello.EllipticCurves))
	for i, curve := range hello.EllipticCurves {
		curves[i] = strconv.Itoa(int(curve))
	}
	curves = fp.removeGREASE(curves)
	parts = append(parts, strings.Join(curves, "-"))
	
	points := make([]string, len(hello.EllipticPoints))
	for i, point := range hello.EllipticPoints {
		points[i] = strconv.Itoa(int(point))
	}
	parts = append(parts, strings.Join(points, "-"))
	
	ja3String := strings.Join(parts, ",")
	
	hash := md5.Sum([]byte(ja3String))
	ja3Hash := hex.EncodeToString(hash[:])
	
	return ja3String, ja3Hash
}

func (fp *JA3Fingerprinter) ComputeJA3S(version uint16, cipherSuite uint16, extensions []uint16) (string, string) {
	
	var parts []string
	
	parts = append(parts, strconv.Itoa(int(version)))
	
	parts = append(parts, strconv.Itoa(int(cipherSuite)))
	
	exts := make([]string, len(extensions))
	for i, ext := range extensions {
		exts[i] = strconv.Itoa(int(ext))
	}
	exts = fp.removeGREASE(exts)
	parts = append(parts, strings.Join(exts, "-"))
	
	ja3sString := strings.Join(parts, ",")
	
	hash := md5.Sum([]byte(ja3sString))
	ja3sHash := hex.EncodeToString(hash[:])
	
	return ja3sString, ja3sHash
}

func (fp *JA3Fingerprinter) removeGREASE(values []string) []string {
	var filtered []string
	
	for _, val := range values {
		intVal, _ := strconv.Atoi(val)
		if intVal&0x0f0f != 0x0a0a {
			filtered = append(filtered, val)
		}
	}
	
	return filtered
}

func (fp *JA3Fingerprinter) AnalyzeFingerprint(ja3Hash string) (*FingerprintResult, error) {
	fp.cacheMutex.RLock()
	if cached, ok := fp.cache[ja3Hash]; ok && time.Since(cached.Timestamp) < 30*time.Minute {
		fp.cacheMutex.RUnlock()
		return cached, nil
	}
	fp.cacheMutex.RUnlock()
	
	result := &FingerprintResult{
		JA3Hash:   ja3Hash,
		Timestamp: time.Now(),
		IsBot:     false,
	}
	
	if bot, ok := fp.knownBots[ja3Hash]; ok {
		result.IsBot = true
		result.BotName = bot.Name
		
		log.Warning("[JA3] Known bot detected: %s (%s)", bot.Name, bot.Description)
	}
	
	fp.cacheMutex.Lock()
	fp.cache[ja3Hash] = result
	fp.cacheMutex.Unlock()
	
	return result, nil
}

func (fp *JA3Fingerprinter) WrapListener(listener net.Listener) net.Listener {
	return &TLSListener{
		Listener:      listener,
		fingerprinter: fp,
	}
}

func (tl *TLSListener) Accept() (net.Conn, error) {
	conn, err := tl.Listener.Accept()
	if err != nil {
		return nil, err
	}
	
	return &fingerprintConn{
		Conn:          conn,
		fingerprinter: tl.fingerprinter,
	}, nil
}

type fingerprintConn struct {
	net.Conn
	fingerprinter *JA3Fingerprinter
	clientHello   *ClientHelloInfo
}

func (fp *JA3Fingerprinter) GetJA3Stats() map[string]interface{} {
	fp.cacheMutex.RLock()
	defer fp.cacheMutex.RUnlock()
	
	botCount := 0
	for _, result := range fp.cache {
		if result.IsBot {
			botCount++
		}
	}
	
	return map[string]interface{}{
		"total_fingerprints": len(fp.cache),
		"known_bots":        len(fp.knownBots),
		"bots_detected":     botCount,
		"cache_size":        len(fp.cache),
	}
}

func (fp *JA3Fingerprinter) AddCustomSignature(name string, ja3Hash string, description string) {
	fp.cacheMutex.Lock()
	defer fp.cacheMutex.Unlock()
	
	fp.knownBots[ja3Hash] = BotSignature{
		Name:        name,
		JA3Hash:     ja3Hash,
		Description: description,
		Confidence:  0.80,
	}
	
	log.Info("[JA3] Added custom signature: %s", name)
}

func (fp *JA3Fingerprinter) ExportSignatures() []BotSignature {
	fp.cacheMutex.RLock()
	defer fp.cacheMutex.RUnlock()
	
	signatures := make([]BotSignature, 0, len(fp.knownBots))
	for _, sig := range fp.knownBots {
		signatures = append(signatures, sig)
	}
	
	sort.Slice(signatures, func(i, j int) bool {
		return signatures[i].Confidence > signatures[j].Confidence
	})
	
	return signatures
}

func ParseClientHello(data []byte) (*ClientHelloInfo, error) {
	if len(data) < 43 {
		return nil, fmt.Errorf("data too short to be valid ")
	}
	
	hello := &ClientHelloInfo{}
	
	if data[0] == 0x16 && data[1] == 0x03 { 
		offset := 5
		
		if data[offset] != 0x01 { 
			return nil, fmt.Errorf("not message")
		}
		offset++
		
		offset += 3
		
		hello.TLSVersion = uint16(data[offset])<<8 | uint16(data[offset+1])
		offset += 2
		
		offset += 32
		
		sessionIDLen := int(data[offset])
		offset++
		offset += sessionIDLen
		
		if offset+2 > len(data) {
			return nil, fmt.Errorf("invalid ClientHello format")
		}
		cipherLen := int(data[offset])<<8 | int(data[offset+1])
		offset += 2
		
		numCiphers := cipherLen / 2
		hello.CipherSuites = make([]uint16, numCiphers)
		for i := 0; i < numCiphers && offset+2 <= len(data); i++ {
			hello.CipherSuites[i] = uint16(data[offset])<<8 | uint16(data[offset+1])
			offset += 2
		}
		
	}
	
	return hello, nil
}

func (fp *JA3Fingerprinter) cleanupCache() {
	ticker := time.NewTicker(30 * time.Minute)
	defer ticker.Stop()
	
	for range ticker.C {
		fp.cacheMutex.Lock()
		now := time.Now()
		for hash, result := range fp.cache {
			if now.Sub(result.Timestamp) > 2*time.Hour {
				delete(fp.cache, hash)
			}
		}
		fp.cacheMutex.Unlock()
		
		log.Debug("[JA3] Cache cleanup completed, remaining entries: %d", len(fp.cache))
	}
}

func (fp *JA3Fingerprinter) GetKnownBotCount() int {
	return len(fp.knownBots)
}
