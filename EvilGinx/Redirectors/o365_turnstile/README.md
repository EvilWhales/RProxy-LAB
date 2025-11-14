# O365 Turnstile Redirector

## Known Issue
You may see this error in the logs:
```
[err] lure: failed to read redirector data file: read /root/evilginx2/redirectors/o365_turnstile: is a directory
```

This is a harmless bug in evilginx2 that occurs when the browser makes multiple requests to the same lure URL. It does not affect functionality.

## Files in this directory:
- `index.html` - Main redirector page with Turnstile integration
- `favicon.ico` - Microsoft favicon to reduce 404 errors
- `robots.txt` - Prevents search engine indexing
- Other files added to minimize browser requests that trigger the directory read bug
