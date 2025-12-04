# Selenium tests

#### Requirements

The scripts assume that you have the chromium and chromedriver installed:

```python
# Chromium path
options.binary_location = "/usr/bin/chromium"

# Chromedriver path
service = Service(executable_path="/usr/bin/chromedriver")
```

Install the requirements:

```bash
pip install -r requirements.txt
```

#### Running

```bash
python3 [File]
```