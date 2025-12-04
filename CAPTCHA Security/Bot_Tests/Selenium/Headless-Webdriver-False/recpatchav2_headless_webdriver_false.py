from selenium import webdriver
from selenium.webdriver.chrome.service import Service
from selenium.webdriver.chrome.options import Options
from selenium.webdriver.common.by import By
from selenium.webdriver.support.ui import WebDriverWait
from selenium.webdriver.support import expected_conditions as EC
from time import sleep

options = Options()
options.binary_location = "/usr/bin/chromium"
options.add_argument("--headless=new")
options.add_experimental_option("detach", True)
service = Service(executable_path="/usr/bin/chromedriver")
driver = webdriver.Chrome(service=service, options=options)

driver.execute_cdp_cmd("Page.addScriptToEvaluateOnNewDocument", {
    "source": """
    Object.defineProperty(navigator, 'webdriver', {
     get: () => undefined
    })
  """
})

driver.get('https://captchatest.online/recaptcha_v2')

WebDriverWait(driver, 10).until(EC.element_to_be_clickable((By.XPATH, '//*[@id="username"]')))
driver.find_element(By.XPATH, '//*[@id="username"]').send_keys('John')

WebDriverWait(driver, 10).until(EC.element_to_be_clickable((By.XPATH, '//*[@id="password"]')))
driver.find_element(By.XPATH, '//*[@id="password"]').send_keys('Doe')

sleep(3)

# Switch to the reCAPTCHA iframe
iframe = WebDriverWait(driver, 10).until(EC.presence_of_element_located((By.CSS_SELECTOR, 'iframe[title="reCAPTCHA"]')))
driver.switch_to.frame(iframe)

# Click the checkbox inside the iframe
WebDriverWait(driver, 10).until(EC.element_to_be_clickable((By.ID, "recaptcha-anchor"))).click()

# Switch back to the main document
driver.switch_to.default_content()

sleep(1)

WebDriverWait(driver, 10).until(EC.element_to_be_clickable((By.XPATH, '/html/body/div[1]/main/form/button'))).click()

sleep(2) 

print(driver.page_source)

driver.quit()