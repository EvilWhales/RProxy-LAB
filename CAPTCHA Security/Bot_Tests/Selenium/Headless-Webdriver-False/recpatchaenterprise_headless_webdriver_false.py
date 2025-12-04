from selenium import webdriver
from selenium.webdriver.chrome.service import Service
from selenium.webdriver.chrome.options import Options
from selenium.webdriver.common.by import By
from selenium.webdriver.support.ui import WebDriverWait
from selenium.webdriver.support import expected_conditions as EC
from time import sleep

# Function to perform actions on captchatest.online
def captchatest_actions(driver):
    driver.get('https://captchatest.online/recaptcha_enterprise')
    WebDriverWait(driver, 10).until(EC.element_to_be_clickable((By.ID, "username")))
    driver.find_element(By.ID, "username").send_keys('John')

    WebDriverWait(driver, 10).until(EC.element_to_be_clickable((By.ID, "password")))
    driver.find_element(By.ID, "password").send_keys('Doe')

    submit_button_xpath = '/html/body/div[1]/main/form/button'
    WebDriverWait(driver, 10).until(EC.element_to_be_clickable((By.XPATH, submit_button_xpath)))
    driver.find_element(By.XPATH, submit_button_xpath).click()
    sleep(2)

    # Print out the entire page source
    print(driver.page_source)

# Function to perform actions on 2captcha.com
def captcha2_actions(driver):
    driver.get('https://2captcha.com/demo/recaptcha-v3-enterprise')
    sleep(3)  # Simulate delay for page scripts

    submit_button_xpath = '/html/body/div[1]/div/main/div/div/div[2]/section/div/form/div[2]/button[1]'
    WebDriverWait(driver, 10).until(EC.element_to_be_clickable((By.XPATH, submit_button_xpath)))
    driver.find_element(By.XPATH, submit_button_xpath).click()
    sleep(2)

    # Extract and print text content using XPath
    text_element = driver.find_element(By.XPATH, "/html/body/div[1]/div/main/div/div/div[2]/section/div/form/div[1]/pre/code")
    if text_element:
        print("Text content of the element:", text_element.text)
    else:
        print("No element found with the given XPath.")

# Configure Selenium WebDriver
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

# Choose site to act on
site_url = 'captchatest.online'  # Change this to '2captcha.com' to switch sites

if site_url == 'captchatest.online':
    captchatest_actions(driver)
elif site_url == '2captcha.com':
    captcha2_actions(driver)

# Close the browser
driver.quit()
