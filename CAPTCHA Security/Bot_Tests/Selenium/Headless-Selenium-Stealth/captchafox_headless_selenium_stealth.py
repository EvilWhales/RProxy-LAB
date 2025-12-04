from selenium import webdriver
from selenium.webdriver.chrome.service import Service
from selenium.webdriver.chrome.options import Options
from selenium.webdriver.common.by import By
from selenium.webdriver.support.ui import WebDriverWait
from selenium.webdriver.support import expected_conditions as EC
from selenium_stealth import stealth
from time import sleep

options = Options()
options.binary_location = "/usr/bin/chromium"
options.add_argument("--headless=new")
options.add_experimental_option("detach", True)
service = Service(executable_path="/usr/bin/chromedriver")
driver = webdriver.Chrome(service=service, options=options)

stealth(driver,
        languages=["en-US", "en"],
        vendor="Google Inc.",
        platform="Win32",
        webgl_vendor="Intel Inc.",
        renderer="Intel Iris OpenGL Engine",
        fix_hairline=True,
        )

driver.get('https://portal.captchafox.com/register')
WebDriverWait(driver, 10).until(
    EC.element_to_be_clickable((By.XPATH, '/html/body/div/div[1]/div/div[2]/div[2]/form/div[2]/div/input')))
driver.find_element(By.XPATH, '/html/body/div/div[1]/div/div[2]/div[2]/form/div[2]/div/input').send_keys('John')

WebDriverWait(driver, 10).until(
    EC.element_to_be_clickable((By.XPATH, '/html/body/div/div[1]/div/div[2]/div[2]/form/div[3]/div/input')))
driver.find_element(By.XPATH, '/html/body/div/div[1]/div/div[2]/div[2]/form/div[3]/div/input').send_keys('Doe')

sleep(3)

submit_button_xpath = '/html/body/div/div[1]/div/div[2]/div[2]/form/div[4]/div/div/div[1]/div[1]'
WebDriverWait(driver, 10).until(
    EC.element_to_be_clickable((By.XPATH, submit_button_xpath)))
driver.find_element(By.XPATH, submit_button_xpath).click()

# We take a screenshot since selenium cant handle http intercepting
sleep(1)
driver.save_screenshot('captchafox_screen.png')

driver.quit()