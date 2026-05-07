import time
import undetected_chromedriver as uc
from selenium.webdriver.common.by import By
from selenium.webdriver.support.ui import WebDriverWait
from selenium.webdriver.support import expected_conditions as EC
from selenium.webdriver.common.keys import Keys # <-- Added this!

def test_cve_login():
    print("Starting undetected-chromedriver...")
    
    options = uc.ChromeOptions()
    options.add_argument("--window-size=1280,1024")
    
    driver = uc.Chrome(options=options, version_main=145)
    
    try:
        login_url = "https://platform.securityscorecard.io/#/external/oauth?client_id=cve-details&redirect_uri=https%3A%2F%2Fwww.cvedetails.com%2Fsign-in%2Fcallback&state=8e6910e1ba3f7c2da5bafa5840dd0b97956c24a8&scope=openid&response_type=code"
        print(f"Navigating to {login_url}...")
        driver.get(login_url)
        
        time.sleep(5)
        
        print("Waiting for login elements to appear...")
        wait = WebDriverWait(driver, 15)
        
        # Enter Email
        email_input = wait.until(EC.presence_of_element_located((By.CSS_SELECTOR, "input[type='email'], input[name='email'], input[name='username']")))
        print("Login form found! Sending email...")
        email_input.send_keys("uc2023205631@student.uc.pt")
        
        # Enter Password
        print("Sending password...")
        password_input = wait.until(EC.presence_of_element_located((By.CSS_SELECTOR, "input[type='password']")))
        password_input.send_keys("Vunerability1234@")
        
        time.sleep(1)
        
        
        print("Pressing ENTER to submit...")
        password_input.send_keys(Keys.RETURN)
        
        print("Waiting 30 seconds for you to manually observe the redirect...")
        time.sleep(30)
        
    except Exception as e:
        print(f"\nAn error occurred: {e}")
        
    finally:
        print("\nClosing the browser...")
        driver.quit()

if __name__ == "__main__":
    test_cve_login()