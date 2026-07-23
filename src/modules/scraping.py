#!/usr/bin/env python3

"""
	This module defines any methods and classes that are used to download and parse vulnerability metadata from websites.
"""

import json
import os
import random
import re
import time
from typing import Optional, Pattern, Union
from urllib.parse import urlsplit, parse_qsl

import requests
import undetected_chromedriver as uc
from selenium.webdriver.common.by import By
from selenium.webdriver.support.ui import WebDriverWait
from selenium.webdriver.support import expected_conditions as EC
from selenium.webdriver.common.keys import Keys

from .common import log, GLOBAL_CONFIG

####################################################################################################

class ScrapingManager():
	""" Represents a connection to one or more websites and provides methods for downloading their pages. """

	session: requests.Session
	connect_timeout: float
	read_timeout: float
	
	use_random_headers: bool
	sleep_random_amounts: bool
	is_logged_in: bool
	
	_driver: Optional[uc.Chrome]

	DEFAULT_HEADERS: dict = {
		'Accept-Language': 'en-US',
		'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/83.0.4103.116 Safari/537.36'
	}

	BROWSER_HEADERS: list = list( GLOBAL_CONFIG['http_headers'].values() )

	def __init__(	self, url_prefixes: Union[str, list] = [],
					connect_timeout: float = 10.0, read_timeout: float = 5.0,
					max_retries: int = 5, headers: dict = DEFAULT_HEADERS,
					use_random_headers: bool = True,sleep_random_amounts: bool = True):
		
		# Initialize a standard session for non-protected sites if needed, 
		# but we will primarily use the driver for CVEDetails.
		self.session = requests.Session()
		adapter = requests.adapters.HTTPAdapter(max_retries=max_retries)

		if isinstance(url_prefixes, str):
			url_prefixes = [url_prefixes]

		for prefix in url_prefixes:
			self.session.mount(prefix, adapter)

		self.session.headers.update(headers)
		
		self.connect_timeout = connect_timeout
		self.read_timeout = read_timeout
		self.use_random_headers = use_random_headers
		self.sleep_random_amounts = sleep_random_amounts
		self.is_logged_in = False
		self._driver = None

	def _get_driver(self) -> uc.Chrome:
		""" Returns a persistent undetected-chromedriver instance. """
		# Check if driver exists but is dead (e.g. user closed it or session crashed)
		if self._driver is not None:
			try:
				# Simple command to check if session is still alive
				_ = self._driver.current_url
			except Exception:
				log.warning("Existing browser session is invalid or closed. Re-initializing...")
				try:
					self._driver.quit()
				except:
					pass
				self._driver = None

		if self._driver is None:
			log.info("Initializing automated browser...")
			
			def create_options(use_profile=True):
				options = uc.ChromeOptions()
				options.add_argument("--window-size=1920,1080")
				options.add_argument("--no-sandbox")
				options.add_argument("--disable-gpu")
				
				if use_profile:
					profile_dir = os.path.join(os.path.dirname(__file__), "data", "chrome_profile")
					os.makedirs(profile_dir, exist_ok=True)
					options.add_argument(f"--user-data-dir={profile_dir}")
				return options
			
			try:
				options = create_options(use_profile=True)
				self._driver = uc.Chrome(options=options, version_main=148, use_subprocess=True)
			except Exception as e:
				log.error(f"Failed to initialize browser with profile: {e}. Attempting without profile...")
				options = create_options(use_profile=False)
				self._driver = uc.Chrome(options=options, version_main=148, use_subprocess=True)
		return self._driver

	def load_cookies_from_file(self) -> bool:
		""" Loads cookies from a manually exported JSON file. """
		cookies_paths = [
			os.path.join(os.path.dirname(__file__), "data", "manual_cookies.json"),
			os.path.join(os.path.dirname(__file__), "data", "cookies", "manual_cookies.json")
		]
		
		for cookies_path in cookies_paths:
			if os.path.exists(cookies_path):
				try:
					with open(cookies_path, 'r') as f:
						cookies_list = json.load(f)
						driver = self._get_driver()
						# Prime the domain
						driver.get("https://www.cvedetails.com")
						time.sleep(10) # Wait for initial load
						for cookie in cookies_list:
							c = {
								'name': cookie['name'],
								'value': cookie['value'],
								'domain': '.cvedetails.com', # Force domain
								'path': '/'
							}
							try:
								driver.add_cookie(c)
							except Exception as e:
								pass
						
						# Refresh to apply cookies
						driver.refresh()
						time.sleep(5)
					log.info(f"Successfully loaded manual cookies from {cookies_path}")
					return True
				except Exception as e:
					log.error(f"Failed to load manual cookies: {e}")
		return False

	def login_cve_details(self):
		""" Automates login to CVE Details or uses manual cookies if available. """
		
		if self.is_logged_in:
			return

		if self.load_cookies_from_file():
			# Verify if cookies worked
			driver = self._get_driver()
			if "Sign Out" in driver.page_source or "My Account" in driver.page_source:
				log.info("Manual cookies verified: Logged in successfully.")
				self.is_logged_in = True
				return
			else:
				log.warning("Manual cookies loaded but 'Sign Out' not found. Might still be blocked.")

		username = GLOBAL_CONFIG.get('account_username')
		password = GLOBAL_CONFIG.get('account_password')
		
		if not username or not password or username == "<Username>" or password == "<Password>":
			log.error("Login credentials not configured. Skipping automated login fallback.")
			return

		driver = self._get_driver()
		# ... (rest of automated login remains as fallback)
		try:
			log.info("Performing automated login fallback...")
			driver.get("https://www.cvedetails.com")
			time.sleep(5)
			
			if "Sign Out" in driver.page_source or "My Account" in driver.page_source:
				log.info("Already logged in.")
				self.is_logged_in = True
				return

			# Find and click the Log In button dynamically
			log.info("Searching for login link...")
			found_link = False
			for text in ["Log In", "Log in", "Login", "Sign In", "Sign in", "Signin"]:
				try:
					login_link = driver.find_element(By.PARTIAL_LINK_TEXT, text)
					login_link.click()
					found_link = True
					log.info(f"Clicked login link with text: '{text}'")
					break
				except:
					continue
			
			if not found_link:
				log.warning("Could not find standard login link. Searching for SSO links...")
				try:
					links = driver.find_elements(By.TAG_NAME, "a")
					for link in links:
						href = link.get_attribute("href")
						if href and "securityscorecard.io" in href:
							link.click()
							found_link = True
							log.info("Clicked SSO login link.")
							break
				except:
					pass
			
			if not found_link:
				log.error("Could not find any login link on the page.")
				log.warning("PLEASE MANUALLY NAVIGATE TO THE LOGIN PAGE IN THE BROWSER.")
				log.warning("Once you see the email/password fields, press ENTER here...")
				input("Press Enter to continue...")

			time.sleep(10)
			
			# Handle the agreement checkbox and initial Sign In button if present
			try:
				# Look for the agreement checkbox
				checkboxes = driver.find_elements(By.CSS_SELECTOR, "input[type='checkbox']")
				for cb in checkboxes:
					# Check if the checkbox is near terms of use text
					parent_text = cb.find_element(By.XPATH, "..").get_attribute("innerText")
					if "I agree" in parent_text or "Terms of Use" in parent_text:
						if not cb.is_selected():
							driver.execute_script("arguments[0].click();", cb)
							log.info("Clicked terms agreement checkbox.")
						break
				
				# Look for the Sign In button that proceeds to SSO
				sign_in_buttons = driver.find_elements(By.CSS_SELECTOR, "a[href*='sign-in'], button")
				for btn in sign_in_buttons:
					if "Sign In" in btn.get_attribute("innerText") or "Sign in" in btn.get_attribute("innerText"):
						driver.execute_script("arguments[0].click();", btn)
						log.info("Clicked initial Sign In button.")
						time.sleep(10)
						break
			except Exception as e:
				log.debug(f"Agreement step skipped or failed: {e}")

			try:
				# Check if we are at the SecurityScorecard login page
				email_input = WebDriverWait(driver, 20).until(
					EC.presence_of_element_located((By.CSS_SELECTOR, "input[type='email'], input[name='email'], input[name='username']"))
				)
				email_input.send_keys(username)
				password_input = driver.find_element(By.CSS_SELECTOR, "input[type='password']")
				password_input.send_keys(password)
				time.sleep(1)
				login_button = driver.find_element(By.CSS_SELECTOR, "button[type='submit'], .btn-primary, button.login-button")
				login_button.click()
				
				# Wait for redirect back to cvedetails
				log.info("Waiting for login to complete and redirect...")
				for _ in range(12):
					time.sleep(5)
					if "cvedetails.com" in driver.current_url and ("Sign Out" in driver.page_source or "My Account" in driver.page_source):
						log.info("Login successful!")
						self.is_logged_in = True
						return
				
				log.warning("Login redirect timed out. Checking current state...")
			except Exception as e:
				log.error(f"Failed during automated credential entry: {e}")
			
			# Semi-automated fallback
			if not self.is_logged_in:
				log.warning("PLEASE MANUALLY LOGIN OR SOLVE CHALLENGES IN THE BROWSER WINDOW.")
				log.warning("Once you are logged in and see the 'Sign Out' button, press ENTER here to continue...")
				input("Press Enter to continue...")
				if "Sign Out" in driver.page_source or "My Account" in driver.page_source:
					self.is_logged_in = True
			
		except Exception as e:
			log.error(f"An error occurred during automated login: {e}")

	def download_page(self, url: str, params: Optional[dict] = None) -> Optional[requests.Response]:
		""" Downloads a web page using the automated browser. """

		if "cvedetails.com" not in url:
			try:
				return self.session.get(url, params=params, timeout=(self.connect_timeout, self.read_timeout))
			except Exception as e:
				log.error(f"Failed to download non-CVE page {url}: {e}")
				return None

		driver = self._get_driver()
		
		if params:
			from urllib.parse import urlencode
			url = f"{url}?{urlencode(params)}"

		log.info(f"Downloading: {url}")
		
		try:
			driver.get(url)
			time.sleep(5) 
			
			# If challenge detected, wait longer for cookies to kick in
			if "Attention Required! | Cloudflare" in driver.title or "Just a moment..." in driver.title:
				log.warning("Cloudflare challenge detected! Please solve it in the browser window.")
				log.warning("Waiting up to 120 seconds for manual interaction...")
				for _ in range(24): # Increased from 12 to 24 (120 seconds)
					time.sleep(5)
					if "Attention Required!" not in driver.title and "Just a moment..." not in driver.title:
						log.info("Cloudflare challenge bypassed successfully.")
						break
				else:
					log.error("Cloudflare challenge persistence. Manual interaction or better cookies required.")
					return None
			
			response = requests.Response()
			response.status_code = 200
			response._content = driver.page_source.encode('utf-8')
			response.url = driver.current_url
			
			return response
		except Exception as e:
			log.error(f"Failed to download page: {e}")
			return None

	def __del__(self):
		if self._driver:
			try:
				self._driver.quit()
			except:
				pass

####################################################################################################

class ScrapingRegex():
	""" Represents various constants used to parse key information from any relevant websites. """

	PAGE_TITLE: Pattern = re.compile(r'Go to page \d+', re.IGNORECASE)
	CVE: Pattern = re.compile(r'(CVE-\d+-\d+)', re.IGNORECASE)

	# BUG TRACKERS
	BUGZILLA_URL: Pattern = re.compile(r'https?://.*bugzilla.*', re.IGNORECASE)

	"""
	Examples:
	- Mozilla: https://bugzilla.mozilla.org/show_bug.cgi?id=1580506
	- Apache: https://bz.apache.org/bugzilla/show_bug.cgi?id=57531
	- Glibc: https://sourceware.org/bugzilla/show_bug.cgi?id=24114
	"""

	# SECURITY ADVISORIES
	MFSA_URL: Pattern = re.compile(r'https?://.*mozilla.*security.*mfsa.*', re.IGNORECASE)
	MFSA_ID: Pattern = re.compile(r'(mfsa\d+-\d+)', re.IGNORECASE)

	XSA_URL: Pattern = re.compile(r'https?://.*xen.*xsa.*advisory.*', re.IGNORECASE)
	XSA_ID: Pattern = re.compile(r'advisory-(\d+)', re.IGNORECASE)

	APACHE_SECURITY_URL: Pattern = re.compile(r'https?://.*apache.*security.*vulnerabilities.*', re.IGNORECASE)
	APACHE_SECURITY_ID: Pattern = re.compile(r'vulnerabilities_(\d+)', re.IGNORECASE)

	"""
	Examples:
	- Mozilla: https://www.mozilla.org/security/advisories/mfsa2019-31/
	- Mozilla: http://www.mozilla.org/security/announce/mfsa2005-58.html 
	- Xen: https://xenbits.xen.org/xsa/advisory-300.html
	- Apache: https://httpd.apache.org/security/vulnerabilities_24.html
	"""

	# VERSION CONTROL
	GIT_URL: Pattern = re.compile(r'https?://.*git.*commit.*', re.IGNORECASE)
	GITHUB_URL: Pattern = re.compile(r'https?://.*github\.com.*commit.*', re.IGNORECASE)
	SVN_URL: Pattern = re.compile(r'https?://.*svn.*rev.*', re.IGNORECASE)

	GIT_COMMIT_HASH_LENGTH = 40
	GIT_COMMIT_HASH: Pattern = re.compile(r'([A-Fa-f0-9]{40})', re.IGNORECASE)
	SVN_REVISION_NUMBER: Pattern = re.compile(r'(\d+)', re.IGNORECASE)

	DJANGO_GIT = re.compile(r'https://www\.djangoproject\.com/weblog/*', re.IGNORECASE)

	"""
	Examples:
	- Linux: https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/commit/?id=eff73de2b1600ad8230692f00bc0ab49b166512a
	- Glibc: https://sourceware.org/git/gitweb.cgi?p=glibc.git;a=commit;h=583dd860d5b833037175247230a328f0050dbfe9

	- Linux: https://github.com/torvalds/linux/commit/6ef36ab967c71690ebe7e5ef997a8be4da3bc844
	- Apache: https://github.com/apache/httpd/commit/e427c41257957b57036d5a549b260b6185d1dd73

	- Apache: http://svn.apache.org/viewcvs?rev=292949&view=rev

	- Django: https://www.djangoproject.com/weblog/2023/sep/04/security-releases/
	"""

	GIT_DIFF_LINE_NUMBERS: Pattern = re.compile(r'^@@ -(?P<from_begin>\d+)(,(?P<from_total>\d+))? \+(?P<to_begin>\d+)(,(?P<to_total>\d+))? @@.*')
	# Example: "@@ -424,20 +420,0 @@ MakeDialogText(nsIChannel* aChannel, nsIAuthInformation* aAuthInfo,"

####################################################################################################

if __name__ == '__main__':
	pass
