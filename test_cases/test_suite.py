import unittest
from selenium import webdriver
from selenium.webdriver.support.ui import WebDriverWait
from selenium.webdriver.support import expected_conditions
from selenium.common.exceptions import NoSuchElementException
from selenium.webdriver.support.ui import Select
from selenium.webdriver.common.by import By
import os
from dotenv import load_dotenv
import random
from webdriver_manager.chrome import ChromeDriverManager

APP_ROOT = os.path.join(os.path.dirname(__file__), '..')  # refers to application_top
dotenv_path = os.path.join(APP_ROOT, '.env')
load_dotenv(dotenv_path)

class HomeTest(unittest.TestCase):
    @classmethod
    def setUp(cls):
        options = webdriver.ChromeOptions()
        options.add_argument("start-maximized")
        # options.add_argument('headless')
        cls.driver = webdriver.Chrome(ChromeDriverManager().install(),options=options)
        cls.base_url = "http://127.0.0.1:5000/"

    def test_home(self):
        self.driver.get(self.base_url )
        WebDriverWait(self.driver, 15).until(expected_conditions.title_is('GeoRepair - About'))
        self.assertIn("Our App's Features", self.driver.page_source)
        
    def test_login(self):
        self.driver.get(self.base_url )
        loginButton = self.driver.find_element_by_id("login")
        loginButton.click()
        WebDriverWait(self.driver, 15).until(expected_conditions.title_is('GeoRepair - Login'))
        self.assertIn("Sign In", self.driver.page_source)
    

    @classmethod
    def tearDown(cls):
        cls.driver.quit()

class LoginTest(unittest.TestCase):
    @classmethod
    def setUp(cls):
        options = webdriver.ChromeOptions()
        options.add_argument("start-maximized")
        # options.add_argument('headless')
        cls.driver = webdriver.Chrome(ChromeDriverManager().install(),options=options)
        cls.base_url = "http://127.0.0.1:5000/login"
        cls.driver.get(cls.base_url)

    def test_blanksubmission(self):
        WebDriverWait(self.driver, 15).until(expected_conditions.title_is('GeoRepair - Login'))
        submitButton = self.driver.find_element_by_id("submit")
        submitButton.click()
        WebDriverWait(self.driver, 15).until(expected_conditions.title_is('GeoRepair - Login'))
        self.assertIn("Sign In", self.driver.page_source)
        
    def test_usernameonly(self):
        self.driver.get(self.base_url)
        userInput = self.driver.find_element_by_id("username")
        userInput.send_keys("joe")
        submitButton = self.driver.find_element_by_id("submit")
        submitButton.click()
        WebDriverWait(self.driver, 15).until(expected_conditions.title_is('GeoRepair - Login'))
        self.assertIn("Sign In", self.driver.page_source)
    
    def test_passwordonly(self):
        self.driver.get(self.base_url)
        pwInput = self.driver.find_element_by_id("password")
        pwInput.send_keys("11111")
        submitButton = self.driver.find_element_by_id("submit")
        submitButton.click()
        WebDriverWait(self.driver, 15).until(expected_conditions.title_is('GeoRepair - Login'))
        self.assertIn("Sign In", self.driver.page_source)

    def test_correctcredentials(self):
        self.driver.get(self.base_url)
        userInput = self.driver.find_element_by_id("username")
        userInput.send_keys(os.getenv("TESTUSER"))
        pwInput = self.driver.find_element_by_id("password")
        pwInput.send_keys(os.getenv("TESTPW"))
        submitButton = self.driver.find_element_by_id("submit")
        submitButton.click()
        WebDriverWait(self.driver, 15).until(expected_conditions.title_is('GeoRepair - Account'))

    @classmethod
    def tearDown(cls):
        cls.driver.quit()