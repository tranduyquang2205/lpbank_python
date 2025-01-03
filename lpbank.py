import hashlib
import math
import requests
import json
import time
import datetime
from requests.cookies import RequestsCookieJar
import base64
import re
import urllib.parse
from bs4 import BeautifulSoup
import os 
from Cryptodome.PublicKey import RSA
from Cryptodome.Cipher import PKCS1_v1_5
from base64 import b64encode
from itertools import cycle
import random

class LPBank:
    def __init__(self,username, password, account_number,proxy_list=None):
        self.transactions = []
        self.proxy_list = proxy_list
        self.proxy_cycle = cycle(self.proxy_list) if self.proxy_list else None
        self.url = {
            'login': 'https://ebanking.lpbank.com.vn/nhs-khcn/login',
            'account_list':'https://ebanking.lpbank.com.vn/dashboard/list_account',
            'captcha': 'https://ebanking.lpbank.com.vn/captcha',
            'transactions_base': 'https://ebanking.lpbank.com.vn/dashboard/transaction_history',
            'transactions': lambda account_number,from_date,to_date : f'https://ebanking.lpbank.com.vn/myaccount/pay/statament/?src={account_number}&fromDate={urllib.parse.quote(from_date)}&endDate={urllib.parse.quote(to_date)}&timeStyle=A',
            'transactions_limit': lambda size,page : f'https://ebanking.lpbank.com.vn/myaccount/pay/paging?size={int(size)}&page={int(page)}'

        }
        if self.proxy_list:
            self.proxy_info = random.choice(self.proxy_list)
            proxy_host, proxy_port, username_proxy, password_proxy = self.proxy_info.split(':')
            self.proxies = {
                'http': f'http://{username_proxy}:{password_proxy}@{proxy_host}:{proxy_port}',
                'https': f'http://{username_proxy}:{password_proxy}@{proxy_host}:{proxy_port}'
            }
        else:
            self.proxies = None
        self.file = f"db/users/{account_number}.json"
        self.cookies_file = f"db/cookies/{account_number}.json"
        self.cookies = RequestsCookieJar()
        self.session = requests.Session()
        self.load_cookies()
        self.accounts_list = {}
        
        self.username = username
        self.password = password
        self.account_number = account_number
        if not os.path.exists(self.file) or os.path.getsize(self.file) == 0:
            self.username = username
            self.password = password
            self.account_number = account_number
            self.is_login = False
            self.time_login = time.time()
            self.save_data()
        else:
            self.parse_data()
            self.username = username
            self.password = password
            self.account_number = account_number
            self.save_data()
    def save_data(self):
        data = {
            'username': self.username,
            'password': self.password,
            'account_number': self.account_number,
            'time_login': self.time_login,
            'is_login': self.is_login
        }
        with open(f"db/users/{self.account_number}.json", 'w') as file:
            json.dump(data, file)
    def parse_data(self):
        with open(f"db/users/{self.account_number}.json", 'r') as file:
            data = json.load(file)
            self.username = data['username']
            self.password = data['password']
            self.account_number = data['account_number']
            self.time_login = data['time_login']
            self.is_login = data['is_login']

    def save_cookies(self,cookie_jar):
        with open(self.cookies_file, 'w') as f:
            json.dump(cookie_jar.get_dict(), f)
    def load_cookies(self):
        try:
            with open(self.cookies_file, 'r') as f:
                cookies = json.load(f)
                self.session.cookies.update(cookies)
                return
        except (FileNotFoundError, json.decoder.JSONDecodeError):
            return requests.cookies.RequestsCookieJar()
    def hash_password(self,password: str) -> str:
        """
        Hashes a password using SHA-256.

        :param password: The plain text password.
        :return: The hashed password as a hexadecimal string.
        """
        # Encode the password and hash it using SHA-256
        hashed = hashlib.sha256(password.encode('utf-8')).hexdigest()
        return hashed
    def createTaskCaptcha(self, base64_img):
        url_1 = 'https://captcha.pay2world.vip/lpbank'
        url_2 = 'https://captcha1.pay2world.vip/lpbank'
        url_3 = 'https://captcha2.pay2world.vip/lpbank'
        
        payload = json.dumps({
        "image_base64": base64_img
        })
        headers = {
        'Content-Type': 'application/json'
        }
        
        for _url in [url_1, url_2, url_3]:
            try:
                response = requests.request("POST", _url, headers=headers, data=payload, timeout=10)
                if response.status_code in [404, 502]:
                    continue
                return json.loads(response.text)
            except:
                continue
        return {}

    def getCaptcha(self):
        response = self.base_request_get(self.url['captcha'])
        return response.text
    
    def change_proxy(self):
            print('change_proxy')
            if not self.proxy_cycle:
                print("No proxies available. Setting self.proxies to None.")
                self.proxies = None
                return
            self.proxy_info = next(self.proxy_cycle)  # Lấy proxy kế tiếp từ vòng lặp
            proxy_host, proxy_port, username_proxy, password_proxy = self.proxy_info.split(':')
            self.proxies = {
                'http': f'http://{username_proxy}:{password_proxy}@{proxy_host}:{proxy_port}',
                'https': f'http://{username_proxy}:{password_proxy}@{proxy_host}:{proxy_port}'
            }
            print(f"New proxy: {self.proxies}")      

    def extract_text_from_td(self,td_string):
        return re.sub(r"<[^>]*>", "", td_string).strip()
    def extract_error_message(self,html_content):
        pattern = r'<p id="alert" class="login-error">(.*)</p>'
        match = re.search(pattern, html_content)
        return match.group(1) if match else None
    
    def extract_csrf(self,html_content):
        pattern = r'<input type="hidden" name="_csrf" value="(.*)"/>'
        match = re.search(pattern, html_content)
        return match.group(1) if match else None
    def extract_total_page(self,html_content):
        pattern = r' / <span>([0-9]+)</span>'
        match = re.search(pattern, html_content)
        return match.group(1) if match else None
    def extract_accounts(self,html):
        """
        Extracts account numbers and balances from the given HTML.

        Args:
            html (str): The HTML string to parse.

        Returns:
            list: A list of dictionaries with 'account_number' and 'balance'.
        """
        soup = BeautifulSoup(html, 'html.parser')
        accounts = []

        # Locate all rows within the table body
        rows = soup.select('table tbody tr')

        for row in rows:
            account_number_tag = row.find('a', href=True)
            balance_tag = row.find('img', {'data-balance': True})

            if account_number_tag and balance_tag:
                account_number = account_number_tag.text.strip()
                balance = balance_tag['data-balance'].strip()

                accounts.append({
                    'account_number': account_number,
                    'balance': balance
                })

        return accounts
    def extract_transactions(self,html):
        """
        Extracts transaction records from the given HTML.

        Args:
            html (str): The HTML string to parse.

        Returns:
            list: A list of dictionaries with transaction details: 'date', 'amount', 'current_balance', and 'description'.
        """
        soup = BeautifulSoup(html, 'html.parser')
        transactions = []

        # Locate all rows within the table body
        rows = soup.select('table tbody tr')

        for row in rows:
            cells = row.find_all('td')

            if len(cells) == 4:
                date = cells[0].text.strip()
                amount_text = cells[1].text.strip()
                current_balance = cells[2].text.strip()
                description = cells[3].text.strip()

                # Convert amount to integer, handling '+' and '-' signs directly
                amount = int(amount_text.replace(',', '').replace('+', ''))

                transactions.append({
                    'date': date,
                    'amount': amount,
                    'current_balance': current_balance,
                    'description': description
                })

        return transactions
    def extract_balance_from_td(self,td_string):
        balance_pattern = r"(\d{1,3}(?:,\d{3})*\.\d{2})"
        balances = re.findall(balance_pattern, td_string)
        formatted_balances = [balance.split('.')[0].replace(',', '') for balance in balances]
        return formatted_balances[0]
    def extract_account_number(self,html_content):
        soup = BeautifulSoup(html_content, 'html.parser')
        ac_element = soup.find('span', class_='me-2')
        if ac_element:
            ac_text = ac_element.get_text(strip=True)
        return (ac_text.strip()) if ac_element else None
    def extract_balance(self,html_content):
        soup = BeautifulSoup(html_content, 'html.parser')
        ac_element = soup.find('span', class_='me-2 text-blue')
        if ac_element:
            ac_text = ac_element.get_text(strip=True)
        return float(ac_text.strip().replace('.', '').replace(',','.')) if ac_element else None
    def extract_transaction_history(self,html: str):
        """
        Extracts transaction history from the provided HTML string.

        :param html: A string containing the HTML.
        :return: A pandas DataFrame containing the extracted transaction history, or an empty DataFrame if an error occurs.
        """
        try:
            # Parse the HTML using BeautifulSoup
            soup = BeautifulSoup(html, 'html.parser')
            
            # Locate the table body
            table_body = soup.find('tbody')
            if not table_body:
                return []  # Return an empty DataFrame

            # Extract rows
            rows = table_body.find_all('tr')
            transactions = []
            
            for row in rows:
                cols = row.find_all('td')
                if len(cols) == 4:
                    amount = cols[1].get_text(strip=True).replace(',', '')
                    current_balance = cols[2].get_text(strip=True).replace(',', '')
                    transaction = {
                        'date_time': cols[0].get_text(strip=True),
                        'amount': int(amount) if amount.startswith('+') else -int(amount[1:]),
                        'current_balance': int(current_balance),
                        'remark': cols[3].get_text(strip=True),
                    }
                    transactions.append(transaction)
            
            # Convert to pandas DataFrame
            return transactions
        
        except Exception as e:
            # Log the error (optional)
            print(f"Error occurred: {e}")
            return []
    def base_request_get(self,url):
        headers = {
        'Accept': 'text/html, */*; q=0.01',
        'Accept-Language': 'en-US,en;q=0.9',
        'Connection': 'keep-alive',
        'Referer': 'https://ebanking.lpbank.com.vn/nhs-khcn/login',
        'Sec-Fetch-Dest': 'empty',
        'Sec-Fetch-Mode': 'cors',
        'Sec-Fetch-Site': 'same-origin',
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36 Edg/131.0.0.0',
        'sec-ch-ua': '"Microsoft Edge";v="131", "Chromium";v="131", "Not_A Brand";v="24"',
        'sec-ch-ua-mobile': '?0',
        'sec-ch-ua-platform': '"Windows"'
        }
        
        try:
            response = self.session.get(url, headers=headers,proxies=self.proxies)
        except Exception as e:
            print('reason change proxy',e)
            self.change_proxy()
            return None
        return response
    def login(self,relogin=False):
        if not relogin:
            balance_response = self.get_balance(self.account_number)
            print(balance_response)
            if balance_response['code'] != 500:
                return balance_response
        self.session = requests.Session()
        base64_captcha_img = self.getCaptcha()
        result = self.createTaskCaptcha(base64_captcha_img)
        print(result)
        if 'prediction' in result and result['prediction']:
            captchaText = result['prediction']
        else:
            return {'code':500,"success": False, "msg": "Error solve captcha", "data": result}


        response = self.base_request_get(self.url['login'])
        _csrf_token = self.extract_csrf(response.text)

        payload = {
            '_csrf': _csrf_token,
            'username': (self.username),
            'password': '***********',
            'hash_password': self.hash_password(self.password),
            'captcha': captchaText,
            "${_csrf.parameterName}":"${_csrf.token}"
        }
        encoded_payload = urllib.parse.urlencode(payload)
        headers = {
        'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7',
        'Accept-Language': 'en-US,en;q=0.9',
        'Cache-Control': 'max-age=0',
        'Connection': 'keep-alive',
        'Content-Type': 'application/x-www-form-urlencoded',
        'Origin': 'https://ebanking.lpbank.com.vn',
        'Referer': 'https://ebanking.lpbank.com.vn/nhs-khcn/login',
        'Sec-Fetch-Dest': 'document',
        'Sec-Fetch-Mode': 'navigate',
        'Sec-Fetch-Site': 'same-origin',
        'Sec-Fetch-User': '?1',
        'Upgrade-Insecure-Requests': '1',
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36 Edg/131.0.0.0',
        'sec-ch-ua': '"Microsoft Edge";v="131", "Chromium";v="131", "Not_A Brand";v="24"',
        'sec-ch-ua-mobile': '?0',
        'sec-ch-ua-platform': '"Windows"'
        }

        try:
            response = self.session.post(self.url['login'], headers=headers, data=encoded_payload,allow_redirects=True,proxies=self.proxies)
        except Exception as e:
            print('reason change proxy',e)
            self.change_proxy()
            return None
        # with open("login.html", "w", encoding="utf-8") as file:
        #     file.write(response.text)
        if 'https://ebanking.lpbank.com.vn/dashboard' in response.url:
            self.save_cookies(self.session.cookies)
            self.is_login = True
            self.time_login = time.time()
            self.save_data()
            return {
                    "success": True,
                    "code": 200,
                    "message": "Login Successfully!",
            }
        else:
            error_message = self.extract_error_message(response.text)
            print(error_message)
            if error_message:
                if 'vô hiệu hóa' in error_message or 'bị khóa' in error_message:
                    return  {
                            "success": False,
                            "code": 449,
                            "message": "Blocked account!",
                            "details": error_message
                        }
                elif 'Thông tin đăng nhập của quý khách không đúng' in error_message:
                    return {
                            'success': False,
                            'message': 'Đăng nhập không thành công!',
                            'code': 444,
                            "details": error_message
                        }
                elif 'không đúng' in error_message:
                    return {
                            'success': False,
                            'message': 'Đăng nhập không thành công!',
                            'code': 444,
                            "details": error_message
                        }
                elif 'Thông tin đăng nhập' in error_message:
                    return {
                            'success': False,
                            'message': 'Đăng nhập không thành công!',
                            'code': 444,
                            "details": error_message
                        }
                elif 'Mã xác thực không đúng. Quý khách vui lòng nhập lại' in error_message:
                        return {
                            'success': False,
                            'message': 'Invalid captcha value!',
                            'code': 421,
                            "details": error_message
                        }
            else:
                return self.login(relogin=True)
                
        return None

    def get_balance(self,account_number,retry=False):
        print('get_balance')
        if not self.is_login:
            self.is_login = True
            self.save_data()
            login = self.login(relogin=True)
            return login
        response = self.base_request_get(self.url['account_list'])

        account_list = self.extract_accounts(response.text)
        if account_list:
            for account in account_list:
                if account.get('account_number') == account_number:
                    return {'code':200,'success': True, 'message': 'Thành công',
                                    'data':{
                                        'account_number':account_number,
                                        'balance':int(account.get('balance').replace(',',''))
                            }}
            return {'code':404,'success': False, 'message': 'account_number not found!'} 
        else:
            # with open("home.html", "w", encoding="utf-8") as file:
            #     file.write(response.text)
            self.is_login = False
            self.save_data()
            if not retry:
                return self.get_balance(account_number,retry=True)
            return {'code':500 ,'success': False, 'message': 'Unknown Error!','data':response.text} 
    def get_transactions_base(self):
        headers = {
        'Accept': '*/*',
        'Accept-Language': 'en-US,en;q=0.9',
        'Connection': 'keep-alive',
        'Referer': f'https://ebanking.lpbank.com.vn/myaccount/pay/{self.account_number}',
        'Sec-Fetch-Dest': 'empty',
        'Sec-Fetch-Mode': 'cors',
        'Sec-Fetch-Site': 'same-origin',
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36 Edg/131.0.0.0',
        'X-Requested-With': 'XMLHttpRequest',
        'sec-ch-ua': '"Microsoft Edge";v="131", "Chromium";v="131", "Not_A Brand";v="24"',
        'sec-ch-ua-mobile': '?0',
        'sec-ch-ua-platform': '"Windows"'
        }
        url = 'https://ebanking.lpbank.com.vn/myaccount/pay/paging?size=30'
        response = self.session.get(url, headers=headers,proxies=self.proxies)
        transaction_history = self.extract_transaction_history(response.text)
        self.transactions = transaction_history
        # with open(f"transaction_base.html", "w", encoding="utf-8") as file:
        #     file.write(response.text)
        return True
    def get_transactions_by_page(self,page,limit,total_page):
        headers = {
        'Accept': '*/*',
        'Accept-Language': 'en-US,en;q=0.9',
        'Connection': 'keep-alive',
        'Referer': f'https://ebanking.lpbank.com.vn/myaccount/pay/{self.account_number}',
        'Sec-Fetch-Dest': 'empty',
        'Sec-Fetch-Mode': 'cors',
        'Sec-Fetch-Site': 'same-origin',
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36 Edg/131.0.0.0',
        'X-Requested-With': 'XMLHttpRequest',
        'sec-ch-ua': '"Microsoft Edge";v="131", "Chromium";v="131", "Not_A Brand";v="24"',
        'sec-ch-ua-mobile': '?0',
        'sec-ch-ua-platform': '"Windows"'
        }
        url = (self.url['transactions_limit'](30,page))
        response = self.session.get(url, headers=headers,proxies=self.proxies)
        # with open(f"transaction_{page}.html", "w", encoding="utf-8") as file:
        #     file.write(response.text)
        transaction_history = self.extract_transaction_history(response.text)

        if page*30 < limit and page < int(total_page):
            if transaction_history:
                self.transactions += transaction_history
            page=page+1
        
            return self.get_transactions_by_page(page,limit,total_page)
        else:
            if transaction_history:
                self.transactions += transaction_history[:limit - (page-1)*30]
                # print(len(self.transactions),transaction_history[:limit - (page-1)*30])
        return True
    
    def get_transactions(self,account_number,from_date,to_date,limit,retry=False):
        self.transactions = []
        if not self.is_login:
            self.is_login = True
            self.save_data()
            login = self.login(relogin=True)
            if not login['success']:
                return login
        # response = self.base_request_get(self.url['transactions_base'])
        # with open("transaction0.html", "w", encoding="utf-8") as file:
        #     file.write(response.text)
        response = self.base_request_get(f'https://ebanking.lpbank.com.vn/myaccount/pay/{account_number}')
            
        # print(self.url['transactions'](account_number,from_date,to_date))
        headers = {
        'Accept': '*/*',
        'Accept-Language': 'en-US,en;q=0.9',
        'Connection': 'keep-alive',
        'Referer': f'https://ebanking.lpbank.com.vn/myaccount/pay/{account_number}',
        'Sec-Fetch-Dest': 'empty',
        'Sec-Fetch-Mode': 'cors',
        'Sec-Fetch-Site': 'same-origin',
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36 Edg/131.0.0.0',
        'X-Requested-With': 'XMLHttpRequest',
        'sec-ch-ua': '"Microsoft Edge";v="131", "Chromium";v="131", "Not_A Brand";v="24"',
        'sec-ch-ua-mobile': '?0',
        'sec-ch-ua-platform': '"Windows"'
        }
        
        url = (self.url['transactions'](account_number,from_date,to_date))
        # url = (self.url['transactions_limit'](30,1))
        response = self.session.get(url, headers=headers,proxies=self.proxies)
        
        # with open("transaction.html", "w", encoding="utf-8") as file:
        #     file.write(response.text)

        response = response.text

        total_page = self.extract_total_page(response)
        if total_page:
            total_page = math.ceil(int(total_page)*10/30)
        else:
            self.is_login = False
            self.save_data()
            if not retry:
                return self.get_transactions(account_number,from_date,to_date,limit,retry=True)
            return {'code':500 ,'success': False, 'message': 'Unknown Error!','data':1} 
        transactions =  self.extract_transaction_history(response)
        
        if transactions:
            self.transactions = transactions
            if limit < 10:
                self.transactions = self.transactions[:limit]
            if limit > 10:
                self.get_transactions_base()
                if limit < 30:
                    self.transactions = self.transactions[:limit]
            if limit > 30:
                self.get_transactions_by_page(2,limit,total_page)
            return {'code':200,'success': True, 'message': 'Thành công',
                    'data':{
                        'transactions':self.transactions,
            }}
        else:
            self.is_login = False
            self.save_data()
            if not retry:
                return self.get_transactions(account_number,from_date,to_date,limit,retry=True)
            return {'code':500 ,'success': False, 'message': 'Unknown Error!','data':1} 
        


