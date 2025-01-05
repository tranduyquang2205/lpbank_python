import hashlib
import math
import requests
import json
import time
from datetime import datetime
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
def solve_captcha_with_capsolver(base64_img_string, api_key="CAP-6C2884061D70C08F10D6257F2CA9518C"):
    """
    Solves a CAPTCHA using CapSolver.

    Args:
        base64_img_string (str): Base64-encoded CAPTCHA image string.
        api_key (str): Your CapSolver API key.

    Returns:
        str: Solved CAPTCHA text or error message.
    """
    url = "https://api.capsolver.com/createTask"
    payload = {
        "clientKey": api_key,
        "task": {
            "type": "ImageToTextTask",
            "body": base64_img_string,
        }
    }
    
    try:
        # Send request to CapSolver
        response = requests.post(url, json=payload)
        response_data = response.json()

        # Check for errors
        if response_data.get("errorId") != 0:
            return f"Error: {response_data.get('errorDescription')}"

        # Return solved CAPTCHA text
        return {
            "prediction":response_data.get("solution", {}).get("text", "")
        }

    except Exception as e:
        return f"Error solving CAPTCHA: {e}"
class LPBank:
    def __init__(self,username, password, account_number,proxy_list=None):
        self.transactions = []
        self.proxy_list = proxy_list
        self.proxy_cycle = cycle(self.proxy_list) if self.proxy_list else None
        self.url = {
            'url': 'https://ebanking.lpbank.com.vn/transaction-service/rest/web/request/',
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
        self.session_id = ""
        self.user_data = {}
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
            'is_login': self.is_login,
            'session_id': self.session_id,
            'user_data': self.user_data
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
            self.session_id = data['session_id']
            self.user_data = data['user_data']

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
        url_1 = 'https://captcha1.pay2world.vip/lpbank'
        url_2 = 'https://captcha.pay2world.vip/lpbank'
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
        clientRequestId = str(math.floor(random.random() * time.time()))
        payload = {
            "clientHeader": {
                "language": "VN",
                "clientRequestId": clientRequestId,
                "deviceId": "WEBLV24H",
                "platform": "LV24HWEB",
                "clientAddress": "127.1.1.1",
                "function": "genCaptcha"
            },
            "body": {
                "header": {
                "platform": "LV24HWEB",
                "clientRequestId": clientRequestId,
                "clientTime": datetime.now().strftime("%Y%m%d%H%M%S.%f")[:-3],
                "zonedClientTime": str(int(time.time() * 1000)),
                "channelCode": "WEBVIVIET",
                "deviceId": "WEBLV24H",
                "ip": "127.1.1.1",
                "makerId": "LV24HWEB",
                "language": "VN"
                }
            }
        }
        response = self.base_request_post(payload)
        if response and 'body' in response and 'base64' in response['body']:
            return response['body']['base64'],response['body']['captchaId']
        return response
    
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
    def base_request_get(self):
        headers = {
        'Accept': 'application/json, text/plain, */*',
        'Accept-Language': 'en-US,en;q=0.9',
        'Access-Control-Allow-Origin': '*',
        'Connection': 'keep-alive',
        'Content-Type': 'application/json',
        'Origin': 'https://ebanking.lpbank.com.vn',
        'Referer': 'https://ebanking.lpbank.com.vn/nhs-khcn',
        'Sec-Fetch-Dest': 'empty',
        'Sec-Fetch-Mode': 'cors',
        'Sec-Fetch-Site': 'same-origin',
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36 Edg/131.0.0.0',
        'sec-ch-ua': '"Microsoft Edge";v="131", "Chromium";v="131", "Not_A Brand";v="24"',
        'sec-ch-ua-mobile': '?0',
        'sec-ch-ua-platform': '"Windows"'
        }
        
        try:
            response = self.session.get(self.url['url'], headers=headers,proxies=self.proxies)
        except Exception as e:
            print('reason change proxy',e)
            self.change_proxy()
            return None
        return response
    def base_request_post(self,payload):
        headers = {
        'Accept': 'application/json, text/plain, */*',
        'Accept-Language': 'en-US,en;q=0.9',
        'Access-Control-Allow-Origin': '*',
        'Connection': 'keep-alive',
        'Content-Type': 'application/json',
        'Origin': 'https://ebanking.lpbank.com.vn',
        'Referer': 'https://ebanking.lpbank.com.vn/nhs-khcn',
        'Sec-Fetch-Dest': 'empty',
        'Sec-Fetch-Mode': 'cors',
        'Sec-Fetch-Site': 'same-origin',
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36 Edg/131.0.0.0',
        'sec-ch-ua': '"Microsoft Edge";v="131", "Chromium";v="131", "Not_A Brand";v="24"',
        'sec-ch-ua-mobile': '?0',
        'sec-ch-ua-platform': '"Windows"'
        }
        if self.session_id:
            headers['Authorization'] = 'Bearer ' + self.session_id
        
        try:
            response = self.session.post(self.url['url'], headers=headers,data=json.dumps(payload),proxies=self.proxies)
            response = response.json()
        except Exception as e:
            print('reason change proxy',e)
            self.change_proxy()
            return None
        return response
    def login(self,relogin=False):
        if not relogin:
            balance_response = self.get_balance(self.account_number)
            if balance_response['code'] != 500:
                return balance_response
        self.session = requests.Session()
        base64_captcha_img,captchaId = self.getCaptcha()
        result = self.createTaskCaptcha(base64_captcha_img)
        # result = solve_captcha_with_capsolver(base64_captcha_img)
        if 'prediction' in result and result['prediction']:
            captchaText = result['prediction']
        else:
            return {'code':500,"success": False, "msg": "Error solve captcha", "data": result}

        clientRequestId = str(math.floor(random.random() * time.time()))
        payload = {
            "clientHeader": {
                "language": "VN",
                "clientRequestId": clientRequestId,
                "deviceId": "WEBLV24H",
                "platform": "LV24HWEB",
                "clientAddress": "127.1.1.1",
                "function": "secureLogin"
            },
            "body": {
                "header": {
                "platform": "LV24HWEB",
                "clientRequestId": clientRequestId,
                "clientTime": datetime.now().strftime("%Y%m%d%H%M%S.%f")[:-3],
                "zonedClientTime": str(int(time.time() * 1000)),
                "channelCode": "WEBVIVIET",
                "deviceId": "WEBLV24H",
                "ip": "127.1.1.1",
                "makerId": "LV24HWEB",
                "language": "VN",
                "userName": self.username,
                "authorizedMode": 0,
                "checkerMode": 0,
                "categoryCode": "WEB_MENU"
                },
                "webStatus": "1",
                "userPwd": hashlib.sha256(self.password.encode('utf-8')).hexdigest(),
                "captcha": captchaText,
                "captchaId": captchaId
            }
        }
        response = self.base_request_post(payload)
        if response and 'body' in response and 'resultCode' in response['body'] and response['body']['resultCode'] == "0":
            self.session_id = response['body']['session']['sessionId']
            self.user_data = response['body']['user']
            self.time_login = time.time()
            self.is_login = True
            self.save_data()
            return {'code':200,"success": True, "msg": "Login success", "session_id": self.session_id}
        elif response and 'body' in response and 'resultCode' in response['body'] and response['body']['resultCode'] == "ESM-1003":
            return {
                "success": False,
                "code": 404,
                "message": "Invalid username not found"
            }
        elif response and 'body' in response and 'resultCode' in response['body'] and response['body']['resultCode'] == "ESM-1004":
            return {
                "success": False,
                "code": 444,
                "message": "Invalid username/password!"
            }
        elif response and 'body' in response and 'resultCode' in response['body'] and 'VERIFY' in response['body']['resultCode']:
            return {
                "success": False,
                "code": 449,
                "message": "Blocked account!"
            }
        else:
            return {'code':500,"success": False, "msg": "Login fail", "data": response}

                
        return None

    def get_balance(self,account_number,retry=False):
        print('get_balance')
        if not self.is_login or time.time() - self.time_login > 900 or 'userId' not in self.user_data:
            self.is_login = True
            self.save_data()
            login = self.login(relogin=True)
            return login
        clientRequestId = str(math.floor(random.random() * time.time()))
        payload = {
            "clientHeader": {
                "language": "VN",
                "clientRequestId": clientRequestId,
                "deviceId": "WEBLV24H",
                "platform": "LV24HWEB",
                "clientAddress": "127.1.1.1",
                "function": "getListSourceAccountLink"
            },
            "body": {
                "header": {
                "platform": "LV24HWEB",
                "clientRequestId": clientRequestId,
                "clientTime": datetime.now().strftime("%Y%m%d%H%M%S.%f")[:-3],
                "zonedClientTime": str(int(time.time() * 1000)),
                "channelCode": "WEBVIVIET",
                "deviceId": "WEBLV24H",
                "ip": "127.1.1.1",
                "makerId": "LV24HWEB",
                "language": "VN",
                "authorizedMode": 0,
                "checkerMode": 0,
                "sessionId": self.session_id,
                "userId": self.user_data['userId'],
                "custId": self.user_data['custId'],
                "custNo": self.user_data['custNo'],
                "categoryCode": "D_TRANSFER",
                "userName": self.username
                }
            }
            }
        response = self.base_request_post(payload)
        if response and 'body' in response and 'resultCode' in response['body'] and response['body']['resultCode'] == "0":
            for account in response['body']['sourceAccountList']:
                if account.get('sourceObjectNumber') == account_number:
                    return {'code':200,'success': True, 'message': 'Thành công',
                                    'data':{
                                        'account_number':account_number,
                                        'balance':int(account.get('availableBalance'))
                            }}
            return {'code':404,'success': False, 'message': 'account_number not found!'} 
        else:
            # with open("home.html", "w", encoding="utf-8") as file:
            #     file.write(response.text)
            self.is_login = False
            self.save_data()
            if not retry:
                return self.get_balance(account_number,retry=True)
            return {'code':500 ,'success': False, 'message': 'Unknown Error!','data':response} 
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
    def get_transactions_by_page(self,page,limit,total_page,account_number,from_date,to_date):
        clientRequestId = str(math.floor(random.random() * time.time()))
        payload = {
            "clientHeader": {
                "language": "VN",
                "clientRequestId": clientRequestId,
                "deviceId": "WEBLV24H",
                "platform": "LV24HWEB",
                "clientAddress": "127.1.1.1",
                "function": "getTransactionHistoryAllSource"
            },
            "body": {
                "header": {
                "platform": "LV24HWEB",
                "clientRequestId": clientRequestId,
                "clientTime": datetime.now().strftime("%Y%m%d%H%M%S.%f")[:-3],
                "zonedClientTime": str(int(time.time() * 1000)),
                "channelCode": "WEBVIVIET",
                "deviceId": "WEBLV24H",
                "ip": "127.1.1.1",
                "makerId": "LV24HWEB",
                "language": "vi",
                "userName": self.username,
                "sessionId": self.session_id,
                "providerCode": "",
                "sourceType": "COREBANK",
                "sourceId": "",
                "sourceValue": "",
                "userId": self.user_data['userId'],
                "custId": self.user_data['custId'],
                "custNo": self.user_data['custNo']
                },
                "rowNumber": "10",
                "fromDate": from_date,
                "toDate": to_date,
                "transferType": "ALL",
                "pageIndex": int(page),
                "accountNo": account_number
            }
            }
        response = self.base_request_post(payload)
        transaction_history =  response['body']['transactionHistories']
        if page*10 < limit and page < int(total_page):
            if transaction_history:
                self.transactions += transaction_history
            page=page+1
        
            return self.get_transactions_by_page(page,limit,total_page,account_number,from_date,to_date)
        else:
            if transaction_history:
                self.transactions += transaction_history[:limit - (page-1)*10]
        return True
    
    def get_transactions(self,account_number,from_date,to_date,limit,retry=False):
        self.transactions = []
        if not self.is_login or time.time() - self.time_login > 900 or 'userId' not in self.user_data:
            self.is_login = True
            self.save_data()
            login = self.login(relogin=True)
            if not login['success']:
                return login
        clientRequestId = str(math.floor(random.random() * time.time()))
        payload = {
            "clientHeader": {
                "language": "VN",
                "clientRequestId": clientRequestId,
                "deviceId": "WEBLV24H",
                "platform": "LV24HWEB",
                "clientAddress": "127.1.1.1",
                "function": "getTransactionHistoryAllSource"
            },
            "body": {
                "header": {
                "platform": "LV24HWEB",
                "clientRequestId": clientRequestId,
                "clientTime": datetime.now().strftime("%Y%m%d%H%M%S.%f")[:-3],
                "zonedClientTime": str(int(time.time() * 1000)),
                "channelCode": "WEBVIVIET",
                "deviceId": "WEBLV24H",
                "ip": "127.1.1.1",
                "makerId": "LV24HWEB",
                "language": "vi",
                "userName": "0764237727",
                "sessionId": self.session_id,
                "providerCode": "",
                "sourceType": "COREBANK",
                "sourceId": "",
                "sourceValue": "",
                "userId": self.user_data['userId'],
                "custId": self.user_data['custId'],
                "custNo": self.user_data['custNo']
                },
                "rowNumber": "10",
                "fromDate": from_date,
                "toDate": to_date,
                "transferType": "ALL",
                "pageIndex": 1,
                "accountNo": account_number
            }
            }
        response = self.base_request_post(payload)
            
        if response and 'body' in response and 'resultCode' in response['body'] and response['body']['resultCode'] == "0":

            total_transactions  = response['body']['totalTransaction']

            total_page = math.ceil(int(total_transactions)/10)
            transactions =  response['body']['transactionHistories']
            
            if transactions:
                self.transactions = transactions
                if limit < 10:
                    self.transactions = self.transactions[:limit]
                if limit > 10 and int(total_transactions) > 10:
                    self.get_transactions_by_page(2,limit,total_page,account_number,from_date,to_date)
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
        


