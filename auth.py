import requests
import json
import base64
import time

from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_v1_5
from pathlib import Path

class Session:
    BASE_URL = "https://org.app.fjnu.edu.cn/openplatform"
    HEADERS = {
        "user-agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36",
    }

    def __init__(self, app_name: str = None):
        """初始化会话状态"""
        self.req_session = requests.Session()
        self.req_session.headers.update(self.HEADERS)
        
        script_dir = Path(__file__).parent
        self.CONFIG_FILE = script_dir / 'config.json'
        
        # 登录流程的状态
        self.qrcode_uuid = ""      # 用于二维码登录的唯一标识
        self.public_key = ""       # RSA 公钥
        self.tokenKey = ""         # 类似于 session id 的关键令牌
        self.verifyToken = ""      # 用于身份验证的临时令牌
        
        # 用于二步验证的状态
        self.double_verify_number = "" # 需要进行二步验证的手机号
        self.account_for_2fa = ""      # 需要进行二步验证的账号
        
        self.app_id = ""
        self.redirect_uri = ""
        try:
            with open(self.CONFIG_FILE, 'r', encoding='utf-8') as f:
                configs = json.load(f)
                self.app_configs = configs
            config = {}
            if not app_name:
                # 输出所有可选配置项
                print("【当前支持的系统列表】")
                print(", ".join([i for i in self.app_configs]))
                app_name = input("请输入需要登录的系统: ")
            if app_name in self.app_configs:
                config = self.app_configs[app_name]
            else:
                raise ValueError(f"错误：提供的应用名称 '{app_name}' 不在预设配置中。")
            self._initialize_session(config)
        except FileNotFoundError:
            raise FileNotFoundError(f"错误：配置文件 '{self.CONFIG_FILE}' 未找到。请确保它与脚本在同一目录下。")
        except json.JSONDecodeError:
            raise ValueError(f"错误：配置文件 '{self.CONFIG_FILE}' 格式不正确，不是有效的JSON。")

    def _initialize_session(self, app_config: dict):
        # --- 访问OAuth接口，获取'cur_appId_'等应用上下文Cookie ---
        print("获取应用上下文中...")
        oauth_url = f"{self.BASE_URL}/oauth/authorize"
        oauth_params = {
            'appId': app_config['app_id'],
            'redirectUri': app_config['redirect_uri'],
            'responseType': app_config['response_type'],
            'scope': app_config['scope'],
            'state': app_config['state']
        }
        try:
            self.req_session.headers['Referer'] = self.BASE_URL 
            
            response_oauth = self.req_session.get(oauth_url, params=oauth_params, allow_redirects=True)
            response_oauth.raise_for_status()

        except requests.RequestException as e:
            print(f"获取应用上下文失败: {e}")
            raise

        # --- 步骤 2: 访问验证码接口，获取'SESSION' Cookie ---
        print("获取会话SESSION中...")
        jcaptcha_url = f"{self.BASE_URL}/g/admin/getJcaptchaCode"
        try:
            # 访问这个接口时，Referer应该是登录页
            self.req_session.headers['Referer'] = f"{self.BASE_URL}/login.html"
            response_jcaptcha = self.req_session.post(jcaptcha_url)
            response_jcaptcha.raise_for_status()

            if 'SESSION' not in self.req_session.cookies.get_dict():
                print("获取会话SESSION失败。")
                raise Exception("无法获取SESSION，请检查网络或目标网站状态。")
        except requests.RequestException as e:
            print(f"获取会话SESSION失败: {e}")
            raise
    
    @staticmethod
    def _get_timestamp() -> str:
        """获取当前时间的13位毫秒时间戳"""
        return str(int(time.time() * 1000))

    def _handle_response(self, response: requests.Response, description: str):
        """统一处理API响应和错误"""
        if response.status_code == 200:
            j = response.json()
            if j.get("code") == 0:
                # print(f"{description} 成功")
                return j.get("data")
            else:
                raise Exception(f"{description} 失败: {j.get('message', '未知错误')}")
        else:
            raise Exception(f"{description} 请求失败: HTTP {response.status_code}")

    # --- 二维码登录方法 ---
    def get_qrcode(self) -> bytes:
        """
        获取二维码
        :return: base64解码后的二维码图片字节
        """
        url = f"{self.BASE_URL}/g/qrcode/getQRCode"
        params = {"width": "215", "height": "215", "_": self._get_timestamp()}
        response = self.req_session.get(url, params=params)
        data = self._handle_response(response, "获取二维码")
        self.qrcode_uuid = data["token"]
        return base64.b64decode(data["baseCode"])

    def check_qrcode(self) -> int:
        """
        轮询检查二维码状态
        :return: 状态码 (0:过期, 1:待扫描, 2:已扫描, 3:已确认)
        """
        url = f"{self.BASE_URL}/g/qrcode/getQrCodeStatus"
        params = {"uuid": self.qrcode_uuid, "_": self._get_timestamp()}
        response = self.req_session.get(url, params=params)
        data = self._handle_response(response, "检查二维码状态")
        return data["qrcodeStatus"]

    def login_by_qrcode(self) -> bool:
        """
        使用已确认的二维码进行登录
        """
        url = f"{self.BASE_URL}/g/admin/login"
        payload = {"username": self.qrcode_uuid, "loginType": 3}
        response = self.req_session.post(url, json=payload)
        data = self._handle_response(response, "二维码登录")
        self.tokenKey = data["tokenKey"]
        self.verifyToken = data["verifyToken"]
        return True

    # --- 账号密码登录方法 ---
    def get_jcaptcha(self) -> bytes:
        """
        获取图形验证码
        :return: base64解码后的验证码图片字节
        """
        url = f"{self.BASE_URL}/g/admin/getJcaptchaCode"
        response = self.req_session.post(url)
        data = self._handle_response(response, "获取图形验证码")
        return base64.b64decode(data)

    def _get_public_key(self) -> str:
        """
        获取用于加密密码的RSA公钥
        """
        if self.public_key:
            return self.public_key
        url = f"{self.BASE_URL}/g/admin/getPublicKey"
        response = self.req_session.post(url)
        data = self._handle_response(response, "获取公钥")
        self.public_key = data
        return data

    def _encrypt_password(self, password: str) -> str:
        """
        使用公钥对密码进行RSA加密
        """
        public_key_str = self._get_public_key()
        key_der = base64.b64decode(public_key_str)
        key_pub = RSA.import_key(key_der)
        cipher_rsa = PKCS1_v1_5.new(key_pub)
        encrypted_password = cipher_rsa.encrypt(password.encode('utf-8'))
        return base64.b64encode(encrypted_password).decode('utf-8')

    def login_by_password(self, username: str, password: str, jcaptcha_code: str) -> bool:
        """
        通过账号密码登录
        :return: True表示登录成功或进入二步验证，False表示失败
        """
        url = f"{self.BASE_URL}/g/admin/login"
        encrypted_pwd = self._encrypt_password(password)
        
        payload = {
            "loginType": 1,
            "username": username,
            "pwd": encrypted_pwd,
            "jcaptchaCode": jcaptcha_code,
        }
        
        response = self.req_session.post(url, json=payload)
        data = self._handle_response(response, "账号密码登录")
        
        # 判断是否需要二步验证
        if data.get("doubleStatus") in ("1", 1):
            # print(f"账号需要二步验证，已向手机号 {data['mobile']} 发送验证码。")
            self.double_verify_number = data['mobile']
            self.account_for_2fa = username # 保存原始账号用于2FA登录
            return True # 进入2FA流程
        else:
            self.tokenKey = data["tokenKey"]
            self.verifyToken = data["verifyToken"]
            self.double_verify_number = "" # 清空2FA状态
            return True # 直接登录成功

    # --- 短信/二步验证方法 ---
    def send_sms_code(self, phone: str):
        """
        发送短信验证码
        """
        url = f"{self.BASE_URL}/g/admin/sendVeriCode"
        payload = {
            "veriType": "sms",
            "username": phone,
            "templeType": "smscode",
        }
        self._handle_response(self.req_session.post(url, json=payload), f"向{phone}发送短信")

    def login_by_sms(self, phone: str, code: str) -> bool:
        """
        通过短信验证码登录
        """
        url = f"{self.BASE_URL}/g/admin/login"
        payload = {
            "loginType": 2,
            "veriType": "sms",
            "username": int(phone),
            "captcha": int(code),
        }
        response = self.req_session.post(url, json=payload)
        data = self._handle_response(response, "短信登录")
        self.tokenKey = data["tokenKey"]
        self.verifyToken = data["verifyToken"]
        return True

    def login_by_2fa(self, code: str) -> bool:
        """
        执行二步验证登录
        """
        url = f"{self.BASE_URL}/g/admin/login"
        payload = {
            "loginType": 2,
            "veriType": "sms",
            "username": int(self.double_verify_number),
            "captcha": int(code),
            "doubleStatus": "1",
            "account": self.account_for_2fa, # 传入原始登录账号
        }
        response = self.req_session.post(url, json=payload)
        data = self._handle_response(response, "二步验证(2FA)")
        self.tokenKey = data["tokenKey"]
        self.verifyToken = data["verifyToken"]
        self.double_verify_number = "" # 清空2FA状态
        return True
    
    # --- 身份验证及跳转 ---
    def get_member_identities(self) -> list:
        """
        登录成功后，使用verifyToken获取用户可用的身份列表。
        
        :return: 一个包含身份信息的列表，例如 [{'sno': '123', 'name': '学生'}, ...]
        """
        if not self.verifyToken:
            raise Exception("用户未登录或登录会话已失效 (缺少verifyToken)。")

        url = f"{self.BASE_URL}/oauth/auth/getMemberIdentitys"
        params = {"verifyToken": self.verifyToken, "_": self._get_timestamp()}
        
        self.req_session.headers['Referer'] = f"{self.BASE_URL}/login.html"
        
        response = self.req_session.get(url, params=params)
        identities = self._handle_response(response, "获取用户身份")
        return identities

    def get_redirect_url(self, sno: str) -> str:
        """
        根据指定的身份sno，获取最终的应用重定向链接。
        
        :param sno: 从身份列表中选择的sno编号。
        :return: 最终的应用URL链接。
        """
        if not sno:
            raise ValueError("'sno' 不能为空。")

        url = f"{self.BASE_URL}/oauth/auth/getRedirectUrl"
        params = {"sno": sno, "_": self._get_timestamp()}
        
        self.req_session.headers['Referer'] = f"{self.BASE_URL}/login.html"

        response = self.req_session.get(url, params=params)
        redirect_url = self._handle_response(response, "获取重定向链接")
        return redirect_url

    def process_post_login(self) -> str:
        """
        获取身份并获取最终链接。
        """
        try:
            identities = self.get_member_identities()
            if not identities:
                print("未找到可用身份。")
                return

            chosen_sno = ""
            if len(identities) == 1: # 仅一个可用身份
                chosen_sno = identities[0].get('sno')
            else:
                try:
                    choice = int(input("请选择一个身份（输入序号）: ")) - 1
                    if 0 <= choice < len(identities):
                        chosen_sno = identities[choice].get('sno')
                    else:
                        print("无效选择。")
                        return
                except ValueError:
                    print("输入无效，请输入数字。")
                    return
            if chosen_sno:
                redirect_url = self.get_redirect_url(chosen_sno)
                return redirect_url
        except Exception as e:
            print(f"处理登录后流程时出错: {e}")

    def login(self) -> bool:
        login_type = input("请选择登录方式 (1: 二维码, 2: 账号密码, 其它任意值: 短信验证码): ")
            
        if login_type == '1': # 二维码登录
            qrcode_bytes = self.get_qrcode()
            with open("qrcode.png", "wb") as f: f.write(qrcode_bytes)
            print('登录二维码已保存至 qrcode.png！')
            
            for i in range(60):
                status = self.check_qrcode()
                if status == 0: print("二维码已过期，请重新获取。"); return False
                elif status == 1: print("等待扫描二维码...")
                elif status == 2: print("已扫描二维码，请确认登录...");
                elif status == 3:
                    print("已确认登录，正在登录...")
                    if self.login_by_qrcode():
                        print('登录成功！')
                        return True
                time.sleep(2)
            print('登录失败！')
            return False # 超时未确认登录
        elif login_type == '2': # 账号密码登录
            jcaptcha_bytes = self.get_jcaptcha()
            with open("jcaptcha.png", "wb") as f: f.write(jcaptcha_bytes)
            print('图形验证码已保存至 jcaptcha.png！')
            
            username = input("请输入账号: ")
            password = input("请输入密码: ")
            jcaptcha_code = input("请输入图形验证码: ")

            if self.login_by_password(username, password, jcaptcha_code):
                if self.double_verify_number: # 如果需要2FA
                    print(f"正在请求向手机 {self.double_verify_number} 发送验证码...")
                    self.send_sms_code(self.double_verify_number)
                    sms_code_2fa = input(f"请输入发送到 {self.double_verify_number} 的短信验证码: ")
                    if self.login_by_2fa(sms_code_2fa):
                        print('登录成功！')
                        return True
                else:
                    print(f"登录成功！")
                    return True
            print('登录失败！')
            return False # 登录失败
        else: # 短信登录
            phone = input("请输入手机号: ")
            self.send_sms_code(phone)
            sms_code = input(f"请输入发送到 {phone} 的短信验证码: ")
            if self.login_by_sms(phone, sms_code):
                print(f"登录成功！")
                return True
            print('登录失败！')
            return False # 登录失败

if __name__ == "__main__":
    session = Session(app_name=None)
    try:
        if session.login():
            print(session.process_post_login())
    except Exception as e:
        print(f"\n程序运行出错: {e}")