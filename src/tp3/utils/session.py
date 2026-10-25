import requests
from pwn import remote

from src.tp3.utils.captcha import Captcha
from tp3.utils.config import logger


class Session:
    """
    Class representing a session to solve a captcha and submit a flag.

    Attributes:
        url (str): The URL of the captcha.
        captcha_value (str): The value of the solved captcha.
        flag_value (str): The value of the flag to submit.
        valid_flag (str): The valid flag obtained after processing the response.
    """

    def __init__(self, url):
        """
        Initializes a new session with the given URL.

        Args:
            url (str): The URL of the captcha.
        """
        self.url = url
        self.captcha_value = ""
        self.flag_value = ""
        self.valid_flag = ""
        self.session = requests.Session()
        self.host = ""
        self.port = 0
        self.key = b""

    def prepare_request(self):
        """
        Prepares the request for sending by capturing and solving the captcha.
        """
        captcha = Captcha(self.session, self.url)
        captcha.capture()
        captcha.solve()

        self.captcha_value = captcha.get_value()
        print(f"captcha_value: {self.captcha_value}")

        print("sending request to get json")
        get_json = self.session.post(f"{self.url}/internal-panel", data={"captcha": self.captcha_value})

        data = get_json.json()

        self.flag_value = data.get("flag1", "")
        self.host = data.get("host", "")
        self.port = data.get("port", 0)
        self.key = data.get("key", "").encode()
        return self.flag_value

    def submit_request(self):
        """
        Sends the flag and captcha.
        """
        target = remote(self.host, self.port)
        target.recvuntil(b"token.\n")
        logger.info("reading whats in tcp connection: ")
        print(target.recvline())

    def process_response(self):
        """
        Processes the response.
        """

    def get_flag(self):
        """
        Returns the valid flag.

        Returns:
            str: The valid flag.
        """
        return self.valid_flag
