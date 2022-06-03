import time
import hmac
import hashlib
import base64
import urllib.parse
import requests
import json
import sys
import os
from string import Template


sys.path.append(os.path.realpath("framework"))

BOT_SECRET = os.getenv("BOT_SECRET")
BOT_ACCESS_TOKEN = os.getenv("BOT_ACCESS_TOKEN")


SEND_CONTENT_TEMPLATE = """**nydus-bot**  
${content}"""


class Bot:
    def __init__(self):
        if BOT_SECRET is None or BOT_ACCESS_TOKEN is None:
            raise ValueError

        timestamp = str(round(time.time() * 1000))
        secret_enc = BOT_SECRET.encode("utf-8")
        string_to_sign = "{}\n{}".format(timestamp, BOT_SECRET)
        string_to_sign_enc = string_to_sign.encode("utf-8")
        hmac_code = hmac.new(
            secret_enc, string_to_sign_enc, digestmod=hashlib.sha256
        ).digest()
        sign = urllib.parse.quote_plus(base64.b64encode(hmac_code))
        self.url = f"https://oapi.dingtalk.com/robot/send?access_token={BOT_ACCESS_TOKEN}&sign={sign}&timestamp={timestamp}"

    def send(self, content: str):
        c = Template(SEND_CONTENT_TEMPLATE).substitute(content=content)
        d = {
            "msgtype": "markdown",
            "markdown": {"title": "Nydus-bot", "text": c},
        }

        ret = requests.post(
            self.url, headers={"Content-Type": "application/json"}, data=json.dumps(d)
        )

        print(ret.__dict__)


if __name__ == "__main__":
    bot = Bot()
    bot.send(sys.argv[1])
