from flask import Flask, request
import requests
import datetime
import logging
 
app = Flask(__name__)

# Server酱配置：

key = ''
 
def push_ftqq(content):
    resp = requests.post("https://sc.ftqq.com/{}.send".format(key),
                  data={"text": "xray vuln alarm", "desp": content})
    if resp.json()["errno"] != 0:
        raise ValueError("push ftqq failed, %s" % resp.text)
 
@app.route('/webhook', methods=['POST'])
def xray_webhook():
    vuln = request.json
    if "vuln_class" not in vuln:
        return "ok"
    content = """## 来货啦！！
 
url: {url}
 
插件: {plugin}
 
漏洞类型: {vuln_class}
 
发现时间: {create_time}
 
请及时查看和处理
""".format(url=vuln["target"]["url"], plugin=vuln["plugin"],
           vuln_class=vuln["vuln_class"] or "Default",
           create_time=str(datetime.datetime.fromtimestamp(vuln["create_time"] / 1000)))
    try:
        push_ftqq(content)
    except Exception as e:
        logging.exception(e)
    return 'ok'
 
 
if __name__ == '__main__':
	app.run(host='0.0.0.0')
