import sys
import subprocess
from concurrent.futures import ThreadPoolExecutor
from multiprocessing import Process
import simplejson




'''
程序流程：

1. URL list --> 1.rad 2.crawlgo --> 3. 爬虫子进程结束xray进程结束

'''

radPath = 'rad_windows_amd64.exe' # 路径自行配置
crawlergoPath = 'crawlergo.exe'
xrayPath = 'xray_windows_amd64.exe' # 路径自行配置
chrome_path = 'C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe' # chrome路径自行配置

list_url = []

def getScanTarget(filename):
    with open(filename,"r") as target:
        for line in target.readlines():
            target = line.strip()
            if "://" not in target:
                target = "http://{}".format(target)
            else:
                target = target
            list_url.append(target)
        #print(list_url)
        print("[+] ScanTarget Count is: " + str(len(set(list_url))))

def TypeScan(plugin):
    xray_cmd = [xrayPath,'webscan','--plugins',plugin,'--listen','127.0.0.1:7777','--html-output','__timestamp__.html']
    exec_xray = subprocess.Popen(xray_cmd)
    output, error = exec_xray.communicate()

def allTypeScan():
    xray_cmd = [xrayPath, 'webscan', '--listen', '127.0.0.1:7777', '--html-output', '__timestamp__.html']
    exec_xray = subprocess.Popen(xray_cmd)
    output, error = exec_xray.communicate()




def Rad(target):
    print("[+] RAD:\t" + target)
    rad_cmd = [radPath,'-t',target,'--http-proxy','127.0.0.1:7777']
    exec_rad = subprocess.Popen(rad_cmd,stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    output,error = exec_rad.communicate()

def crawlerGo(target):
    print("[+] Crawler-Go:\t" + target)
    cmd = [crawlergoPath, "-c", chrome_path,"-t", "10","-f","smart","--fuzz-path","--push-to-proxy", "http://127.0.0.1:7777/", "--push-pool-max", "10","--output-mode", "json" , target]
    exec_crgo = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    output, error = exec_crgo.communicate()
    #  save path:
    try:
        result = simplejson.loads(output.decode().split("--[Mission Complete]--")[1])
        # crawler result:
        req_list = result["req_list"]
        sub_domain = result["sub_domain_list"]
        all_domain_list = result["all_domain_list"]

        # save crawler-result:
        for p in req_list:
            print("[+] Find_New_Path: " + p["url"])
            path2File(str(p))
        for sd in sub_domain:
            print("[+] Find_New_SubDomain: " + str(sd))
            sub2File(str(sd))
        for d in all_domain_list:
            print("[+] Find_New_Domain: " + str(d))
            all2File(str(d))
    except Exception as e:
        print(e)


def plugin_p(type_info):

    alltype = {
        'sqlin':    'sqldet',   # 详细类型：
        'cmd':      'cmd_injection',
        'xss':      'xss',
        'xxe':      'xxe',
        'base':     'baseline',
        'path':     'path_traversal',
        'upload':   'upload',
        'brute':    'brute_force',
        'dir':      'direarch',
        'phan':     'phantasm',
        'urlred':   'redirect',
        'crlf':     'crlf',
        'thinkphp': 'thinkphp',
        'shiro':    'shiro',
        'fastjson': 'fastjson',
        'struts':   'struts'
    }

    return alltype[type_info]

def path2File(paths):
    try:
        f = open('crawl_path.txt','a')
        f.write(paths + '\n')
    finally:
        f.close()

def sub2File(subdomains):
    try:
        f = open('sub_domains.txt','a')
        f.write(subdomains + '\n')
    finally:
        f.close()

def all2File(subdomains):
    try:
        f = open('all_domains.txt','a')
        f.write(subdomains + '\n')
    finally:
        f.close()


def banner():
    print('''
                ____                        __________     .___
    \   \/  /___________  ___.__.   \______   \_____     __| _/
     \     /\_  __ \__  \<   |  |    |       _/\__  \   / __ |
     /     \ |  | \// __ \\___  |    |    |   \ / __ \_/ /_/ |
    /___/\  \|__|  (____  / ____|____|____|_  /(____  /\____ |
          \_/           \/\/   /_____/      \/      \/      \/

                                        Author:	loecho       
                                        Date:   2021/09/24      

    --------------------------------------------------------------------------------------
                 sqlin           SQL注入漏洞探测
                 cmd             命令执行漏洞探测
                 xss             XSS漏洞探测
                 xxe             XXE漏洞探测
                 base            baseline
                 path            目录穿越
                 upload          文件上传
                 brute           暴力破解
                 dir             目录扫描
                 urlred          任意uRL跳转
                 crlf            CRLF
                 thinkphp        THINKPHP系列漏洞探测
                 shiro           SHIRO系列漏洞探测
                 fastjson        FASTJSON系列漏洞探测
                 struts          STRUTS系列漏洞探测

            usage:

                 <1> allType-漏洞检测
                     python3 xrayRad.py url.txt all

                 <2> SQL注入漏洞检测
                     python3 xrayRad.py url.txt sqlin

         ---------------------------------------------------------------------------        
          ''')



def main():
    try:
        banner()
        filename = str(sys.argv[1])
        getScanTarget(filename)

        executor = ThreadPoolExecutor(max_workers=4)

        if 0 < len(sys.argv) < 4 and sys.argv[2] == 'all':
            # xrayScan-all
            x = Process(target=allTypeScan)
            x.start()
            print("[+] All Type XrayVulScan is Runing!")
            executor.map(Rad, list_url)
            executor.map(crawlerGo, list_url)


        elif 0 < len(sys.argv) < 4:

            # plugins-Scan:
            x = Process(target=TypeScan, args=(plugin_p(sys.argv[2]),))
            x.start()
            print("[+] Single Type XrayVulScan is Runing! The Type is {}".format(plugin_p(sys.argv[2])))
            executor.map(Rad, list_url)
            executor.map(crawlerGo, list_url)

        else:
            print("[x] Miss arg !")
            banner()
            sys.exit()

    except Exception as e:
        print(e)


if __name__ == '__main__':

    main()




