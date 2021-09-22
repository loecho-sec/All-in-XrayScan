import sys
import subprocess
from multiprocessing import Process

# 目标文件写死了，可以自己更改，推送地址自己更改！！
radPath = './rad_windows_amd64.exe'
xrayPath = './xray_windows_amd64.exe'
filename = 'url.txt'


def Rad():
    with open(filename,"r") as target:
        for line in target.readlines():
            target = line.strip('\n')
            if "://" not in target:
                target = "http://{}".format(target)
            else:
                target = target
            rad_cmd = [radPath,'-t',target,'--http-proxy','127.0.0.1:7777']
            exec_rad = subprocess.Popen(rad_cmd)
            out = exec_rad.communicate()



def SelectTypeScan(plugin):
    # ServerIP = 'http://192.168.111.1:5000'
    # filename = time.strftime('%Y-%m-%d-%H.%M.%S', time.localtime(time.time()))
    xray_cmd = [xrayPath,'webscan','--plugins',plugin,'--listen','127.0.0.1:7777','--html-output','__timestamp__.html']
    print(xray_cmd)
    exec_xray = subprocess.Popen(xray_cmd)
    output, error = exec_xray.communicate()
    #print (exec_xray)




def AllTypeScan():
    # ServerIP = 'http://192.168.111.1:5000'
    # filename = time.strftime('%Y-%m-%d-%H.%M.%S', time.localtime(time.time()))
    xray_cmd = [xrayPath,'webscan','--listen','127.0.0.1:7777','--html-output','__timestamp__.html']
    exec_xray = subprocess.Popen(xray_cmd)
    print (exec_xray)
    output, error = exec_xray.communicate()

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
        'struts':   'struts'}

    return alltype[type_info]

if __name__ == '__main__':

    print ('''
    ____                        __________             .___
\   \/  /___________  ___.__.   \______   \_____     __| _/
 \     /\_  __ \__  \<   |  |    |       _/\__  \   / __ |
 /     \ |  | \// __ \\___  |    |    |   \ / __ \_/ /_/ |
/___/\  \|__|  (____  / ____|____|____|_  /(____  /\____ |
      \_/           \/\/   /_____/      \/      \/      \/
                            
                                    Author:	Chr1sto        
                                    Date:   2020/09/01                    
    ''')
    try:
        if len(sys.argv) > 1 and sys.argv[1] == 'all':

            # xrayScan-all
            x = Process(target=AllTypeScan)
            print('[*]xray already runing')
            x.start()

            # Rad-Crawler:
            p = Process(target=Rad)
            print('[*]rad already runing')
            p.start()

        else:
            # Data check
            list1 = []
            list1.append(plugin_p(sys.argv[1]))
            parcam = tuple(list1)

            # plugins-Scan:
            x = Process(target=SelectTypeScan, args=parcam)
            print('[*]xray already runing')
            x.start()

            # Rad-Crawler:
            p = Process(target=Rad)
            print('[*]rad already runing')
            p.start()


    except Exception as e:
        print(e)
        print('''
    --------------------------------------------------------------------------
             sqlin           SQL注入漏洞探测
             cmd             命令执行漏洞探测
             xss             XSS漏洞探测
             xxe             XXE漏洞探测
             base            基线检查
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
                 python3 xrayRad.py all

             <2> SQL注入漏洞检测
                 python3 xrayRad.py sqlin

     ---------------------------------------------------------------------------        
      ''')

