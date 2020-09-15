import sys
import subprocess
import time
from multiprocessing import Process

# 目标文件写死了，可以自己更改，推送地址自己更改！！

radPath = './rad_windows_amd64.exe'
xrayPath = './xray_windows_amd64.exe'


def Rad():
    with open("url.txt","r") as target:
        for line in target.readlines():
            target = line.strip('\n')
            if "://" not in target:
                target = "http://{}".format(target)
            else:
                target = target
            rad_cmd = [radPath,'-t',target,'--http-proxy','127.0.0.1:7777']
            exec_rad = subprocess.Popen(rad_cmd)
            out = exec_rad.communicate()



def SelectTypeScan(type_info):

    ServerIP = 'http://192.168.111.1:5000'
    
    filename = time.strftime('%Y-%m-%d-%H.%M.%S', time.localtime(time.time()))
    xray_cmd = [xrayPath,'webscan','--plugins',type_info,'--listen','127.0.0.1:7777','--webhook-output','{}/webhook'.format(ServerIP),'--html-output','{}.html'.format(ServerIP,filename)]
    exec_xray = subprocess.Popen(xray_cmd)
    print (exec_xray)
    output, error = exec_xray.communicate()



def AllTypeScan():

    ServerIP = 'http://192.168.111.1:5000'
    
    filename = time.strftime('%Y-%m-%d-%H.%M.%S', time.localtime(time.time()))
    xray_cmd = [xrayPath,'webscan','--listen','127.0.0.1:7777','--webhook-output','{}/webhook'.format(ServerIP),'--html-output','{}.html'.format(filename)]
    exec_xray = subprocess.Popen(xray_cmd)
    print (exec_xray)
    output, error = exec_xray.communicate()



def Type():
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
    try:
        i = sys.argv[1]
        type_info=alltype[i]
        #print(type_info)


    except Exception as e:
            print("[error]参数输入错误或无参数，请检查输入！")
            sys.exit()
    return type_info
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

    if len(sys.argv) > 1:
        if sys.argv[1]=="all":
            x = Process(target=AllTypeScan)
            print('[*]xray already runing')
            x.start()
            # 启动Rad爬虫
            p = Process(target=Rad)
            print('[*]rad already runing')
            p.start()


        else:
            list1 = []
            list1.append(Type())
            type_info = tuple(list1)
            x = Process(target=SelectTypeScan, args=(type_info))
            print('[*]xray already runing')
            x.start()
            # 启动Rad爬虫
            p = Process(target=Rad)
            print('[*]rad already runing')
            p.start()


    else:
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
        sys.exit()


