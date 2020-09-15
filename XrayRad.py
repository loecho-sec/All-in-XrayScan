import sys
import subprocess
import time
from multiprocessing import Process

radPath = './rad_windows_amd64.exe'
xrayPath = './xray_windows_amd64.exe'
ServerIP = 'http://192.168.111.1:5000'

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
    filename = time.strftime('%Y-%m-%d-%H.%M.%S', time.localtime(time.time()))
    xray_cmd = [xrayPath,'webscan','--plugins',type_info,'--listen','127.0.0.1:7777','--webhook-output','{}/webhook','--html-output','{}.html'.format(ServerIP,filename)]
    exec_xray = subprocess.Popen(xray_cmd)
    print exec_xray 
    output, error = exec_xray.communicate()



def AllTypeScan():
    filename = time.strftime('%Y-%m-%d-%H.%M.%S', time.localtime(time.time()))
    xray_cmd = [xrayPath,'webscan','--listen','127.0.0.1:7777','--webhook-output','{}/webhook','--html-output','{}.html'.format(ServerIP,filename)]
    exec_xray = subprocess.Popen(xray_cmd)
    print exec_xray
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
        print(type_info)

        # for i, k in alltype.items():
        #     if i == sys.argv[1]:
        #         type_info = k
        #     continue
        #
        #     else:
        #         print('[error]参数输入错误，请检查输入！')
        #         sys.exit()

    except Exception as e:
            print("[error]参数输入错误或无参数，请检查输入！")
            sys.exit()
    return type_info
if __name__ == '__main__':
    print '''
    ____                        __________             .___
\   \/  /___________  ___.__.   \______   \_____     __| _/
 \     /\_  __ \__  \<   |  |    |       _/\__  \   / __ |
 /     \ |  | \// __ \\___  |    |    |   \ / __ \_/ /_/ |
/___/\  \|__|  (____  / ____|____|____|_  /(____  /\____ |
      \_/           \/\/   /_____/      \/      \/      \/




                     Usage:
                            python3 Xray_rad.py -all 全类型扫描
                            python3 Xray_rad.py sqlin sql注入扫描
                            
                     Author:
                            Chr1sto
                            
                     Date:
                            2020/09/01


    '''
    if  sys.argv[1] == '--all' :
        x = Process(target=AllTypeScan)
        print('[*]xray already runing')
        x.start()
    elif sys.argv[1] == '-h' or sys.argv[1] == '--help':
        print '''
                指定漏洞类型进行扫描，参数如下：
                                            sqlin
                                            cmd
                                            xss
                                            xxe
                                            base
                                            path
                                            upload
                                            brute
                                            dir
                                            phan
                                            urlred
                                            crlf
                                            thinkphp
                                            shiro
                                            fastjson
                                            struts
                --all 全类型扫描
        '''
        sys.exit()
    else:
        list1=[]
        list1.append(Type())
        type_info = tuple(list1)
        x = Process(target=SelectTypeScan, args=(type_info))
        print('[*]xray already runing')
        x.start()

    p = Process(target=Rad)
    print('[*]rad already runing')
    p.start()
