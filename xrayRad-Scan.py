#!/usr/bin/ python
# -*- coding:utf-8 -*-
"""
-------------------------------------------------
Author:    loecho
Datetime:  2020/8/31 10:15
ProjectN:  xrayRad.py
Blog:      https://loecho.me
Email:     loecho@foxmail.com
-------------------------------------------------
"""
import subprocess
import sys
import time
from colorama import Fore, init


xrayPath = './xray_windows_amd64.exe'

def Alltype(url):
    '''
    默认扫描所有类型的漏洞
    '''

    filename = time.strftime('%Y-%m-%d-%H.%M.%S', time.localtime(time.time()))
    target = url
    print '\033[32m[+] ScanUrl: \033[0m' + target
    cmd = [xrayPath, "webscan", "--browser-crawler", target, "--html-output",
           "{}.html".format(filename)]
    rsp = subprocess.Popen(cmd)
    output, error = rsp.communicate()


def type(url, type_info):

    target = url

    print '\033[32m[+] ScanUrl: \033[0m' + target

    '''
    细化攻击类型，提升效率：

    high: sqldet, cmd_injection, thinkphp, fastjson, shiro, xxe, path_traversal, upload, brute_force, ssrf
    Low：dirscan, phantasm, baseline, redirect, crlf_injection, xss struts
    '''

    # 基本探测：
    # High ='sqldet,cmd_injection,thinkphp,fastjson,shiro,xxe,path_traversal,upload,brute_force,ssrf'
    # Low ='dirscan,phantasm,baseline,redirect,crlf_injection,xss,struts'

    # all-探测类型：
    alltype = {

        'sqlin': 'sqldet',  # 详细类型：
        'cmd': 'cmd_injection',
        'xss': 'xss',
        'xxe': 'xxe',
        'base': 'baseline',
        'path': 'path_traversal',
        'upload': 'upload',
        'brute': 'brute_force',
        'dir': 'dirsearch',
        'phan': 'phantasm',
        'urlred': 'redirect',
        'crlf': 'crlf',
        'thinkphp': 'thinkphp',
        'shiro': 'shiro',
        'fastjson': 'fastjson',
        'struts': 'struts'
    }

    filename = time.strftime('%Y-%m-%d-%H.%M.%S', time.localtime(time.time()))
    type = alltype[type_info]
    cmd = [xrayPath, "webscan", "--plugins", type, "--browser-crawler", target, "--html-output",
       "{}-{}.html".format(type_info, filename)]
    rsp = subprocess.Popen(cmd)
    output, error = rsp.communicate()


# 单类型：
def oneTypemain(filename, type_info):
    file = open(filename)
    for text in file.readlines():
        url = text.strip('\n')
        if "://" not in url:
            url = "http://{}".format(url)
            type(url, type_info)
        else:
            url = url
            type(url, type_info)


# 全类型：
def typemain(filename):
    file = open(filename)
    for text in file.readlines():
        url = text.strip('\n')
        if "://" not in url:
            url = "http://{}".format(url)
            Alltype(url)
        else:
            url = url
            Alltype(url)


if __name__ == '__main__':

    try:
        if len(sys.argv) > 2:
            oneTypemain(filename=sys.argv[1], type_info=sys.argv[2])
        else:
            typemain(filename=sys.argv[1])


    except Exception as r:

        print Fore.LIGHTYELLOW_EX + '''
    _  __                  ____            __     _____
   | |/ /_________ ___  __/ __ \____ _____/ /    / ___/_________ _____
   |   // ___/ __ `/ / / / /_/ / __ `/ __  /_____\__ \/ ___/ __ `/ __ \\
  /   |/ /  / /_/ / /_/ / _, _/ /_/ / /_/ /_____/__/ / /__/ /_/ / / / /
 /_/|_/_/   \__,_/\__, /_/ |_|\__,_/\__,_/     /____/\___/\__,_/_/ /_/
                 /____/

                                                     Version:    v1.0
                                                     Author:     loecho
                                                     Blog:       https://loecho.me

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
             python2 xrayRad-Scan.py url.txt


         <2> SQL注入漏洞检测
             python2 xrayRad-Scan.py url.txt sqlin

 ---------------------------------------------------------------------------
 '''
