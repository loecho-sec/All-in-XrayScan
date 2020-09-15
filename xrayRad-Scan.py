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

def Alltype(url):

    '''
    默认扫描所有类型的漏洞
    '''

    target = url

    print '\033[32m[+] ScanUrl: \033[0m'+ target
    cmd = ["./xray_windows_amd64.exe", "webscan", "--browser-crawler", target, "--html-output", "{}.html",format()]
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
    #High ='sqldet,cmd_injection,thinkphp,fastjson,shiro,xxe,path_traversal,upload,brute_force,ssrf'
    #Low ='dirscan,phantasm,baseline,redirect,crlf_injection,xss,struts'

    # all-探测类型：
    alltype = {

        'sqlin':    'sqldet',   # 详细类型：
        'cmd':      'cmd_injection',
        'xss':      'xss',
        'xxe':      'xxe',
        'base':     'baseline',
        'path':     'path_traversal',
        'upload':   'upload',
        'brute':    'brute_force',
        'dir':      'dirsearch',
        'phan':     'phantasm',
        'urlred':   'redirect',
        'crlf':     'crlf',
        'thinkphp': 'thinkphp',
        'shiro':    'shiro',
        'fastjson': 'fastjson',
        'struts':   'struts'
    }

    if "High" or "Low" not in type_info:
        type_info=alltype[type_info]
    else:pass
        # if "High" in type_info:
        #     type_info = High
        # else:
        #     type_info = Low

    cmd = ["./xray_windows_amd64.exe", "webscan", "--plugins", type_info, "--browser-crawler", target, "--html-output",
           "{}-Report.html".format(type_info)]
    rsp = subprocess.Popen(cmd)
    output, error = rsp.communicate()


def main(filename):

    file = open(filename)
    for text in file.readlines():
        url = text.strip('\n')
        if "://" not in url:
            url = "http://{}".format(url)
            Alltype(url)
        elif "://" and ":443" in url:
            url = url
            Alltype(url)
        else:
            url = url
            Alltype(url)


if __name__=='__main__':

    try:
        if len(sys.argv) == 3:
            type(sys.argv[1], sys.argv[2])
        else:
            main(filename=sys.argv[1])


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
