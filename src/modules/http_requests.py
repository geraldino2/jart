import requests
import time
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

ua = "Mozilla/5.0 (X11; Linux x86_64; rv:90.0) Gecko/20100101 Firefox/90.0"
ua_accept_headers = {"User-Agent": ua, "Accept": "*/*"}

def probe(hostname:str,port:int,path:str="/",req_timeout:int=6,\
            rcv_timeout:int=12,max_size:int=int(16e6),retries:int=3)\
            -> (int,str,dict,bool):

    http_response = https_response = (-1,"","",False)
    protocol_link = {"http":http_response,"https":https_response}

    for protocol in protocol_link.keys():
        req,response = request(f"{protocol}://{hostname}:{port}{path}")
        if(req == -1):
            continue
        protocol_link[protocol] = (req.status_code,response,\
                                    req.headers,int(protocol=="https"))

    if(protocol_link["https"][0] != -1):
        return(protocol_link["https"])
    return(protocol_link["http"])

def request(url:str,req_timeout:int=6,rcv_timeout:int=12,\
            max_size:int=int(16e6),retries:int=3):
    for _ in range(retries):
        try:
            req = requests.get(url,allow_redirects=False,verify=False, \
                               stream=True,headers=ua_accept_headers,\
                               timeout=req_timeout)
        except:
            continue

        response = b""
        size = 0
        start = time.time()
        for chunk in req.iter_content(1024):
            response += chunk
            size += len(chunk)
            if(time.time() - start > rcv_timeout):
                break
            if(size > max_size):
                break
        response = response.decode("utf-8")
        return(req,response)
    return(-1,-1)
