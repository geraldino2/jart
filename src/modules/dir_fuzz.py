import random
import concurrent.futures

from modules import http_requests

class DirFuzzer(object):
    def __init__(self,http_req_timeout,http_rcv_timeout,max_http_size,\
                    dir_fuzz_threads,dir_fuzz_retries):
        self.http_req_timeout = http_req_timeout
        self.http_rcv_timeout = http_rcv_timeout
        self.max_http_size = max_http_size
        self.dir_fuzz_threads = dir_fuzz_threads
        self.dir_fuzz_retries = dir_fuzz_retries
        self.paths = set()
        self.known_urls = list()
        self.urls = list()
        self.calibration = dict()
        self.calibration_strs = set()
        self.matches = dict()


    def set_paths(self,collection):
        self.paths = set(collection)

    def set_known_urls(self,collection):
        self.known_urls = list(collection)

    def set_calibration_strs(self,collection):
        self.calibration_strs = set(collection)

    def parametized_request(self,url):
        req,resp = http_requests.request(url,self.http_req_timeout,\
                                    self.http_rcv_timeout,self.max_http_size,\
                                    self.dir_fuzz_retries)
        return(req,resp)

    def calibration_req(self,url,calibration_str):
        req_url = f"{url}/{calibration_str}"
        req,resp = self.parametized_request(req_url)
        if(req!=-1):
            if(url not in self.calibration.keys()):
                self.calibration[url] = set()
            self.calibration[url].add("{},{},{},{}".format(req.status_code,\
                                        len(resp.split()),len(req.headers)))

    def gen_calibration(self):
        calibration_urls = []
        for url in self.known_urls:
            for calibration_str in self.calibration_strs:
                calibration_urls.append([url,calibration_str])
        with concurrent.futures.ThreadPoolExecutor(max_workers=self.\
                                                dir_fuzz_threads) as executor:
            threads = {executor.submit(self.calibration_req,url[0],url[1]): 
                        url for url in calibration_urls}
            executor.shutdown(wait=True)

    def gen_urls(self):
        for i in range(len(self.known_urls)):
            url = self.known_urls[i]
            if(url[-1:]=="/"):
                url=url[:-1]
            self.known_urls[i] = url
            for path in self.paths:
                self.urls.append(f"{url}/{path}")
        random.shuffle(self.urls)

    def fuzz_req(self,url):
        self.urls.remove(url)
        req,resp = self.parametized_request(url)
        if(req!=-1):
            calibration_url = url
            while(calibration_url not in self.calibration.keys()):
                calibration_url = "/".join(calibration_url.split("/")[:-1])
                print(calibration_url)
            for filters in self.calibration[calibration_url]:
                filters = list(map(int,calibration_filter.split(",")))
                filter_status,filter_rlen,filter_hlen = filters
                print(len(req.headers),req.headers)
                if(req.status_code==filter_status and len(resp.split())==\
                    filter_rlen and len(req.headers)==filter_rlen):
                    return
            self.matches[url] = req,resp

    def fuzz(self):
        self.gen_urls()
        self.gen_calibration()
        with concurrent.futures.ThreadPoolExecutor(max_workers=self.\
                                                dir_fuzz_threads) as executor:
            threads = {executor.submit(self.fuzz_req,url): 
                        url for url in self.urls[:20000]}
            executor.shutdown(wait=True)
        return(self.matches)
