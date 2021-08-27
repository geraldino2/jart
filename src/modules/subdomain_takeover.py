import yaml
import tldextract
from modules import dns_query
from dns import rcode,rdatatype

with open("modules/fingerprints.yaml","r") as fingerprints_file:
    fingerprints = yaml.load(fingerprints_file.read(), Loader=yaml.CLoader)

class Subdomain_Takeover(object):
    def __init__(self,rresolver="1.1.1.1",dns_cnames=dict()):
        self.dns_cnames = dns_cnames
        self.rresolver = rresolver

    def check_body_cname(self,host:str,text:str):
        for fingerprint in fingerprints:
            if(fingerprint["nxdomain"] == False):
                for cname in fingerprint["cname"]:
                    for record in self.dns_cnames[host][1]:
                        if(cname in record):
                            for text_fingerprint in fingerprint["text"]:
                                if(text_fingerprint in text):
                                    return(fingerprint["service"])
        return(None)

    def check_cname(self,host:str):
        for fingerprint in fingerprints:
            if(fingerprint["nxdomain"] == True):
                for cname in fingerprint["cname"]:
                    for record in self.dns_cnames[host][1]:
                        if(cname in record):
                            return(fingerprint["service"])
        return(None)

    def check_nxdomain(self,host:str):
        code = self.check_dns_rcode(host)
        if(code == "NXDOMAIN"):
            return(True)
        return(False)

    def check_dns_rcode(self,host:str):
        query_result = dns_query.process_query(self.rresolver,host,\
                                                rdatatype.A)
        code = rcode.to_text(query_result[0])
        return(code)
