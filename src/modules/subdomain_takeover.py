import yaml
import tldextract
from modules import dns_query
from dns import rcode,rdatatype

with open("modules/fingerprints.yaml","r") as fingerprints_file:
    fingerprints = yaml.load(fingerprints_file.read(), Loader=yaml.CLoader)

class Subdomain_Takeover(object):
    def __init__(self,dns_cnames=dict()):
        self.dns_cnames = dns_cnames

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
        query_result = dns_query.process_query("1.1.1.1",host,rdatatype.A)
        code = rcode.to_text(query_result[0])
        return(code)

    def check_mx(self,host:str):
        vulnerable = set()
        mx_query_result = dns_query.process_query("1.1.1.1",host,rdatatype.MX)
        for mail_record in mx_query_result[1].split("\n"):
            if(len(mail_record.split(" ")) < 6):
                continue
            mail_server = mail_record.split(" ")[5]
            mail_domain = tldextract.extract(mail_server).registered_domain
            code = self.check_dns_rcode(mail_server)
            if(code == "NOERROR"):
                continue
            elif(code in ["SERVFAIL","REFUSED"]):
                ns_query_result = dns_query.process_query("1.1.1.1",\
                                                    mail_server,rdatatype.MX)
                for ns_record in ns_query_result[1].split("\n"):
                    ns = ns_record.split(" ")[4]
                    ns_domain = tldextract.extract(ns).registered_domain
                    if(self.check_nxdomain(ns_domain)):
                        vulnerable.add(f"(NS NXDOMAIN) @{mail_server}")
            elif(code == "NXDOMAIN"):
                if(self.check_nxdomain(mail_domain)):
                    vulnerable.add(f"(NXDOMAIN) @{mail_server}")
        return(vulnerable)
