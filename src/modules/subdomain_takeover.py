import yaml
import tldextract
from dns import rcode,rdatatype

from modules import dns_query

with open("modules/fingerprints.yaml","r") as fingerprints_file:
    fingerprints = yaml.load(fingerprints_file.read(), Loader=yaml.CLoader)


class SubdomainTakeover:
    def __init__(
            self,
            rresolver: str = "1.1.1.1",
            dns_cnames: dict = dict()
        ) -> None:
        self.dns_cnames = dns_cnames
        self.rresolver = rresolver


    def check_body_cname(
            self,
            host: str,
            text: str
        ) -> str:
        for fingerprint in fingerprints:
            if(fingerprint["nxdomain"] == False):
                for cname in fingerprint["cname"]:
                    for record in self.dns_cnames[host][1]:
                        if(cname in record):
                            for text_fingerprint in fingerprint["text"]:
                                if(text_fingerprint in text):
                                    return(fingerprint["service"])
        return("")

    def check_cname(
            self,
            host: str
        ) -> str:
        for fingerprint in fingerprints:
            if(fingerprint["nxdomain"] == True):
                for cname in fingerprint["cname"]:
                    for record in self.dns_cnames[host][1]:
                        if(cname in record):
                            return(fingerprint["service"])
        return("")

    def check_nxdomain(
            self,
            host: str
        ) -> bool:
        code = self.check_dns_rcode(host)
        if(code == "NXDOMAIN"):
            return(True)
        return(False)

    def check_dns_rcode(
            self,
            host: str
        ) -> int:
        query_result = dns_query.process_query(
                                            self.rresolver,
                                            host,
                                            rdatatype.A
                                        )
        code = rcode.to_text(query_result[0])
        return(code)
