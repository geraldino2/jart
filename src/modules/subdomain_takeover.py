import yaml
import tldextract
from dns import rcode, rdatatype

from modules import dns_query

with open("modules/fingerprints.yaml", "r") as fingerprints_file:
    fingerprints = yaml.load(fingerprints_file.read(), Loader = yaml.CLoader)


class SubdomainTakeover:
    def __init__(
            self,
            rresolver: str = "1.1.1.1",
            dns_cnames: dict = dict()
        ) -> None:
        """
        Initialize class.

        :param rresolver: the DNS resolver to be used
        :param dns_cnames: dictionary containing DNS CNAME answers
        """
        self.rresolver = rresolver
        self.dns_cnames = dns_cnames
        return


    def check_body_cname(
            self,
            host: str,
            text: str
        ) -> str:
        """
        Check if both the source code of a page and its CNAME contains
        a vulnerable fingerprint.

        :param host: hostname of the webpage
        :param text: source code of the webpage
        :returns: vulnerable service's fingerprint
        """
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
        """
        Check if a hostname's CNAME contains a vulnerable fingerprint.

        :param host: the hostname to be tested
        :returns: vulnerable service's fingerprint
        """ 
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
        """
        Check if, when questioned its A record, the rcode is NXDOMAIN.

        :param host: hostname to be questioned
        :returns: a boolean. Is rcode == NXDOMAIN?
        """
        code = self.check_dns_rcode(host)
        if(code == "NXDOMAIN"):
            return(True)
        return(False)

    def check_dns_rcode(
            self,
            host: str
        ) -> int:
        """Perform a DNS A question to a host; returns the rcode."""
        query_result = dns_query.process_query(
                                            self.rresolver,
                                            host,
                                            rdatatype.A
                                        )
        code = rcode.to_text(query_result[0])
        return(code)
