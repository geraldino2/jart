import concurrent.futures
import requests
import re
from dns import exception,flags,message,name,query,rdatatype

domain = "uber.com"

public_lists = ["http://public-dns.info/nameservers.txt"]
resolvers = set()
valid_resolvers = set()

checks = [[f"www.tumblr.com,www.pizzirani.{domain}",""], \
        [f"tb-origin-staging.{domain}",""], \
        [f"metallicheckiy-portal.{domain}",""], \
        [f"www.wairoadirect.{domain}",""], \
        [f"www.work-from-home-dads.{domain}",""], \
        [f"*.mysql.{domain}",""], \
        [f"join.{domain}",""], \
        ["google.com",""], \
        [f"www.content.mysql.rbc.medialand.latin-ru.dm.{domain}",""], \
        [f"ir.af-ir.{domain}",""], \
        ["www.uber.com",""], \
        ["github.com",""]]

def load_resolvers():
    for public_list in public_lists:
        res = requests.get(public_list)
        if(res.status_code == 200):
            for resolver in res.text.split("\n"):
                valid = re.match("^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$",\
                                resolver)
                if(valid):
                    resolvers.add(resolver)

    with open("/home/apolo2/Desktop/jart/src/utils/base-resolvers.txt","r") as base_resolvers:
        for resolver in base_resolvers.read().split("\n"):
            resolvers.add(resolver)

def process_query(resolver:str,host:str) -> (int,str):
    '''
    Output
        status
        ANSWER
    '''
    ADDITIONAL_RDCLASS = 65535
    request = message.make_query(name.from_text(host), rdatatype.CNAME)
    request.flags |= flags.AD
    request.find_rrset(request.additional,name.root,ADDITIONAL_RDCLASS, \
                       rdatatype.OPT, create=True, force_unique=True)
    try:
        response = query.udp(request,resolver,5)
        if(len(response.answer)>0):
            return((response.rcode(),response.answer[0].to_text() \
                    .split(" ")[4]))
        return((response.rcode(),""))
    except exception.Timeout:
        return(("TIMEOUT",""))

def generate_baseline():
    for check in checks:
        check[1] = process_query("1.1.1.1",check[0])

def check_resolver(resolver:str) -> bool:
    for check in checks:
        if(process_query(resolver,check[0]) != check[1]):
            return(False)
    valid_resolvers.add(resolver)
    print(resolver)
    return(True)

def validate_resolvers():
    with concurrent.futures.ThreadPoolExecutor(max_workers=256) as executor:
        thread = {executor.submit(check_resolver, resolver): 
        resolver for resolver in resolvers}

def export_resolvers(filename:str):
    generate_baseline()
    load_resolvers()
    validate_resolvers()
    with open(filename,"w") as output:
        for resolver in valid_resolvers:
            output.write(resolver + "\n")
