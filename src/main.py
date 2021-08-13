import subprocess
import os
import mysql
import sys
import tldextract
import concurrent.futures
import time
from requests.structures import CaseInsensitiveDict
from dns import rcode,rdatatype
from modules.parse import formatting
from modules.parse import massdns
from modules import dns_query
from modules import database
from modules import http_requests
from modules.subdomain_takeover import Subdomain_Takeover

def run_command(cmd:str) -> (bytes,bytes,bytes):
    cmd = [arg for arg in cmd.split(" ") if arg != ""]
    process = subprocess.Popen(cmd,stdout=subprocess.PIPE,
                                stderr=subprocess.PIPE)
    return(process.communicate()[0],process.communicate()[1])


def get_dns_id(db_cursor,record:str) -> int:
    db_cursor.execute(f"SELECT dns_id FROM ip_cnames WHERE record='{record}'")
    result = db_cursor.fetchall()
    if(len(result) > 0):
        return(int(result[0][0]))
    return(-1)

def add_service(db_cursor,dns_id:int,port:int,transport_protocol:str,\
                state:str,service:str,fingerprint:str):
    if(dns_id == -1):
        return(-1)
    if(fingerprint == ""):
        fingerprint = "NULL"
    else:
        fingerprint = "'{}'".format(fingerprint.replace("'","\\'"))
    db_cursor.execute(f"INSERT INTO services (dns_id,port,service,state,\
                        transport_protocol,fingerprint) SELECT {dns_id} AS \
                        dns_id, {port} AS port, '{service}' AS service, \
                        '{state}' AS state, '{transport_protocol}' AS \
                        transport_protocol, {fingerprint} AS fingerprint\
                        WHERE NOT EXISTS ( SELECT 1 FROM services WHERE \
                        dns_id = {dns_id} AND port = {port} ) LIMIT 1")

def add_vulnerability(db_cursor,hostname:str,vuln:str):
    db_cursor.execute(f"INSERT INTO vulnerabilities(subdomain_id,\
                        vulnerability) VALUES ((SELECT subdomain_id FROM \
                        subdomains WHERE hostname='{hostname}'),'{vuln}')")

def probe_http(hostname:str,port:int,subdomain_id:int):
    response = http_requests.request(hostname,port)
    if(response[0] != -1):
        return("({},{},{},'/',{},'{}','{}')".format(subdomain_id,port,\
                response[3],response[0],response[1].replace("'","\\'"), \
                str(response[2]).replace("'","\\'")))

def run(domain:str,resolvers:str,brute_wordlist:str,alt_wordlist:str,\
        db_credentials:tuple):
    os.system("cls||clear")

    if(os.geteuid() != 0):
        print("nmap/masscan requires sudo.")
        sys.exit(1)

    inicio = time.time()
    print("#subfinder")
    _ = run_command(f"subfinder -d {domain} -all -o subfinder-out\
                -rL {resolvers} -timeout 90")
    print(time.time() - inicio)

    inicio = time.time()
    print("#amass")
    _ = run_command(f"amass enum -active -rf {resolvers} -d {domain} \
                    -o amass-out -passive -nf subfinder-out")
    print(time.time() - inicio)

    inicio = time.time()
    print("#massdns - resolve")
    _ = run_command(f"massdns -r {resolvers} -w massdns-resolve-out -o \
                      Srmldni amass-out -s 20000")
    print(time.time() - inicio)

    print("#create brute_wordlist")
    with open("tobrute","w") as saida:
        for parameter in open(brute_wordlist,"r"):
            _ = saida.write("{}.{}\n".format(parameter.replace("\n",""), \
                              domain))

    inicio = time.time()
    print("#massdns - brute")
    _ = run_command(f"massdns -r {resolvers} -w massdns-brute-out -o \
        Srmldni tobrute -s 20000")
    print(time.time() - inicio)

    print("#join | sort | uniq")
    with open("massdns-resolve-out","r") as resolve_out, \
        open("massdns-brute-out","r") as brute_out, \
        open("t-subdomains","w") as valid_join, open("t-nxdomains","w") \
        as nxdomain_join, open("t-errors","w") as errors_join:
            valid,nxdomain,errors = massdns.load(\
                                              resolve_out.read().split("\n") 
                                              + brute_out.read().split("\n"))
            valid_join.write("\n".join(list(valid.keys())))
            nxdomain_join.write("\n".join(nxdomain))
            errors_join.write("\n".join(errors))

    inicio = time.time()
    print("#altdns")
    _ = run_command(f"altdns -i t-subdomains -o altdns-out -w \
                    {alt_wordlist}")
    print(time.time() - inicio)

    inicio = time.time()
    print("#massdns - brute alt")
    _ = run_command(f"massdns -r {resolvers} -w massdns-alt-out -o \
        Srmldni altdns-out -s 200000")
    print(time.time() - inicio)

    print("#join | sort | uniq")
    with open("massdns-alt-out","r") as alt_out, \
        open("subdomains","w") as valid_join, \
        open("nxdomains","w") as nxdomain_join, \
        open("errors","w") as errors_join, \
        open("t-subdomains","r") as temp_subdomains, \
        open("t-nxdomains","r") as temp_nxdomains, \
        open("t-errors","r") as temp_errors:
            alt_valid,alt_nxdomain,alt_errors = massdns.load \
                                                (alt_out.read().split("\n"))
            valid = set()
            nxdomain = set()
            error = set()
            for line in temp_subdomains.read().split("\n"):
                valid.add(line)
            for line in temp_nxdomains.read().split("\n"):
                nxdomain.add(line)
            for line in temp_errors.read().split("\n"):
                error.add(line)
            for item in alt_valid.keys():
                valid.add(item)
            for item in alt_nxdomain:
                nxdomain.add(item)
            for item in alt_errors:
                error.add(item)
            for domain in valid:
                valid_join.write(domain+"\n")
            for domain in nxdomain:
                nxdomain_join.write(domain+"\n")
            for domain in error:
                if(domain not in valid):
                    errors_join.write(domain+"\n")

    inicio = time.time()
    print("#massdns - ns")
    _ = run_command(f"massdns -r /home/apolo2/.config/trusted-resolvers.txt \
        -w massdns-ns-out -t NS -o Srmldni errors -s 20000")
    print(time.time() - inicio)

    inicio = time.time()
    print("#parsing")
    with open("subdomains","a+") as subdomains_file, \
        open("massdns-alt-out","r") as alt_out, \
        open("massdns-brute-out","r") as brute_out, \
        open("massdns-ns-out","r") as ns_out, \
        open("massdns-resolve-out","r") as resolve_out:
        subdomains_lines = subdomains_file.read().split("\n")
        ns_lines = ns_out.read().split("\n")
        valid,nx,errors = massdns.load \
                            (alt_out.read().split("\n") + \
                            brute_out.read().split("\n") + \
                            resolve_out.read().split("\n"))
        massdns_ns = massdns.load(ns_lines)
        ns_valid = massdns_ns[0]
        ns_records = massdns_ns
        errors = dict()
        for subdomain in list(ns_records[0].keys()):
            if(subdomain not in subdomains_lines):
                query_result = dns_query.process_query("1.1.1.1",subdomain,\
                                                        rdatatype.A)
                code = rcode.to_text(query_result[0])
                if(query_result[1]!="" and query_result[0] == 0):
                    answers = set()
                    for answer in query_result[1].split("\n"):
                        answer = answer.split(" ")[4]
                        if(answer[-1:] == "."):
                            answer = answer[:-1]
                        answers.add(answer)
                    valid[subdomain] = (code,answers)
                else:
                    if(code in ["SERVFAIL","REFUSED"]):
                        errors[subdomain] = (code,ns_valid[subdomain][1])
    print(time.time() - inicio)

    print("#database")
    db = database.DB_Connection( \
        db_credentials[0],db_credentials[1],db_credentials[2]).connect()

    print("#tables")
    db_cursor = db.cursor()
    db_cursor.execute(f"CREATE DATABASE {domain.replace('.','_')}")
    db_cursor.execute("SET NAMES utf8mb4")
    db_cursor.execute(f"ALTER DATABASE {domain.replace('.','_')} CHARACTER \
                      SET = utf8mb4 COLLATE = utf8mb4_general_ci")
    db_cursor.execute(f"USE {domain.replace('.','_')}")
    db_cursor.execute("CREATE TABLE ip_cnames (dns_id INTEGER AUTO_INCREMENT,\
                        record VARCHAR(255) NOT NULL, PRIMARY KEY (dns_id))")
    db_cursor.execute("CREATE TABLE subdomains (subdomain_id INTEGER \
                        AUTO_INCREMENT, hostname VARCHAR(255) NOT NULL, \
                        dns_id INTEGER NOT NULL, dns_records VARCHAR(1024), \
                        classification VARCHAR (8), datetime TIMESTAMP \
                        DEFAULT CURRENT_TIMESTAMP, PRIMARY KEY \
                        (subdomain_id), FOREIGN KEY (dns_id) \
                        REFERENCES ip_cnames(dns_id))")
    db_cursor.execute("CREATE TABLE services (dns_id INTEGER, port INTEGER, \
                        state VARCHAR(14), service VARCHAR(32),\
                        transport_protocol VARCHAR(3) NOT NULL, fingerprint\
                        VARCHAR(307), PRIMARY KEY (dns_id, port), \
                        FOREIGN KEY (dns_id) REFERENCES ip_cnames(dns_id))")
    db_cINTOursor.execute("CREATE TABLE vulnerabilities (vulnerability_id INTEGER\
                        AUTO_INCREMENT, subdomain_id INTEGER NOT NULL, \
                        vulnerability VARCHAR(1024), PRIMARY KEY \
                        (vulnerability_id), FOREIGN KEY (subdomain_id) \
                        REFERENCES subdomains(subdomain_id))")
    db_cursor.execute("CREATE TABLE directories (directory_id INTEGER \
                        AUTO_INCREMENT, subdomain_id INTEGER NOT NULL, \
                        port INTEGER NOT NULL, tls TINYINT NOT NULL, \
                        path VARCHAR(2083) NOT NULL, status_code INTEGER, \
                        source_code MEDIUMTEXT CHARACTER SET utf8, headers \
                        VARCHAR(4096) CHARACTER SET utf8, PRIMARY KEY \
                        (directory_id), FOREIGN KEY (subdomain_id) \
                        REFERENCES subdomains(subdomain_id))")

    print("#table ip_cnames")
    ip_cnames = set()
    for value in valid.keys():
        ip_cnames.add(value)
    ip_cnames_str = ""
    for value in ip_cnames:
        ip_cnames_str += f" ('{value}'),"
    db_cursor.execute(f"INSERT INTO ip_cnames(record) \
                    VALUES{ip_cnames_str[:-1]}")
    db.commit()

    print("#table subdomains")
    for dns_type in [valid,nx,errors]:
        if(dns_type == valid):
            classification = "OK"
        elif(dns_type == nx):
            classification = "NXDOMAIN"
        else:
            classification = "SERVFAIL"

        for subdomain in dns_type.keys():
            records = formatting.set_to_str(dns_type[subdomain][1])
            for record in dns_type[subdomain][1]:
                db_cursor.execute(f"SELECT dns_id FROM ip_cnames WHERE \
                                    record='{record}'")
                results = db_cursor.fetchall()
                if(len(results) > 0):
                    dns_id = results[0][0]
                    db_cursor.execute(f"INSERT INTO subdomains (hostname,\
                                        dns_id, dns_records,classification) \
                                        VALUES ('{subdomain}',{dns_id},\
                                        '{records}','{classification}')")
                    break
    db.commit()

    print("#ip-cnames/ips file")
    ip_cname_link = dict()
    with open("ips","w") as ips_file:
        for ip_cname in ip_cnames:
            ip = ip_cname
            while(not formatting.is_ipv4(ip)):
                ip_query = dns_query.process_query("1.1.1.1",ip,rdatatype.A)
                if(ip_query[1] == ""):
                    break
                ip = ip_query[1].split("\n")[-1:][0].split(" ")[4]
            if(ip != ""):
                if(ip not in ip_cname_link.keys()):
                    ips_file.write(ip + "\n")
                    ip_cname_link[ip] = []
                ip_cname_link[ip].append(ip_cname)

    inicio = time.time()
    print("#nmap")
    _ = run_command("nmap -T4 --min-hostgroup 128 --max-hostgroup 2048 \
                  --host-timeout 30m -max-retries 7 -sSV -oG nmap-out -v \
                  --open -iL ips --top-ports 2000 -n")
    print(time.time() - inicio)

    inicio = time.time()
    print("#masscan")
    _ = run_command("masscan -iL ips -p- --rate 20000 -oG masscan-out")
    print(time.time() - inicio)

    inicio = time.time()
    print("#add nmap to db")
    with open("nmap-out","r") as nmap_file:
        text = nmap_file.read()
        for ip in ip_cname_link.keys():
            for line in text.split("\n")[2:-2]:
                if("Status: " not in line):
                    line = line.split("\t")
                    line = line[1][7:]
                    for terms in line.split(", "):
                        terms = terms.split("/")
                        port = int(terms[0])
                        transport_protocol = terms[2]
                        state = terms[1]
                        service = terms[4]
                        fingerprint = terms[6]
                        print(fingerprint)
                        for record in ip_cname_link[ip]:
                            add_service(db_cursor,\
                                        get_dns_id(db_cursor,record),port,\
                                        transport_protocol,state,service,\
                                        fingerprint)
    db.commit()
    print(time.time() - inicio)

    inicio = time.time()
    print("#add masscan to db")
    with open("masscan-out","r") as masscan_file:
        text = masscan_file.read()
        for ip in ip_cname_link.keys():
            for line in text.split("\n")[2:-2]:
                line = line.split("\t")
                record = line[1].split(" ")[1]
                terms = line[2].split(" ")[1].split("/")
                port = int(terms[0])
                transport_protocol = terms[2]
                state = terms[1]
                service = terms[4]
                for record in ip_cname_link[ip]:
                    add_service(db_cursor,get_dns_id(db_cursor,record),port,\
                                transport_protocol,state,service,'')
    db.commit()
    print(time.time() - inicio)

    print("#probe http")
    inicio = time.time()
    db_cursor.execute("SELECT hostname,port,subdomain_id FROM subdomains \
                        INNER JOIN services AS svc \
                        ON svc.dns_id = subdomains.dns_id")
    query = "INSERT INTO directories(subdomain_id,port,tls,path,status_code,\
            source_code,headers) VALUES "
    with concurrent.futures.ThreadPoolExecutor(max_workers=2048) as executor:
        threads = {executor.submit(probe_http,\
                                    result[0],result[1],result[2]): 
                    result for result in db_cursor.fetchall()}
        for thread in threads:
            result = thread.result()
            if(result != None):
                query += f"{result},"
    db_cursor.execute(query[:-1])
    db.commit()
    print(time.time() - inicio)

    print("#subdomain takeover")
    inicio = time.time()
    services_takeover = Subdomain_Takeover(valid)
    for subdomain in valid.keys():
        source_code = ""
        db_cursor.execute(f"SELECT source_code FROM directories WHERE path =\
                         '/' AND subdomain_id = (SELECT subdomain_id FROM \
                         subdomains WHERE hostname = '{subdomain}') AND \
                         (port = 80 OR port = 443)")
        for code in db_cursor.fetchall():
            source_code += code[0]
        result = services_takeover.check_body_cname(subdomain,source_code)
        if(result != None):
            add_vulnerability(db_cursor,subdomain,\
                            formatting.normalize_whitespaces( \
                            f"[SUBDOMAIN TAKEOVER] SVC {result}"))
        mx_result = services_takeover.check_mx(subdomain)
        if(len(mx_result) > 0):
            add_vulnerability(db_cursor,subdomain,\
                            formatting.normalize_whitespaces( \
                            f"[SUBDOMAIN TAKEOVER] MX {mx_result}"))
    db.commit()
    services_nx_takeover = Subdomain_Takeover(nx)
    for subdomain in nx.keys():
        result = services_nx_takeover.check_cname(subdomain)
        if(result != None):
            add_vulnerability(db_cursor,subdomain,
                            formatting.normalize_whitespaces( \
                            f"[SUBDOMAIN TAKEOVER] NX {result}"))
    db.commit()
    services_ns_takeover = Subdomain_Takeover()
    for subdomain in errors.keys():
        for ns in errors[subdomain][1]:
            ns = tldextract.extract(ns).registered_domain
            result = services_ns_takeover.check_nxdomain(ns)
            if(result):
                add_vulnerability(db_cursor,subdomain,
                            formatting.normalize_whitespaces( \
                            f"[SUBDOMAIN TAKEOVER] NX NS {result}"))
    db.commit()
    print(time.time() - inicio)

    print("#delete")
    to_remove = ["altdns-out","alt-errors","alt-nxdomain-cname", \
                "alt-subdomains","tobrute","t-errors","t-nxdomains", \
                "t-subdomains","amass-out","subfinder-out","subdomains", \
                "errors","nxdomains","ips"]
    for file in to_remove:
        try:
            os.remove(file)
        except FileNotFoundError:
            pass

    print("#close db conn")
    db_cursor.close()
    db.close()
