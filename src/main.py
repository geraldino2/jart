import subprocess
import os
import sys
import tldextract
import concurrent.futures
import time
import ast
import json
import random
from urllib import parse
from html2image import Html2Image
from requests.structures import CaseInsensitiveDict
from dns import rcode,rdatatype
from modules.parse import formatting,massdns,http_extract
from modules.database import db_conn
from modules import dns_query,http_requests
from modules.subdomain_takeover import Subdomain_Takeover

def run_command(cmd:str) -> (bytes,bytes,bytes):
    start_time = time.time()
    cmd = [arg for arg in cmd.split(" ") if arg != ""]
    process = subprocess.Popen(cmd,stdout=subprocess.PIPE,
                                stderr=subprocess.PIPE)
    stdout,stderr=process.communicate()[0],process.communicate()[1]
    print(time.time() - start_time)
    return(stdout,stderr)


def get_dns_id(db_cursor,record:str) -> int:
    db_cursor.execute("SELECT dns_id FROM dns_records WHERE record=%s",\
                        (record,))
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
    db_cursor.execute("INSERT INTO vulnerabilities(subdomain_id,\
                        vulnerability) VALUES ((SELECT subdomain_id FROM \
                        subdomains WHERE hostname=%s),%s)",(hostname,vuln))

def probe_http(hostname:str,port:int,subdomain_id:int,http_req_timeout:int,\
                http_rcv_timeout:int,max_http_size:int,max_http_retries:int):
    response = http_requests.probe(hostname,port,"/",http_req_timeout,\
                                    http_rcv_timeout,max_http_size,\
                                    max_http_retries)
    if(response[0] != -1):
        return(subdomain_id,port,response[3],response[0],len(response[1]), \
                response[1],str(response[2]))
        #subdomain_id,port,tls,status,size,source_code,headers
    return(None)

def run(root_path:str,domain:str,resolvers:str,brute_wordlist:str,\
        alt_wordlist:str,db_credentials:tuple,scan_external_redirection:int,\
        max_http_redirection:int,max_dns_retries:int,max_http_retries:int,\
        http_req_timeout:int,http_rcv_timeout:int,max_http_size:int,\
        nuclei_templates:str,max_http_rps:int,nuclei_bulksize:int,\
        nuclei_concurrency:int,max_http_probe_threads:int):

    if(os.geteuid() != 0):
        print("nmap/masscan requires sudo.")
        sys.exit(1)

    targets = {domain}
    os.system("cls||clear")

    print("#subfinder")
    _ = run_command(f"subfinder -d {domain} -all -o subfinder-out\
                -rL {resolvers} -timeout 90")

    print("#amass")
    _ = run_command(f"amass enum -active -rf {resolvers} -d {domain} \
                    -o amass-out -passive -nf subfinder-out")

    print("#massdns - resolve")
    _ = run_command(f"massdns -r {resolvers} -w massdns-resolve-out -o \
                      Srmldni amass-out -s 20000")
    print("#create brute_wordlist")
    with open("tobrute","w") as saida:
        for parameter in open(brute_wordlist,"r"):
            _ = saida.write("{}.{}\n".format(parameter.replace("\n",""), \
                              domain))


    print("#massdns - brute")
    _ = run_command(f"massdns -r {resolvers} -w massdns-brute-out -o \
        Srmldni tobrute -s 20000")
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


    print("#altdns")
    _ = run_command(f"altdns -i t-subdomains -o altdns-out -w \
                    {alt_wordlist}")

    print("#massdns - brute alt")
    _ = run_command(f"massdns -r {resolvers} -w massdns-alt-out -o \
        Srmldni altdns-out -s 200000")
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


    print("#massdns - ns")
    _ = run_command(f"massdns -r /home/apolo2/.config/trusted-resolvers.txt \
        -w massdns-ns-out -t NS -o Srmldni errors -s 20000")

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
                                                       rdatatype.A,\
                                                       max_dns_retries)
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
                    if(code in ['SERVFAIL','REFUSED']):
                        errors[subdomain] = (code,ns_valid[subdomain][1])

    print("#database")
    db = db_conn.DB_Connection( \
        db_credentials[0],db_credentials[1],db_credentials[2]).connect()

    print("#tables")
    db_cursor = db.cursor()
    db_cursor.execute("CREATE DATABASE IF NOT EXISTS {} CHARACTER SET = \
                        utf8mb4 COLLATE = utf8mb4_unicode_ci".format(\
                        domain.replace('.','_')))
    db_cursor.execute(f"USE {domain.replace('.','_')}")
    db_cursor.execute("SET GLOBAL sql_mode=''")
    db_cursor.execute("SET NAMES utf8mb4")
    db_cursor.execute("SET character_set_connection=utf8mb4")
    db.commit()

    print("#create tables")
    with open("{}/modules/database/create-tables.sql".format(\
            root_path)) as queries_file:
        create_table_queries = queries_file.read().split("---")
    for sql_query in create_table_queries:
        db_cursor.execute(sql_query)

    print("#table targets")
    for target in targets:
        db_cursor.execute("INSERT INTO targets(hostname) SELECT * FROM \
                            (SELECT %s) AS tmp WHERE NOT EXISTS (SELECT 1 \
                            FROM targets WHERE hostname=%s LIMIT 1)",\
                            (target,target))
    db.commit()

    print("#tables dns_records,subdomains,dns_link")
    for classification in [valid,nx,errors]:
        for key in classification.keys():
            db_cursor.execute("INSERT INTO subdomains(hostname) VALUES (%s)",\
                                (key,))
            db_cursor.execute("SELECT subdomain_id FROM subdomains WHERE\
                                hostname=%s",(key,))
            subdomain_id = db_cursor.fetchall()[0]
            for ip_cname in classification[key][1]:
                query_question = "A" if formatting.is_ipv4(ip_cname) \
                                else "CNAME"
                if(classification == errors):
                    query_question = "NS"
                query_rcode = classification[key][0]
                db_cursor.execute("INSERT INTO dns_records(record,type,rcode)\
                                    SELECT * FROM (SELECT %s,%s,%s) AS tmp \
                                    WHERE NOT EXISTS (SELECT 1 FROM \
                                    dns_records WHERE record=%s AND type=%s \
                                    LIMIT 1)",(ip_cname,query_question,\
                                    query_rcode,ip_cname,query_question))
                db_cursor.execute("INSERT INTO dns_link(subdomain_id,dns_id)\
                                    VALUES (%s,(SELECT dns_id FROM \
                                    dns_records WHERE record=%s))",\
                                    (subdomain_id,ip_cname))
    db.commit()

    print("#table cname_resolutions")
    db_cursor.execute("SELECT dns_id,record FROM dns_records WHERE (type=\
                        'CNAME')")
    for result in db_cursor.fetchall():
        dns_id,ips = result[0],[result[1]]
        while(not formatting.is_ipv4(ips[0])):
            ip_query = dns_query.process_query("1.1.1.1",ips[0],rdatatype.A,\
                                                max_dns_retries)
            if(ip_query[1] == ""):
                db_cursor.execute("DELETE FROM cname_resolutions WHERE\
                                    dns_id=%s",(dns_id,))
                break
            ips = []
            for record in ip_query[1].split("\n")[-1:]:
                ips.append(record.split(" ")[4])
            for ip in ips:
                if(ip[-1:] == "."):
                    ip = ip[:-1]
                db_cursor.execute("INSERT INTO cname_resolutions(dns_id,\
                                    record) VALUES (%s,%s)",(dns_id,ip))
    db.commit()

    print("#ips file, ip_cname_link")
    with open("{}/modules/database/select-hostname_ipv4.sql".format(\
                root_path)) as queries_file:
        hostname_ipv4_queries = queries_file.read().split("---")
    with open("ips","w") as ips_file:
        ip_cname_link  = dict()
        for sql_query in hostname_ipv4_queries:
            db_cursor.execute(sql_query)
            for result in db_cursor.fetchall():
                if(result[1] not in ip_cname_link.keys()):
                    ip_cname_link[result[1]] = []
                ip_cname_link[result[1]].append(result[0])
        for ip in ip_cname_link.keys():
            ips_file.write(ip + "\n")

    print("#nmap")
    _ = run_command("nmap -T4 --min-hostgroup 128 --max-hostgroup 2048 \
                  --host-timeout 30m -max-retries 7 -sSV -oG nmap-out -v \
                  --open -iL ips --top-ports 2000 -n")

    print("#masscan")
    _ = run_command("masscan -iL ips -p- --rate 20000 -oG masscan-out")

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
                        for record in ip_cname_link[ip]:
                            add_service(db_cursor,\
                                        get_dns_id(db_cursor,record),port,\
                                        transport_protocol,state,service,\
                                        fingerprint)
    db.commit()

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
 
    print("#probe http")
    db_cursor.execute("SELECT sbd.hostname,svc.port,dnl.subdomain_id FROM \
                        subdomains AS sbd INNER JOIN dns_link AS dnl ON \
                        sbd.subdomain_id=dnl.subdomain_id INNER JOIN services\
                        AS svc ON svc.dns_id=dnl.dns_id")
    results = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=\
                                        max_http_probe_threads) as executor:
        threads = {executor.submit(probe_http,\
                                    result[0],result[1],result[2],\
                                    http_req_timeout,http_rcv_timeout,\
                                    max_http_size,max_http_retries): 
                    result for result in db_cursor.fetchall()}
        for thread in threads:
            result = thread.result()
            if(result != None):
                results.append(result)
    for result in results:
        db_cursor.execute("INSERT INTO source_codes(source_code) SELECT * \
                            FROM (SELECT %s) AS tmp  WHERE NOT EXISTS \
                            (SELECT 1 FROM source_codes WHERE source_code \
                            = %s LIMIT 1)",(result[5],result[5]))
        db_cursor.execute("INSERT INTO headers(header_dict) SELECT * \
                            FROM (SELECT %s) AS tmp  WHERE NOT EXISTS \
                            (SELECT 1 FROM headers WHERE header_dict \
                            = %s LIMIT 1)",(result[6],result[6]))
        db_cursor.execute("INSERT INTO directories(subdomain_id,port,tls,\
                            path,status_code,size,source_code_id,header_id,\
                            source) VALUES (%s,%s,%s,'/',%s,%s,\
                            (SELECT source_code_id FROM source_codes \
                            WHERE source_code = %s),(SELECT header_id \
                            FROM headers WHERE header_dict = %s),'forced')",\
                            result)
    db.commit()

    print("#check redirections")
    for _ in range(max_http_redirection):
        db_cursor.execute("SELECT header_dict FROM headers")
        for result in db_cursor.fetchall():
            if(result[0] == None):
                continue
            headers = ast.literal_eval(result[0])
            if(headers.get("location") == None):
                continue
            redirection = headers.get("location")
            redirection_domain = \
                            tldextract.extract(redirection).registered_domain
            if(redirection_domain in targets):
                parsed_url = parse.urlsplit(redirection)
                db_cursor.execute(f"SELECT EXISTS (SELECT 1 FROM subdomains \
                                    WHERE hostname = %s LIMIT 1)",\
                                    (parsed_url.netloc,))
                if(db_cursor.fetchall()[0] == 0):
                    print(74234) #add_subdomain() #todo
                    continue
                if(":" in parsed_url.netloc):
                    port = int(parsed_url.netloc.split(":")[1])
                elif(parsed_url.scheme == "http"):
                    port = 80
                else:
                    port = 443
                tls = 1 if parsed_url.scheme == "https" else 0
                db_cursor.execute("SELECT 1 FROM directories WHERE \
                                    (subdomain_id = (SELECT subdomain_id FROM\
                                    subdomains WHERE hostname = %s) AND port \
                                    = %s AND tls = %s AND path = %s) \
                                    LIMIT 1",(parsed_url.netloc,port,tls,\
                                    parsed_url.path))
                if(len(db_cursor.fetchall()) == 1):
                    continue
                req,response = http_requests.request(redirection,\
                                    http_req_timeout,http_rcv_timeout,\
                                    max_http_size,\
                                    max_http_retries)
                if(req == -1):
                    continue
                db_cursor.execute("INSERT INTO source_codes(source_code) \
                                    SELECT * FROM (SELECT %s) AS tmp  WHERE \
                                    NOT EXISTS (SELECT 1 FROM source_codes \
                                    WHERE source_code = %s) LIMIT 1",\
                                    (response,response))
                db_cursor.execute("INSERT INTO headers(header_dict) SELECT * \
                                    FROM (SELECT %s) AS tmp  WHERE NOT EXISTS\
                                    (SELECT 1 FROM headers WHERE header_dict \
                                    = %s) LIMIT 1",\
                                    (str(req.headers),str(req.headers)))
                db_cursor.execute("INSERT INTO directories(subdomain_id,port,\
                                    tls,path,status_code,size,source_code_id,\
                                    header_id,source) VALUES ((SELECT \
                                    subdomain_id FROM subdomains WHERE \
                                    hostname = %s LIMIT 1),%s,%s,%s,\
                                    %s,%s,(SELECT source_code_id FROM \
                                    source_codes WHERE source_code = %s),\
                                    (SELECT header_id FROM headers WHERE \
                                    header_dict = %s),'redirection')",\
                                    (parsed_url.netloc,port,tls,\
                                    parsed_url.path,req.status_code,\
                                    len(response),response,str(req.headers)))
        db.commit()
    
    print("#create url list")
    db_cursor.execute("SELECT sbd.hostname,port,tls,path FROM directories AS\
                        dir INNER JOIN subdomains AS sbd ON sbd.subdomain_id\
                        = dir.subdomain_id")
    with open("urls","w") as url_list:
        for parameters in db_cursor.fetchall():
            hostname = parameters[0]
            port = parameters[1]
            protocol = "https://" if parameters[2] == 1 else "http://"
            path = parameters[3]
            url_list.write("{}{}:{}{}\n".format(protocol,hostname,port,path))
    
    print("#run nuclei")
    _ = run_command(f"nuclei -l urls -t {nuclei_templates} -o nuclei-output\
               -json -nc -vv -r {resolvers} -env-vars -rl {max_http_rps} \
               -bs {nuclei_bulksize} -c {nuclei_concurrency} -timeout \
               {http_req_timeout} -retries {max_http_retries} -project \
               -project-path log/")

    print("#parse nuclei")
    with open("nuclei-output","r") as nuclei_output:
        results = nuclei_output.read().split("\n")[:-1]
    for result in results:
        result = json.loads(result)
        vulnerability,severity,url = result['templateID'], \
                                    result['info']['severity'],\
                                    result['matched']
        info = ""
        keys = result.keys()
        if("matcher_name" in keys):
            info = result['matcher_name']
        if(result['info']['name'] == "Wappalyzer Technology Detection"):
            if(info == "wordpress"):
                with open("wordpress-urls","a") as wp_file:
                    wp_file.write(url+"\n")
        db_cursor.execute("INSERT INTO vulnerabilities(subdomain_id,endpoint,\
                           vulnerability,info,severity) VALUES ({},'{}','{}',\
                           '{}','{}')"\
                           .format("(SELECT subdomain_id FROM subdomains\
                                    WHERE hostname='{}')".format(parse.\
                                    urlsplit(url).netloc.split(":")[0]),url,\
                                    vulnerability,info,severity))
    db.commit()

    print("#extract emails")
    db_cursor.execute("SELECT source_code FROM source_codes")
    emails = set()
    for source_code in db_cursor.fetchall():
        emails = \
            emails.union(http_extract.extract_emails(source_code[0],targets))
    db_cursor.execute("SELECT header_dict FROM headers")
    for header in db_cursor.fetchall():
        emails = \
            emails.union(http_extract.extract_emails(header[0],targets))
    for email in emails:
        db_cursor.execute("INSERT INTO emails(email_address) VALUES (%s)",\
                            (email,))
    db.commit()

    print("#subdomain takeover")
    services_takeover = Subdomain_Takeover(valid)
    for subdomain in valid.keys():
        source_code = ""
        db_cursor.execute("SELECT sc.source_code FROM directories AS dir \
                            INNER JOIN source_codes AS sc ON \
                            sc.source_code_id = dir.source_code_id \
                            WHERE path = '/' AND subdomain_id = (SELECT \
                            subdomain_id FROM subdomains WHERE hostname = %s)\
                            AND (port = 80 OR port = 443)",(subdomain,))
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

    print("#screenshotting")
    hti = Html2Image(custom_flags=["--virtual-time-budget=10000",\
                                "--hide-scrollbars",\
                                "--default-background-color=FFFFFFFF",\
                                "--headless","--disable-gpu"],\
                output_path="{}/screenshots".format(root_path))
    db_cursor.execute("SELECT source_code,source_code_id FROM source_codes")
    for result in db_cursor.fetchall():
        sc_id = int(random.random()*10000000000)
        hti.screenshot(html_str=result[0],\
                        save_as="{}.png".format(sc_id))
        db_cursor.execute("UPDATE source_codes SET screenshot_path = %s WHERE\
                            source_code_id=%s",("{}/screenshots/{}.png".\
                            format(root_path,sc_id),result[1]))
    db.commit()

    print("#delete")
    to_remove = ["altdns-out","alt-errors","alt-nxdomain-cname", \
                "alt-subdomains","tobrute","t-errors","t-nxdomains", \
                "t-subdomains","amass-out","subfinder-out","subdomains", \
                "errors","nxdomains","ips"]
    for file in to_remove:
        try:
            os.remove(file)
        except FileNotFoundError:
            continue

    print("#close db conn")
    db_cursor.close()
    db.close()
