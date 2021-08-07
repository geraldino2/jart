import subprocess
import os
import mysql
from dns import rcode
from modules.parse import massdns
from modules import dns_query
from modules import database

def run_command(cmd:str) -> (bytes,bytes,bytes):
    cmd = [arg for arg in cmd.split(" ") if arg != ""]
    process = subprocess.Popen(cmd,stdout=subprocess.PIPE,
                                stderr=subprocess.PIPE)
    return(process.communicate()[0],process.communicate()[1])

def run(domain:str,resolvers:str,brute_wordlist:str,alt_wordlist:str,\
        amass_config:str,db_credentials:tuple):
    os.system("cls||clear")

    print("#subfinder")
    _ = run_command(f"subfinder -d {domain} -all -o subfinder-out\
                -rL {resolvers} -timeout 90")

    print("#amass")
    _ = run_command(f"amass enum -active -config {amass_config} -rf \
                    {resolvers} -d {domain} -o amass-out\
                    -passive -nf subfinder-out")

    print("#massdns - resolve")
    _ = run_command(f"massdns -r {resolvers} -w massdns-resolve-out -o \
        Srmldni amass-out -s 20000")

    print("#create brute_wordlist")
    with open("tobrute","w") as saida:
        for parametro in open(brute_wordlist,"r"):
            _ = saida.write("{}.{}\n".format(parametro.replace("\n",""), \
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
            print(len(valid))

    print("#massdns - ns")
    _ = run_command(f"massdns -r /home/apolo2/.config/trusted-resolvers.txt -w massdns-ns-out -t NS -o \
        Srmldni errors -s 20000")

    print("#parsing")
    with open("subdomains","a+") as subdomains_file, \
        open("massdns-alt-out","r") as alt_out, \
        open("massdns-brute-out","r") as brute_out, \
        open("massdns-ns-out","r") as ns_out, \
        open("massdns-resolve-out","r") as resolve_out:
        lines = subdomains_file.read().split("\n")
        ns_lines = ns_out.read().split("\n")
        valid,nx,errors = massdns.load \
                            (alt_out.read().split("\n") + \
                            brute_out.read().split("\n") + \
                            resolve_out.read().split("\n") + \
                            ns_lines)
        errors = set()
        ns_records = massdns.load(ns_lines)
        for subdomain in list(ns_records[0].keys()):
            if(subdomain not in lines):
                query_result = dns_query.process_query("1.1.1.1",subdomain,1)
                if(query_result[1]!="" and query_result[0] == 0):
                    answers = set()
                    for answer in query_result[1].split("\n"):
                        answers.add(answer)
                    valid[subdomain] = (rcode.to_text(query_result[0]),\
                                        answers)
                else:
                    errors.add(subdomain)
    ip_cnames = set()
    for pair in ([ip_cname[1] for ip_cname in list(valid.values())]):
        for value in pair:
            ip_cnames.add(value)

    print("#database")
    db = database.DB_Connection( \
        db_credentials[0],db_credentials[1],db_credentials[2]).connect()
    db_cursor = db.cursor()
    db_cursor.execute(f"CREATE DATABASE {domain.replace('.','_')}")
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
                        subdomain_id INTEGER, fingerprint VARCHAR(1024), \
                        PRIMARY KEY (dns_id, port), FOREIGN KEY (dns_id) \
                        REFERENCES ip_cnames(dns_id), FOREIGN KEY \
                        (subdomain_id) REFERENCES subdomains(subdomain_id))")
    db_cursor.execute("CREATE TABLE vulnerabilities (vulnerability_id INTEGER\
                        AUTO_INCREMENT, subdomain_id INTEGER NOT NULL, \
                        vulnerability VARCHAR(1024), PRIMARY KEY \
                        (vulnerability_id, subdomain_id), FOREIGN KEY \
                        (subdomain_id) REFERENCES subdomains(subdomain_id))")
    db_cursor.execute("CREATE TABLE directories (directory_id INTEGER \
                        AUTO_INCREMENT, subdomain_id INTEGER NOT NULL, \
                        path VARCHAR(2083) NOT NULL, status_code INTEGER, \
                        size INTEGER, PRIMARY KEY (directory_id), \
                        FOREIGN KEY (subdomain_id) \
                        REFERENCES subdomains(subdomain_id))")
    ip_cnames_str = ""
    for value in ip_cnames:
        ip_cnames_str += f" ('{value}'),"
    db_cursor.execute(f"INSERT INTO ip_cnames(record) \
                    VALUES{ip_cnames_str[:-1]}")
    db.commit()

    print("#delete")
    to_remove = ["altdns-out","alt-errors","alt-nxdomain-cname", \
                "alt-subdomains","tobrute","t-errors","t-nxdomains", \
                "t-subdomains","amass-out","subfinder-out","subdomains", \
                "errors","nxdomains"]
    for file in to_remove:
        try:
            os.remove(file)
        except FileNotFoundError:
            pass
