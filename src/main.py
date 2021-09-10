#!/usr/bin/python

banner = """
    _            _   
   (_)          | |  
    _  __ _ _ __| |_ 
   | |/ _` | '__| __|
   | | (_| | |  | |_ 
   | |\\__,_|_|   \\__|
  _/ |               
 |__/                
-------------------------
Version: beta
Status: {}
Author: apolo2
"""

import subprocess
import os
import sys
import ast
import json
import random
import concurrent.futures
from dataclasses import dataclass

import tldextract
import yaml
from pymysql.connections import Connection
from pymysql.cursors import Cursor
from urllib import parse
from html2image import Html2Image
from requests.structures import CaseInsensitiveDict
from dns import rcode,rdatatype

from modules import dns_query,http_requests
from modules.parse import formatting,massdns,http_extract
from modules.database import db_conn
from modules.subdomain_takeover import SubdomainTakeover


def run_command(
        cmd: str
    ) -> (bytes, bytes):
    """
    Run a command in the default shell and return stdout, stderr.

    :param cmd: command string
    :returns: stdout, stderr as bytes
    """
    cmd = [arg for arg in cmd.split(" ") if arg != ""]
    process = subprocess.Popen(
                    cmd,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE
                )
    stdout, stderr = process.communicate()[0], process.communicate()[1]
    return(stdout,stderr)


@dataclass
class Jart:
    root_path: str = "/",
    domain: str = "",
    resolvers: str = "resolvers.txt",
    trusted_resolvers: str = "",
    brute_wordlist: str = "~/SecLists/Discovery/DNS/big.txt",
    alt_wordlist: str = "~/SecLists/Discovery/DNS/big.txt",
    db_host: str = "localhost",
    db_user: str = "admin",
    db_pass: str = "pass",
    max_http_redirection: int = 7,
    max_dns_retries: int = 3,
    max_http_retries: int = 2,
    http_req_timeout: int = 7,
    http_rcv_timeout: int = 12,
    max_http_size: int = int(10e6),
    nuclei_templates: str = "~/nuclei-templates/",
    max_http_rps: int = 1200,
    nuclei_bulksize: int = 100,
    nuclei_concurrency: int = 30,
    max_http_probe_threads: int = 2048,
    max_dns_query_threads: int = 2048,
    dir_target_wordlists: bool = True,
    dir_target_specific_path_depth: int = 1, 
    dir_excluded_ext: str = "ico,jpg",
    dir_wordlist_path: str = "~/SecLists/Discovery/Web-Content/big.txt", 
    ferox_concurrency: int = 2048,
    http_proxy: str = "",
    https_proxy: str = ""
    db: Connection = None
    db_cursor: Cursor = None
    valid: dict = {}
    nx: dict = {}
    errors: dict = {}

    @property
    def proxies(self):
        """Return a proxy dictionary from http_proxy, https_proxy."""
        _proxies = {
            "http": self.http_proxy,
            "https": self.https_proxy
        }
        return(_proxies)

    @property
    def trusted_resolver_list(self):
        """Read self.trusted_resolvers and returns a list of lines."""
        with open(self.trusted_resolvers, "r") as trusted_resolvers_file:
            return(trusted_resolvers_file.read().split("\n")[:-1])


    def get_dns_id(
            self,
            record: str
        ) -> int:
        """
        Using the current DB, return the first dns_id that is equal to 
        the record.

        :param record: a specific DNS record value to be searched for
        :returns: dns_records.dns_id if the conditions are met
        """
        self.db_cursor.execute(
                            "SELECT dns_id FROM dns_records WHERE record=%s",
                            (record,)
                        )
        result = self.db_cursor.fetchall()
        if(len(result) > 0):
            return(int(result[0][0]))
        return(None)

    def add_service(
            self,
            dns_id: int,
            port: int,
            transport_protocol: str,
            state: str,
            service: str,
            fingerprint: str
        ) -> None:
        """
        In the current DB, insert a new row into services.

        :param dns_id: db.services.dns_id
        :param port: db.services.port
        :param transport_protocol: db.services.transport_protocol
        :param state: db.services.state
        :param service: db.services.service
        :param fingerprint: db.services.fingerprint
        :returns: integer indicating if it was added as a valid record
        """
        if(dns_id == None):
            return(None)
        if(fingerprint == ""):
            fingerprint = "NULL"
        else:
            fingerprint = "'{}'".format(fingerprint.replace("'", "\\'"))
        self.db_cursor.execute(f"""INSERT INTO services (dns_id,port,service,
                            state,transport_protocol,fingerprint) SELECT 
                            {dns_id} AS dns_id, {port} AS port, '{service}' AS
                            service, '{state}' AS state, '{transport_protocol}'
                            AS transport_protocol, {fingerprint} AS fingerprint
                            WHERE NOT EXISTS ( SELECT 1 FROM services WHERE
                            dns_id = {dns_id} AND port = {port} ) LIMIT 1""")
        return

    def add_vulnerability(
            self,
            hostname: str,
            vuln: str
        ) -> None:
        """
        In the current DB, insert a new row into vulnerabilities.

        :param hostname: db.subdomains.hostname
        :param vuln: db.vulnerabilities.vulnerability
        """
        self.db_cursor.execute("""INSERT INTO vulnerabilities(subdomain_id,
                            vulnerability) VALUES ((SELECT subdomain_id FROM
                            subdomains WHERE hostname=%s),%s)""",
                            (hostname, vuln))
        return

    def probe_http(
            self,
            hostname: str,
            port: int,
            subdomain_id: int, 
            http_req_timeout: int,
            http_rcv_timeout: int, 
            max_http_size: int,
            max_http_retries: int,
            proxies: dict
        ) -> tuple:
        """
        Perform a HTTP request to a socket.

        :param hostname: db.subdomains.hostname
        :param port: TCP port
        :param subdomain_id: db.subdomains.subdomain_id
        :param http_req_timeout: timeout to perform a request
        :param http_rcv_timeout: timeout to download the content
        :param max_http_size: max size to be downloaded
        :param max_http_retries: max retries to perform a request
        :param proxies: dictionary containing proxies
        :returns: db.directories.(subdomain_id, port, tls, status_code,
                  size, source, headers) as tuple
        """
        response = http_requests.probe(
                        hostname,
                        port,
                        "/",
                        http_req_timeout,
                        http_rcv_timeout,
                        max_http_size,
                        max_http_retries,
                        proxies
                    )
        if(response[0] != None):
            return(
                subdomain_id,
                port,
                response[3], #tls
                response[0], #status_code
                len(response[1]), #size
                response[1], #source_code
                str(response[2]) #headers
            )
        return((,))

    def initialize_database(self) -> None:
        """Establish a DB connection and create structures."""
        self.db = db_conn.DB_Connection(
                            self.db_host,
                            self.user,
                            self.password
                        ).connect()
        self.self.db_cursor = self.db.cursor()
        self.db_cursor.execute("""CREATE DATABASE IF NOT EXISTS {} CHARACTER 
                                SET = utf8mb4 COLLATE = utf8mb4_unicode_ci"""\
                                .format(domain.replace(".", "_")))
        self.db_cursor.execute("USE {}".format(domain.replace(".", "_")))
        self.db_cursor.execute("SET GLOBAL sql_mode=''")
        self.db_cursor.execute("SET NAMES utf8mb4")
        self.db_cursor.execute("SET character_set_connection=utf8mb4")
        self.db.commit()

        with open("{}/modules/database/create-tables.sql".format(\
                self.root_path)) as queries_file:
            create_table_queries = queries_file.read().split("---")
        for sql_query in create_table_queries:
            self.db_cursor.execute(sql_query)

        targets = {self.domain}
        with open("targets", "w") as targets_file:
            for target in targets:
                targets_file.write(target + "\n")
        for target in targets:
            self.db_cursor.execute("""INSERT INTO targets(hostname) SELECT * 
                                    FROM (SELECT %s) AS tmp WHERE NOT EXISTS (
                                    SELECT 1 FROM targets WHERE hostname=%s 
                                    LIMIT 1)""", (target, target))
        self.db.commit()
        return

    def subfinder(self) -> None:
        """Run projectdiscovery/subfinder."""
        run_command(f"""subfinder -d {self.domain} -all -o subfinder-out
                        -rL {self.resolvers} -timeout 90""")
        return

    def amass(self) -> None:
        """Run OWASP/Amass."""
        run_command(f"""amass enum -active -rf {self.resolvers} -d 
                        {self.domain} -o amass-out -passive -nf 
                        subfinder-out""")
        return

    def validate_base_subdomains(self) -> None:
        """Run blechschmidt/massdns against possible subdomains."""
        run_command(f"""massdns -r {self.resolvers} -w massdns-resolve-out -o
                        Srmldni amass-out -s 20000 --root""")
        return

    def brute_subdomains(self):
        """
        Generate a list of subdomains using self.brute_wordlist,
        run blechschmidt/massdns against it. Run infosec-au/altdns and
        blechschmidt/massdns against valid subdomains.
        """
        with open("tobrute", "w") as brute_file:
            for parameter in open(self.brute_wordlist,"r"):
                _ = brute_file.write("{}.{}\n".format(
                                                parameter.replace("\n", ""),
                                                domain))

        run_command(f"""massdns -r {self.resolvers} -w massdns-brute-out 
                            -o Srmldni tobrute -s 20000 --root""")

        with open("massdns-resolve-out", "r") as resolve_out,\
            open("massdns-brute-out", "r") as brute_out,\
            open("t-subdomains", "w") as valid_join, open("t-nxdomains", "w")\
            as nxdomain_join, open("t-errors", "w") as errors_join:
                lines = resolve_out.read().split("\n")\
                        + brute_out.read().split("\n")
                valid, nxdomain, errors = massdns.load(lines)
                valid_join.write("\n".join(list(valid.keys())))
                nxdomain_join.write("\n".join(nxdomain))
                errors_join.write("\n".join(errors))

        run_command(f"""altdns -i t-subdomains -o altdns-out -w
                            {self.alt_wordlist}""")
        run_command(f"""massdns -r {self.resolvers} -w massdns-alt-out -o
                            Srmldni altdns-out -s 200000 --root""")

    def consolidate_subdomains(self) -> None:
        """
        Perform DNS queries to categorize a subdomain. Join subdomains 
        and its info into files/dictionaries.
        """
        with open("massdns-alt-out", "r") as alt_out,\
            open("subdomains", "w") as valid_join,\
            open("nxdomains", "w") as nxdomain_join,\
            open("errors", "w") as errors_join,\
            open("t-subdomains", "r") as temp_subdomains,\
            open("t-nxdomains", "r") as temp_nxdomains,\
            open("t-errors", "r") as temp_errors:
                alt_lines = alt_out.read().split("\n")
                alt_valid, alt_nxdomain, alt_errors = massdns.load(alt_lines)
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
                    valid_join.write(domain + "\n")
                for domain in nxdomain:
                    nxdomain_join.write(domain + "\n")
                for domain in error:
                    if(domain not in valid):
                        errors_join.write(domain + "\n")

        run_command(f"""massdns -r {self.trusted_resolvers} -w 
                            massdns-ns-out -t NS -o Srmldni errors -s 20000
                            --root""")

        with open("subdomains", "a+") as subdomains_file,\
            open("massdns-alt-out", "r") as alt_out,\
            open("massdns-brute-out", "r") as brute_out,\
            open("massdns-ns-out", "r") as ns_out,\
            open("massdns-resolve-out", "r") as resolve_out:
            subdomains_lines = subdomains_file.read().split("\n")
            ns_lines = ns_out.read().split("\n")
            self.valid, self.nx, errors = massdns.load(
                                            alt_out.read().split("\n")
                                            + brute_out.read().split("\n")
                                            + resolve_out.read().split("\n")
                                          )
            massdns_ns = massdns.load(ns_lines)
            ns_valid = massdns_ns[0]
            ns_records = massdns_ns
            self.errors = dict()
            for subdomain in list(ns_records[0].keys()):
                if(subdomain not in subdomains_lines):
                    resolver = random.choice(self.trusted_resolver_list)
                    query_result = dns_query.process_query(
                                        resolver,
                                        subdomain,
                                        rdatatype.A,
                                        max_dns_retries
                                    )
                    code = rcode.to_text(query_result[0])
                    if(query_result[1] != "" and query_result[0] == 0):
                        answers = set()
                        for answer in query_result[1].split("\n"):
                            answer = answer.split(" ")[4]
                            if(answer[-1:] == "."):
                                answer = answer[:-1]
                            answers.add(answer)
                        self.valid[subdomain] = (code, answers)
                    else:
                        if(code in ["SERVFAIL","REFUSED"]):
                            self.errors[subdomain] = (
                                                        code,
                                                        ns_valid[subdomain][1]
                                                     )
    return

    def consolidate_dns(self) -> None:
        """
        Add DNS information into the DB. Perform different types of 
        queries, treat it and add their data into the DB.
        """
        for classification in [self.valid, self.nx, self.errors]:
            for key in classification.keys():
                db_cursor.execute("""INSERT INTO subdomains(hostname) VALUES 
                                    (%s)""", (key,))
                db_cursor.execute("""SELECT subdomain_id FROM subdomains WHERE
                                    hostname=%s""", (key,))
                subdomain_id = self.db_cursor.fetchall()[0]
                for ip_cname in classification[key][1]:
                    query_question = "A" if formatting.is_ipv4(ip_cname)
                                    else "CNAME"
                    if(classification == self.errors):
                        query_question = "NS"
                    query_rcode = classification[key][0]
                    self.db_cursor.execute("""INSERT INTO dns_records(record,
                                            type,rcode) SELECT * FROM (SELECT
                                            %s,%s,%s) AS tmp WHERE NOT EXISTS 
                                            (SELECT 1 FROM dns_records WHERE 
                                            record=%s AND type=%s LIMIT 1)""",
                                            (
                                                ip_cname, 
                                                query_question,
                                                query_rcode, 
                                                ip_cname, 
                                                query_question
                                            ))
                    self.db_cursor.execute("""INSERT INTO dns_link(
                                            subdomain_id,dns_id) VALUES (%s,
                                            (SELECT dns_id FROM dns_records
                                            WHERE record=%s))""",
                                            (subdomain_id, ip_cname))
        self.db.commit()

        self.db_cursor.execute("""SELECT dns_id,record FROM dns_records WHERE 
                                (type='CNAME')""")
        for result in self.db_cursor.fetchall():
            dns_id, ips = result[0], [result[1]]
            while(not formatting.is_ipv4(ips[0])):
                resolver = random.choice(self.trusted_resolver_list)
                ip_query = dns_query.process_query(
                                resolver,
                                ips[0],
                                rdatatype.A,
                                self.max_dns_retries
                            )
                if(ip_query[1] == ""):
                    db_cursor.execute("""DELETE FROM cname_resolutions WHERE
                                        dns_id=%s""", (dns_id,))
                    break
                ips = []
                for record in ip_query[1].split("\n")[-1:]:
                    ips.append(record.split(" ")[4])
                for ip in ips:
                    if(ip[-1:] == "."):
                        ip = ip[:-1]
                    self.db_cursor.execute("""INSERT INTO cname_resolutions
                                            (dns_id,record) VALUES (%s,%s)""",
                                            (dns_id, ip))
        self.db.commit()

        def dns_parsed_query(hostname: str, query_question: int) -> list:
            """
            Perform a DNS query and return its parsed answer.

            :param hostname: hostname to be questioned
            :param query_question: DNS question
            :returns: hostname, DNS question, DNS answer, DNS SOA, rcode
            """
            rlist = [] 
            question_str = rdatatype.to_text(query_question)
            resolver = random.choice(self.trusted_resolver_list)
            query_result = dns_query.process_query(
                                resolver,
                                hostname, 
                                query_question,
                                self.max_dns_retries
                            )
            if(question_str in query_result[1]):
                for rec in [trec.split("\n")[0][:-1] for trec in 
                            query_result[1].split(f"IN {question_str} ")[1:]]:
                    if(question_str == "MX"):
                        rlist.append(
                            [
                                hostname,
                                question_str,
                                rec.split(" ")[1],
                                query_result[2],
                                rcode.to_text(query_result[0])
                            ]
                        )
                    else:
                        rlist.append(
                            [
                                hostname,
                                question_str,
                                rec,
                                query_result[2],
                                rcode.to_text(query_result[0])
                            ]
                        )
            else:
                rlist.append([None, None, None, query_result[2]])
            return(rlist)

        with open("{}/modules/database/select-up_subdomains.sql".format(\
                self.root_path)) as queries_file:
            select_query = "\n".join(queries_file.read().split("\n")[1:])

        self.db_cursor.execute(select_query)
        records = []

        def append_dns_record(hostname: str, query_questions: list) -> None:
            """
            For each question, add its answer into a list of records.

            :param hostname: hostname to be questioned
            :param query_questions: list of DNS question types
            """
            for question in query_questions:
                records.append(dns_parsed_query(hostname, question))
            return

        with concurrent.futures.ThreadPoolExecutor(
                                    max_workers=self.max_dns_query_threads
                                ) as executor:
            threads = {
                executor.submit(
                    append_dns_record,
                    result[0],
                    [
                        rdatatype.NS,
                        rdatatype.MX,
                        rdatatype.TXT,
                        rdatatype.SRV,
                        rdatatype.AAAA,
                        rdatatype.HINFO
                    ]
                ): result for result in self.db_cursor.fetchall()
            }

        for record in records:
            for sr in record:
                if(sr[0] != None):
                    self.db_cursor.execute("""INSERT INTO dns_records(record,
                                            type,rcode) SELECT %s AS record, 
                                            %s AS type, %s AS rcode WHERE NOT 
                                            EXISTS ( SELECT 1 FROM dns_records
                                            WHERE record=%s AND type=%s )""",
                                            (
                                                sr[2], 
                                                sr[1], 
                                                sr[4], 
                                                sr[2], 
                                                sr[1]
                                            ))
                    self.db_cursor.execute("""SELECT subdomain_id FROM 
                                            subdomains WHERE hostname=%s""",
                                            (sr[0],))
                    subdomain_id = self.db_cursor.fetchall()[0]
                    self.db_cursor.execute("""INSERT INTO dns_link(
                                            subdomain_id,dns_id) VALUES (%s, 
                                            (SELECT dns_id FROM dns_records 
                                            WHERE record=%s))""", 
                                            (subdomain_id, sr[2]))
                if(sr[3] != "" and sr[3] != []):
                    email = sr[3][0].to_text().split()[5][:-1]
                    email_domain = tldextract.extract(email).registered_domain
                    if(email_domain in targets):
                        email = "{}@{}".format(email.split("." + 
                                               email_domain)[0], email_domain)
                        self.db_cursor.execute("""INSERT INTO emails(
                                                email_address) SELECT %s AS 
                                                email_address WHERE NOT EXISTS
                                                ( SELECT 1 FROM emails WHERE
                                                email_address=%s )""",
                                                (email, email))
        self.db.commit()
        return

    def service_scan(self) -> None:
        """
        Use robertdavidgraham/masscan and nmap to detect services; add
        them to the DB.
        """
        with open("{}/modules/database/select-hostname_ipv4.sql".format(\
                self.root_path)) as queries_file:
            hostname_ipv4_queries = queries_file.read().split("---")
        with open("ips", "w") as ips_file:
            ip_cname_link  = dict()
            for sql_query in hostname_ipv4_queries:
                self.db_cursor.execute(sql_query)
                for result in self.db_cursor.fetchall():
                    if(result[1] not in ip_cname_link.keys()):
                        ip_cname_link[result[1]] = []
                    ip_cname_link[result[1]].append(result[0])
            for ip in ip_cname_link.keys():
                ips_file.write(ip + "\n")

        run_command("""nmap -T4 --min-hostgroup 128 --max-hostgroup 2048
                      --host-timeout 30m -max-retries 7 -sSV -oG nmap-out -v
                      --open -iL ips --top-ports 2000 -n""")

        run_command("masscan -iL ips -p- --rate 20000 -oG masscan-out")

        with open("nmap-out", "r") as nmap_file:
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
                                self.add_service(
                                    self.get_dns_id(record),
                                    port,
                                    transport_protocol,
                                    state,
                                    service,
                                    fingerprint
                                )
        self.db.commit()

        with open("masscan-out", "r") as masscan_file:
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
                        self.add_service(
                            self.get_dns_id(record),
                            port,
                            transport_protocol,
                            state,
                            service,
                            ""
                        )
        self.db.commit()
    return

    def fuzz_webservers(self) -> None:
        """Use self.probe_http and get webpages; add them to the DB."""
        self.db_cursor.execute("""SELECT sbd.hostname,svc.port,
                                dnl.subdomain_id FROM subdomains AS sbd INNER 
                                JOIN dns_link AS dnl ON sbd.subdomain_id=
                                dnl.subdomain_id INNER JOIN services
                                AS svc ON svc.dns_id=dnl.dns_id""")
        results = []
        with concurrent.futures.ThreadPoolExecutor(
                                    max_workers=self.max_http_probe_threads
                                ) as executor:
            threads = {
                executor.submit(
                    self.probe_http,
                    result[0],
                    result[1],
                    result[2],
                    self.http_req_timeout,
                    self.http_rcv_timeout,
                    self.max_http_size,
                    self.max_http_retries,
                    self.proxies
                ): result for result in self.db_cursor.fetchall()
            }
            for thread in threads:
                result = thread.result()
                if(result != (,)):
                    results.append(result)

        for result in results:
            self.db_cursor.execute("""INSERT INTO source_codes(source_code) 
                                    SELECT * FROM (SELECT %s) AS tmp  WHERE 
                                    NOT EXISTS (SELECT 1 FROM source_codes 
                                    WHERE source_code = %s LIMIT 1)""", 
                                    (result[5], result[5]))
            self.db_cursor.execute("""INSERT INTO headers(header_dict) SELECT 
                                    * FROM (SELECT %s) AS tmp  WHERE NOT 
                                    EXISTS (SELECT 1 FROM headers WHERE 
                                    header_dict = %s LIMIT 1)""",
                                    (result[6], result[6]))
            self.db_cursor.execute("""INSERT INTO directories(subdomain_id,
                                    port,tls,path,status_code,size,
                                    source_code_id,header_id,source) VALUES 
                                    (%s,%s,%s,'/',%s,%s,(SELECT source_code_id
                                    FROM source_codes WHERE source_code = %s),
                                    (SELECT header_id FROM headers WHERE 
                                    header_dict = %s),'forced')""",
                                    result)
        self.db.commit()

        for _ in range(self.max_http_redirection):
            self.db_cursor.execute("SELECT header_dict FROM headers")
            for result in self.db_cursor.fetchall():
                if(result[0] == None):
                    continue
                headers = ast.literal_eval(result[0])
                if(headers.get("location") == None):
                    continue
                redirection = headers.get("location")
                redirection_domain = tldextract.extract(redirection).\
                                                        registered_domain
                if(redirection_domain in targets):
                    parsed_url = parse.urlsplit(redirection)
                    self.db_cursor.execute(f"""SELECT EXISTS (SELECT 1 FROM 
                                            subdomains WHERE hostname = %s 
                                            LIMIT 1)""",
                                            (parsed_url.netloc,))
                    if(self.db_cursor.fetchall()[0] == 0):
                        print(74234) #todo - add_subdomain()
                        continue
                    if(":" in parsed_url.netloc):
                        port = int(parsed_url.netloc.split(":")[1])
                    elif(parsed_url.scheme == "http"):
                        port = 80
                    else:
                        port = 443
                    tls = 1 if parsed_url.scheme == "https" else 0
                    self.db_cursor.execute("""SELECT 1 FROM directories WHERE
                                            (subdomain_id = (SELECT 
                                            subdomain_id FROM subdomains WHERE
                                            hostname = %s) AND port = %s AND 
                                            tls = %s AND path=%s) LIMIT 1""",
                                            (
                                                parsed_url.netloc, 
                                                port, 
                                                tls,
                                                parsed_url.path
                                            ))
                    if(len(self.db_cursor.fetchall()) == 1):
                        continue
                    req, response = http_requests.request(
                                                        redirection,
                                                        self.http_req_timeout,
                                                        self.http_rcv_timeout,
                                                        self.max_http_size, 
                                                        self.max_http_retries,
                                                        self.proxies
                                                    )
                    if(req == None):
                        continue
                    self.db_cursor.execute("""INSERT INTO source_codes(
                                            source_code) SELECT * FROM (SELECT
                                            %s) AS tmp  WHERE NOT EXISTS (
                                            SELECT 1 FROM source_codes WHERE 
                                            source_code = %s) LIMIT 1""",
                                            (response, response))
                    self.db_cursor.execute("""INSERT INTO headers(header_dict)
                                            SELECT * FROM (SELECT %s) AS tmp  
                                            WHERE NOT EXISTS (SELECT 1 FROM 
                                            headers WHERE header_dict = %s) 
                                            LIMIT 1""", 
                                            (
                                                str(req.headers), 
                                                str(req.headers)
                                            ))
                    hostname = parsed_url.netloc.split(":")[0]
                    self.db_cursor.execute("""INSERT INTO directories(
                                            subdomain_id,port,tls,path,
                                            status_code,size,source_code_id,
                                            header_id,source) VALUES ((SELECT
                                            subdomain_id FROM subdomains WHERE
                                            hostname = %s LIMIT 1),%s,%s,%s,
                                            %s,%s,(SELECT source_code_id FROM
                                            source_codes WHERE source_code = 
                                            %s), (SELECT header_id FROM 
                                            headers WHERE header_dict = %s),
                                            'redirection')""",
                                            (
                                                hostname, 
                                                port, 
                                                tls, 
                                                parsed_url.path,
                                                req.status_code, 
                                                len(response), 
                                                response,
                                                str(req.headers)
                                            ))
            self.db.commit()

        self.db_cursor.execute("""SELECT sbd.hostname,port,tls,path FROM 
                                directories AS dir INNER JOIN subdomains AS 
                                sbd ON sbd.subdomain_id = dir.subdomain_id""")
        with open("urls", "w") as url_list:
            for parameters in self.db_cursor.fetchall():
                hostname = parameters[0]
                port = parameters[1]
                protocol = "https://" if parameters[2] == 1 else "http://"
                path = parameters[3]
                url_list.write("{}{}:{}{}\n".format(
                                                        protocol, 
                                                        hostname, 
                                                        port, 
                                                        path
                                                    ))
        return

    def nuclei(self) -> None:
        """
        Run projectdiscovery/nuclei; filter detected vulns and add them 
        to the DB.
        """
        run_command(f"""nuclei -l urls -t {self.nuclei_templates} -o 
                        nuclei-output -json -nc -vv -r {self.resolvers} 
                        -env-vars -rl {self.max_http_rps} -bs 
                        {self.nuclei_bulksize} -c {self.nuclei_concurrency} 
                        -timeout {self.http_req_timeout} -retries {
                        self.max_http_retries} -project -project-path log/""")

        with open("nuclei-output", "r") as nuclei_output:
            results = nuclei_output.read().split("\n")[:-1]
        for result in results:
            result = json.loads(result)
            vulnerability, severity, url = result["templateID"],\
                                           result["info"]["severity"],\
                                           result["matched"]
            info = ""
            keys = result.keys()
            if("matcher_name" in keys):
                info = result["matcher_name"]
            if(result["info"]["name"] == "Wappalyzer Technology Detection"):
                if(info == "wordpress"):
                    with open("wordpress-urls", "a") as wp_file:
                        wp_file.write(url + "\n")
            self.db_cursor.execute("""INSERT INTO vulnerabilities(
                                    subdomain_id,endpoint,vulnerability,info,
                                    severity) VALUES ({},"{}","{}","{}","{}"
                                    )""".format(
                                        """(SELECT subdomain_id FROM
                                        subdomains WHERE hostname='{}')""".\
                                        format(parse.urlsplit(url).\
                                        netloc.split(":")[0]),
                                        url,
                                        vulnerability, 
                                        info, 
                                        severity
                                    ))
        self.db.commit()
        return

    def filter_emails(self) -> None:
        """
        Use regular expressions to filter emails from database data and
        add them to the database.
        """
        self.db_cursor.execute("SELECT source_code FROM source_codes")
        emails = set()
        for source_code in self.db_cursor.fetchall():
            emails = emails.union(http_extract.extract_emails(
                                                    source_code[0],
                                                    self.targets
                                                ))
        self.db_cursor.execute("SELECT header_dict FROM headers")
        for header in self.db_cursor.fetchall():
            emails = emails.union(http_extract.extract_emails(
                                                    header[0], 
                                                    targets
                                                ))
        for email in emails:
            self.db_cursor.execute("""INSERT INTO emails(email_address) VALUES
                                    (%s)""", (email,))
        self.db.commit()
        return

    def check_subdomain_takeover(self) -> None:
        """
        Use SubdomainTakeover class to check possible subdomain 
        takeovers; if any subdomain is vulnerable, add it to the DB.
        """
        services_takeover = SubdomainTakeover(
                                random.choice(self.resolver_list), 
                                self.valid
                            )
        for subdomain in self.valid.keys():
            source_code = ""
            self.db_cursor.execute("""SELECT sc.source_code FROM directories 
                                    AS dir INNER JOIN source_codes AS sc ON
                                    sc.source_code_id = dir.source_code_id
                                    WHERE path = "/" AND subdomain_id = (
                                    SELECT subdomain_id FROM subdomains WHERE 
                                    hostname = %s) AND (port = 80 OR port = 
                                    443)""", (subdomain,))
            for code in self.db_cursor.fetchall():
                source_code += code[0]
            result = services_takeover.check_body_cname(subdomain, source_code)
            if(result != ""):
                self.add_vulnerability(subdomain, formatting.\
                                        normalize_whitespaces(f"""[SUBDOMAIN 
                                        TAKEOVER] SVC {result}"""))
            mx_result = services_takeover.check_mx(subdomain)
            if(len(mx_result) > 0):
                self.add_vulnerability(subdomain, formatting.\
                                        normalize_whitespaces(f"""[SUBDOMAIN 
                                        TAKEOVER] MX {mx_result}"""))
        self.db.commit()
        services_nx_takeover = SubdomainTakeover(
                                    random.choice(resolver_list), 
                                    self.nx
                                )
        for subdomain in self.nx.keys():
            result = services_nx_takeover.check_cname(subdomain)
            if(result != ""):
                self.add_vulnerability(subdomain, formatting.\
                                        normalize_whitespaces(f"""[SUBDOMAIN 
                                        TAKEOVER] NX {result}"""))
        self.db.commit()
        services_ns_takeover = SubdomainTakeover(random.choice(resolver_list))
        for subdomain in self.errors.keys():
            for ns in self.errors[subdomain][1]:
                ns = tldextract.extract(ns).registered_domain
                result = services_ns_takeover.check_nxdomain(ns)
                if(result):
                    self.add_vulnerability(subdomain,formatting.\
                                            normalize_whitespaces(
                                            f"""[SUBDOMAIN TAKEOVER] NX NS 
                                            {result}"""))
        self.db.commit()
        return

    def fuzz_directories(self) -> None:
        """
        Use self.dir_wordlist_path and getallurls to create a list of
        possible directories. Use epi052/feroxbuster to fuzz those dirs.
        """
        if(self.dir_target_wordlists):
            p1 = subprocess.Popen(["cat", "targets"],stdout=subprocess.PIPE)
            p2 = subprocess.Popen(["getallurls", "-subs", "-o", "waybackurls"],
                                    stdin=p1.stdout, stdout=subprocess.PIPE)
            p2.communicate()
            exts = self.dir_excluded_ext.split(",")
            paths = set()
            with open("waybackurls", "r") as wayback_urls_file:
                for url in wayback_urls_file.read().split("\n"):
                    depth = 0
                    for urlpath in url.split("://")[1:]:
                        if(depth == self.dir_target_specific_path_depth):
                            depth = 0
                        for path in urlpath.split("?")[0].split("/")[1:]:
                            skip = False
                            for ext in exts:
                                if(path.endswith(f".{ext}")):
                                    skip = True
                                    break
                            if(skip):
                                continue
                            paths.add(path)
                            depth += 1
                            if(depth == self.dir_target_specific_path_depth):
                                break

        with open(self.dir_wordlist_path) as wl_file:
            for path in wl_file.read().split("\n"):
                paths.add(path)
        with open("dir_wordlist", "w") as wl_file:
            for path in paths:
                wl_file.write(path + "\n")

        p1 = subprocess.Popen(["cat", "urls"],stdout=subprocess.PIPE)
        with subprocess.Popen(["feroxbuster", "--stdin", "-w", "dir_wordlist",
                                "--parallel", str(self.ferox_concurrency)],
                                stdin=p1.stdout, stdout=subprocess.PIPE,
                                bufsize=1, universal_newlines=True) as p2:
            for line in p2.stdout:
                if(line != "\n"):
                    #print(line[:-1])
                    pass
        return

    def screenshot(self) -> None:
        """Take a screenshot of every source_code and add to the DB."""
        hti = Html2Image(
            custom_flags = [
                "--virtual-time-budget=10000",
                "--hide-scrollbars",
                "--default-background-color=FFFFFFFF",
                "--headless",
                "--disable-gpu"
            ],
            output_path = "{}/screenshots".format(self.root_path)
        )
        self.db_cursor.execute("""SELECT source_code,source_code_id FROM 
                                source_codes""")
        for result in self.db_cursor.fetchall():
            sc_id = int(random.random()*10000000000)
            hti.screenshot(
                    html_str = result[0], 
                    save_as = "{}.png".format(sc_id)
                )
            self.db_cursor.execute("""UPDATE source_codes SET screenshot_path 
                                    = %s WHERE source_code_id=%s""",
                                    ("{}/screenshots/{}.png".format(
                                    self.root_path, sc_id), result[1]))
        self.db.commit()
        return

    def remove(self) -> None:
        """Remove some used files."""
        to_remove = [
            "altdns-out",
            "alt-errors",
            "alt-nxdomain-cname",
            "alt-subdomains",
            "tobrute",
            "t-errors",
            "t-nxdomains",
            "t-subdomains",
            "amass-out",
            "subfinder-out",
            "ips"
        ]
        for file in to_remove:
            try:
                os.remove(file)
            except FileNotFoundError:
                continue
        return

    def close(self) -> None:
        """Close the DB connection."""
        self.db_cursor.close()
        self.db.close()
        return


if __name__ == "__main__":
    os.system("cls||clear")
    print(banner)
    if(os.geteuid() != 0):
        print("nmap/masscan requires sudo.")
        sys.exit(1)
    if(os.path.isfile("config.yaml")):
        with open("config.yaml") as config_file:
            config = yaml.load(config_file.read(), Loader = yaml.CLoader)
            scanner = Jart(**config)
    else:
        scanner = Jart()
    scanner.initialize_database()
    scanner.subfinder()
    scanner.amass()
    scanner.validate_base_subdomains()
    scanner.brute_subdomains()
    scanner.consolidate_subdomains()
    scanner.consolidate_dns()
    scanner.service_scan()
    scanner.fuzz_webservers()
    scanner.nuclei()
    scanner.filter_emails()
    scanner.check_subdomain_takeover()
    scanner.fuzz_directories()
    scanner.screenshot()
    #scanner.remove()
    scanner.close()
