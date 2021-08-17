#!/usr/bin/python

import main
import yaml

def load_config():
	global domain,resolvers,brute_wordlist,alt_wordlist,db_host,db_user,\
	db_pass,scan_external_redirection,max_http_redirection,max_dns_retries\
	max_http_retries,http_req_timeout,http_rcv_timeout,max_http_size

	with open("config.yaml","r") as config_file:
		config = yaml.load(config_file.read(), Loader=yaml.CLoader)

	domain = config["domain"]
	resolvers = config["resolvers"]
	brute_wordlist = config["brute_wordlist"]
	alt_wordlist = config["alt_wordlist"]
	db_host = config["db_host"]
	db_user = config["db_user"]
	db_pass = config["db_pass"]
	scan_external_redirection = config["scan_external_redirection"]
    max_http_redirection = config["max_http_redirection"]
    max_dns_retries = config["max_dns_retries"]
    max_http_retries = config["max_http_retries"]
    http_req_timeout = config["http_req_timeout"]
    http_rcv_timeout = config["http_rcv_timeout"]
    max_http_size = config["max_http_size"]

load_config()
main.run(domain,resolvers,brute_wordlist,alt_wordlist,(db_host,db_user, \
		db_pass),scan_external_redirection,max_http_redirection,\
		max_dns_retries,max_http_retries,http_req_timeout,http_rcv_timeout,\
		max_http_size)
