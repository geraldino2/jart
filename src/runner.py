#!/usr/bin/python

import main
import yaml

def load_config():
	global domain,resolvers,brute_wordlist,alt_wordlist,\
	db_host,db_user,db_pass
	with open("config.yaml","r") as config_file:
		config = yaml.load(config_file.read(), Loader=yaml.CLoader)

	domain = config["domain"]
	resolvers = config["resolvers"]
	brute_wordlist = config["brute_wordlist"]
	alt_wordlist = config["alt_wordlist"]
	db_host = config["db_host"]
	db_user = config["db_user"]
	db_pass = config["db_pass"]

load_config()
main.run(domain,resolvers,brute_wordlist,alt_wordlist,\
		(db_host,db_user,db_pass))
