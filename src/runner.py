#!/usr/bin/python

import main
import yaml

def load_config():
	global domain,resolvers_list,brute_wordlist,alt_wordlist,amass_config
	with open("config.yaml","r") as config_file:
		config = yaml.load(config_file.read(), Loader=yaml.CLoader)

	domain = config["domain"]
	resolvers = config["resolvers"]
	brute_wordlist = config["brute_wordlist"]
	alt_wordlist = config["alt_wordlist"]
	amass_config = config["amass_config"]

load_config()
main.run(domain,resolvers,brute_wordlist,alt_wordlist,amass_config)
