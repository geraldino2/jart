#!/usr/bin/python

import os
import main

os.system("cls||clear")

domain = "uber.com"
resolvers = "/home/apolo2/.config/resolvers.txt"
brute_wordlist = "/home/apolo2/SecLists/Discovery/DNS/dns-The-Biggest.txt"
alt_wordlist = "/home/apolo2/SecLists/Discovery/DNS/small-alt.txt"
amass_config = "/home/apolo2/Desktop/config.ini"

main.run(domain,resolvers,brute_wordlist,alt_wordlist,amass_config)
