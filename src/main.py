#!/usr/bin/python

import subprocess
import os
from parse import massdns

domain = "uber.com"
resolvers = "/home/apolo2/.config/resolvers.txt"
brute_wordlist = "/home/apolo2/SecLists/Discovery/DNS/dns-The-Biggest.txt"
alt_wordlist = "/home/apolo2/SecLists/Discovery/DNS/small-alt.txt"
amass_config = "/home/apolo2/Desktop/config.ini"

os.system("cls||clear")


def run_command(cmd:str,wait_output:bool=True) -> (bytes,bytes,bytes):
    cmd = [arg for arg in cmd.split(" ") if arg != ""]
    print(cmd)
    process = subprocess.Popen(cmd,stdout=subprocess.PIPE,
                                stderr=subprocess.PIPE)
    if(wait_output):
            return(process.communicate()[0],process.communicate()[1])
    else:
        return()

print("#subfinder")
print(run_command(f"subfinder -d {domain} -all -o subfinder-output\
            -rL {resolvers} -timeout 90"))

print("#amass")
print(run_command(f"amass enum -active -config {amass_config} -rf \
            {resolvers} -d {domain} -o amass-output\
            -passive -nf subfinder-output"))

print("#join | sort | uniq")
with open("subfinder-output","r") as subfinder_output, \
    open("amass-output","r") as amass_output, open("join-1","w") as join:
        comb = list(set(list(subfinder_output) + list(amass_output)))
        join.write("".join(comb))
        subfinder_output.close()
        amass_output.close()


print("#massdns - resolve")
print(run_command(f"massdns -r {resolvers} -w massdns-resolve-output -o \
    Srmldni join-1"))

print("#create brute_wordlist")
with open("tobrute","w") as saida:
    for parametro in open(brute_wordlist,"r"):
        _ = saida.write("{}.{}\n".format(parametro.replace("\n",""),domain))

print("#massdns - brute")
print(run_command(f"massdns -r {resolvers} -w massdns-brute-output -o Srmldni\
    tobrute"))

print("#join | sort | uniq")
with open("massdns-resolve-output","r") as resolve_output, \
    open("massdns-brute-output","r") as brute_output, \
    open("subdomains","w") as valid_join, open("nxdomain-cname","w") \
    as nxdomain_join, open("errors","w") as errors_join, open("teste","w") as teste:
        valid,nxdomain,errors = massdns.load(resolve_output.read().split("\n") 
                                + brute_output.read().split("\n"))
        valid_join.write("\n".join(list(valid.keys())))
        nxdomain_join.write("\n".join(nxdomain))
        errors_join.write("\n".join(errors))
        teste.write(str(valid))

print("#altdns")
print(run_command(f"altdns -i subdomains -o altdns-output -w \
                {alt_wordlist}"))

print("#massdns - brute alt")
print(run_command(f"massdns -r {resolvers} -w massdns-alt-output -o Srmldni\
    altdns-output"))

print("#join | sort | uniq")
with open("massdns-alt-output","r") as alt_output, \
    open("alt-subdomains","w") as valid_join, open("alt-nxdomain-cname","w") \
    as nxdomain_join, open("alt-errors","w") as errors_join:
        valid,nxdomain,errors = massdns.load(alt_output.read().split("\n"))
        valid_join.write("\n".join(list(valid.keys())))
        nxdomain_join.write("\n".join(nxdomain))
        errors_join.write("\n".join(errors))
