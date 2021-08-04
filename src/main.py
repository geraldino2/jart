#!/usr/bin/python

import subprocess,os

domain = "uber.com"
resolvers = "/home/apolo2/.config/ipv4-resolvers.txt"
brute_wordlist = "/home/apolo2/SecLists/Discovery/DNS/dns-The-Biggest.txt"
alt_wordlist = "/home/apolo2/SecLists/Discovery/DNS/small-alt.txt"
amass_config = "/home/apolo2/Desktop/config.ini"

os.system("cls||clear")

def run_command(cmd:str,wait_output:bool=True) -> (bytes,bytes):
    cmd = [arg for arg in cmd.split(" ") if arg != ""]
    process = subprocess.Popen(cmd,stdout=subprocess.PIPE,
                                stderr=subprocess.PIPE)
    if(wait_output):
            return(process.communicate()[0],process.communicate()[1])
    else:
        return(b'',b'')

print('#subfinder')
print(run_command(f"subfinder -d {domain} -all -o subfinder-output\
            -rL {resolvers} -timeout 90"))

print('#amass')
print(run_command(f"amass enum -active -config {amass_config} -rf \
            {resolvers} -d {domain} -o amass-output\
            -passive -nf subfinder-output"))

print('#join | sort | uniq')
with open('subfinder-output','r') as subfinder_output, \
    open('amass-output','r') as amass_output, open('join-1','w') as join:
        comb = list(set(list(subfinder_output) + list(amass_output)))
        join.write(''.join(comb))
        subfinder_output.close()
        amass_output.close()

print('#massdns - resolve')
print(run_command(f"massdns -r {resolvers} -w massdns-resolve-output -o \
    Srmldni join-1"))

print('#create brute_wordlist')
with open("tobrute","w") as saida:
    for parametro in open(brute_wordlist,"r"):
        _ = saida.write("{}.{}\n".format(parametro.replace("\n",""),domain))

print('#massdns - brute')
print(run_command(f"massdns -r {resolvers} -w massdns-brute-output -o Srmldni\
    tobrute"))
'''

# parse massdns output
#    filter valid domains
#    filter cnames
#    filter codes to check takeovers

print('#join | sort | uniq')
with open('massdns-resolve-output','r') as resolve_output, \
    open('massdns-brute-output','r') as brute_output, \
    open('subdomains','w') as join:
        comb = list(set(list(resolve_output) + list(brute_output)))
        open('subdomains','w').close()
        join.write(''.join(comb))
        resolve_output.close()
        brute_output.close()

print('#altdns')
print(run_command(f"altdns -i {subdomains} -o altdns-output -w {alt_wordlist}"))

print('#shuffledns - resolve')
print(run_command(f"shuffledns -d {domain} -list altdns-output -r {resolvers} \
            -o altdns-output-valid"))

print('#join | sort | uniq')
with open('subdomains','r') as subdomains, \
    open('altdns-output-valid','r') as altdns_output_valid, \
    open('subdomains','w') as join:
        comb = list(set(list(subdomains) + list(altdns_output_valid)))
        open('subdomains','w').close()
        join.write(''.join(comb))
        subdomains.close()
        altdns_output_valid.close()
'''