#!/usr/bin/python

import subprocess,os

domain = "uber.com"
resolvers = "/home/apolo2/.config/resolvers.txt"
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

print('#shuffledns - resolve')
print(run_command(f"shuffledns -d {domain} -list join-1 -r {resolvers} \
            -o subdomains"))

print('#shuffledns - brute')
print(run_command(f"shuffledns -d {domain} -w {brute_wordlist} -r {resolvers} \
            -o shuffledns-output"))

print('#join | sort | uniq')
with open('subdomains','r') as subdomains, \
    open('shuffledns-output','r') as shuffledns_output, \
    open('subdomains','w') as join:
        comb = list(set(list(subdomains) + list(shuffledns_output)))
        open('subdomains','w').close()
        join.write(''.join(comb))
        subdomains.close()
        shuffledns_output.close()

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
