import subprocess
import os
from parse import massdns


def run_command(cmd:str) -> (bytes,bytes,bytes):
    cmd = [arg for arg in cmd.split(" ") if arg != ""]
    process = subprocess.Popen(cmd,stdout=subprocess.PIPE,
                                stderr=subprocess.PIPE)
    return(process.communicate()[0],process.communicate()[1])

def run(domain:str,resolvers:str,brute_wordlist:str,alt_wordlist:str,\
        amass_config:str):
    os.system("cls||clear")
    print("#subfinder")
    print(run_command(f"subfinder -d {domain} -all -o subfinder-out\
                -rL {resolvers} -timeout 90"))

    print("#amass")
    print(run_command(f"amass enum -active -config {amass_config} -rf \
                    {resolvers} -d {domain} -o amass-out\
                    -passive -nf subfinder-out"))

    print("#join | sort | uniq")
    with open("subfinder-out","r") as subfinder_out, \
        open("amass-out","r") as amass_out, open("join-1","w") as join:
            comb = list(set(list(subfinder_out) + list(amass_out)))
            join.write("".join(comb))
            subfinder_out.close()
            amass_out.close()


    print("#massdns - resolve")
    print(run_command(f"massdns -r {resolvers} -w massdns-resolve-out -o \
        Srmldni join-1"))

    print("#create brute_wordlist")
    with open("tobrute","w") as saida:
        for parametro in open(brute_wordlist,"r"):
            _ = saida.write("{}.{}\n".format(parametro.replace("\n",""), \
                domain))

    print("#massdns - brute")
    print(run_command(f"massdns -r {resolvers} -w massdns-brute-out -o \
        Srmldni tobrute"))

    print("#join | sort | uniq")
    with open("massdns-resolve-out","r") as resolve_out, \
        open("massdns-brute-out","r") as brute_out, \
        open("subdomains","w") as valid_join, open("nxdomain-cname","w") \
        as nxdomain_join, open("errors","w") as errors_join:
            valid,nxdomain,errors = massdns.load(\
                                        resolve_out.read().split("\n") 
                                        + brute_out.read().split("\n"))
            valid_join.write("\n".join(list(valid.keys())))
            nxdomain_join.write("\n".join(nxdomain))
            errors_join.write("\n".join(errors))

    print("#altdns")
    print(run_command(f"altdns -i subdomains -o altdns-out -w \
                    {alt_wordlist}"))

    print("#massdns - brute alt")
    print(run_command(f"massdns -r {resolvers} -w massdns-alt-out -o \
        Srmldni altdns-out"))

    print("#join | sort | uniq")
    with open("massdns-alt-out","r") as alt_out, \
        open("alt-subdomains","w") as valid_join, open("alt-nxdomain-cname",\
            "w") as nxdomain_join, open("alt-errors","w") as errors_join:
            valid,nxdomain,errors = massdns.load(alt_out.read().split("\n"))
            valid_join.write("\n".join(list(valid.keys())))
            nxdomain_join.write("\n".join(nxdomain))
            errors_join.write("\n".join(errors))
