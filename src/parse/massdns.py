def load(lines:list) -> (dict,set,set):
    '''
    Input
        list
            List of lines
    Output
        dict
            {subdomain: (code, {IPs})}
        set
            NXDOMAIN with CNAME
        set
            SERVFAIL/REFUSED subdomains
    '''
    valid = dict()
    nxdomain_cname = set()
    errors = set()
    for i in range(len(lines)):
        if(lines[i] != ""):
            terms = lines[i].split(" ")
            if(lines[i][0] == "\t"):
                if(code != "NXDOMAIN"):
                    if(terms[1] == "A"):
                        valid[subdomain][1].add(terms[2])
                    else:
                        valid[subdomain][1].add(terms[2][:-1])
            else:
                if(lines[i+1] != ""):
                    code,subdomain = terms[2],terms[3][:-1]
                    if(code != "NXDOMAIN"):
                        valid[subdomain] = (code,set())
                    else:
                        nxdomain_cname.add(subdomain)
                elif(terms[2] in ["SERVFAIL","REFUSED"]):
                    errors.add(terms[3][:-1])
    return(valid,nxdomain_cname,errors)

def load_from_file(filename:str) -> (dict,set,set):
    '''
    Input
        str
            Filename
    Output
        dict
            {subdomain: (code, {IPs})}
        set
            NXDOMAIN with CNAME
        set
            SERVFAIL/REFUSED subdomains
    '''
    with open(filename) as file:
        return(load(file.read().split("\n")))
