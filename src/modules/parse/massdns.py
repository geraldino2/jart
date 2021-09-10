def load(
        lines: list
    ) -> (dict, dict, set):
    """
    Read massdns lines and separate results into valid, NX and errors.

    :param lines: massdns output lines
    :returns: subdomains that are valid/nx, as dicts and errors, as set
    """
    valid = dict()
    nxdomain_cname = dict()
    errors = set()
    for i in range(len(lines)):
        if(lines[i] != ""):
            terms = lines[i].split(" ")
            if(lines[i][0] == "\t"):
                answer = terms[2]
                if(answer[-1:] == "."):
                    answer = answer[:-1]
                if(code != "NXDOMAIN"):
                    valid[subdomain][1].add(answer)
                else:
                    nxdomain_cname[subdomain][1].add(terms[2][:-1])
            else:
                code,subdomain = terms[2],terms[3][:-1]
                if(lines[i+1] != ""):
                    if(code != "NXDOMAIN"):
                        valid[subdomain] = (code, set())
                    else:
                        nxdomain_cname[subdomain] = (code, set())
                elif(code == "NOERROR" and terms[5] == "NS"):
                    valid[subdomain] = (code, set())
                elif(code in ["SERVFAIL", "REFUSED"]):
                    errors.add(subdomain)
    return(valid, nxdomain_cname, errors)
