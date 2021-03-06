from dns import exception, flags, message, name, query, rdatatype


def process_query(
        resolver: str,
        host: str,
        question: int,
        retries: int = 3
    ) -> (int, str, str):
    """
    Perform a DNS request.

    :param resolver: DNS resolver to be used
    :param host: hostname to be questioned
    :param question: DNS question type
    :param retries: max number of retries
    :returns: DNS rcode, answer, SOA
    """
    ADDITIONAL_RDCLASS = 65535
    request = message.make_query(name.from_text(host), question)
    request.flags |= flags.AD
    request.find_rrset(
                        request.additional,
                        name.root,
                        ADDITIONAL_RDCLASS,
                        rdatatype.OPT,
                        create = True,
                        force_unique = True
                    )
    for _ in range(retries):
        try:
            response = query.udp(request, resolver, 5)
            if(len(response.answer) > 0):
                return(
                        response.rcode(),
                        response.answer[0].to_text(),
                        response.authority
                    )
            return(
                    response.rcode(), 
                    "", 
                    response.authority
                )
        except exception.Timeout:
            continue
    return(4, "", "")
