from dns import exception,flags,message,name,query,rdatatype

def process_query(resolver:str,host:str,question:int) -> (int,str):
    '''
    Output
        status
        ANSWER
    '''
    ADDITIONAL_RDCLASS = 65535
    request = message.make_query(name.from_text(host), question)
    request.flags |= flags.AD
    request.find_rrset(request.additional,name.root,ADDITIONAL_RDCLASS, \
                       rdatatype.OPT, create=True, force_unique=True)
    try:
        response = query.udp(request,resolver,5)
        if(len(response.answer)>0):
            return((response.rcode(),response.answer[0].to_text() \
                    .split(" ")[4]))
        return((response.rcode(),""))
    except exception.Timeout:
        return(("TIMEOUT",""))