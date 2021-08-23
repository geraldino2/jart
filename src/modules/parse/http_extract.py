import re

def extract_emails(text:str,domains:set) -> set:
    emails = set()
    for domain in domains:
        for email in re.findall(r"[\w|\.|-]+@{}".format(domain),text):
            emails.add(email)
    return(emails)
