import re

def set_to_str(input: set):
	parsed = ""
	for item in input:
		parsed += f"{item} "
	return(parsed[:-1])

def is_ipv4(address: str):
	return(re.match("^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$", address))

def normalize_whitespaces(text:str):
	return(" ".join(text.split()))
