import re


def is_ipv4(
		address: str
	) -> bool:
	"""Returns a boolean indicating if the given address is in IPv4 format."""
	return(re.match("^\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}$", address))

def normalize_whitespaces(
		text: str
	): -> str:
	"""Returns the given string, without duplicated whitespaces."""
	return(" ".join(text.split()))
