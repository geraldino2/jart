def set_to_str(input:set):
	parsed = ""
	for item in input:
		parsed += f"{item} "
	return(parsed[:-1])
