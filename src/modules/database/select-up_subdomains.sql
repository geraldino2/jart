#Assuming RFC1034: if a CNAME RR is present at a node, no other data should be present
SELECT
	hostname
	FROM subdomains AS sbd
	INNER JOIN dns_link AS dnl
	ON sbd.subdomain_id=dnl.subdomain_id
	INNER JOIN dns_records AS dnr
	ON dnl.dns_id=dnr.dns_id
	WHERE
		dnr.rcode="NOERROR"
		AND
		dnr.type="A"
