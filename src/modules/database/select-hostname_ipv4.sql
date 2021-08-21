SELECT
	(SELECT hostname FROM subdomains WHERE subdomain_id=dnsl.subdomain_id),
	dnsr.record
	FROM dns_records AS dnsr
	INNER JOIN dns_link AS dnsl
	ON dnsr.dns_id = dnsl.dns_id
	WHERE dnsr.type='A'
---
SELECT
	(SELECT hostname FROM subdomains WHERE subdomain_id=dnsl.subdomain_id),
	(SELECT record FROM cname_resolutions WHERE dns_id=dnsl.dns_id
		ORDER BY record LIMIT 1),
	cnr.record
	FROM cname_resolutions AS cnr
	INNER JOIN dns_link AS dnsl
	ON cnr.dns_id = dnsl.dns_id