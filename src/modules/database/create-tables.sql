CREATE TABLE IF NOT EXISTS dns_records (
    dns_id INTEGER AUTO_INCREMENT,
    record VARCHAR(255) NOT NULL,
    type VARCHAR(8),
    rcode VARCHAR(8),
    PRIMARY KEY (dns_id), 
    UNIQUE(record,type)
)
---
CREATE TABLE IF NOT EXISTS subdomains (
    subdomain_id INTEGER AUTO_INCREMENT,
    hostname VARCHAR(255) NOT NULL,
    datetime TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (subdomain_id)
)
---
CREATE TABLE IF NOT EXISTS dns_link (
    record_id INTEGER AUTO_INCREMENT,
    subdomain_id INTEGER,
    dns_id INTEGER,
    PRIMARY KEY(record_id),
    FOREIGN KEY(subdomain_id) REFERENCES subdomains(subdomain_id),
    FOREIGN KEY (dns_id) REFERENCES dns_records(dns_id)
)
---
CREATE TABLE IF NOT EXISTS dns_link (
    record_id INTEGER AUTO_INCREMENT,
    subdomain_id INTEGER,
    dns_id INTEGER,
    PRIMARY KEY(record_id),
    FOREIGN KEY(subdomain_id) REFERENCES subdomains(subdomain_id),
    FOREIGN KEY (dns_id) REFERENCES dns_records(dns_id)
)
---
CREATE TABLE IF NOT EXISTS cname_resolutions (
    resolution_id INTEGER AUTO_INCREMENT,
    dns_id INTEGER,
    record VARCHAR(255),
    PRIMARY KEY (resolution_id),
    FOREIGN KEY (dns_id) REFERENCES dns_records(dns_id)
)
---
CREATE TABLE IF NOT EXISTS services (
    dns_id INTEGER,
    port INTEGER,
    state VARCHAR(14),
    service VARCHAR(32),
    transport_protocol VARCHAR(3) NOT NULL,
    fingerprint VARCHAR(307),
    PRIMARY KEY (dns_id, port),
    FOREIGN KEY (dns_id) REFERENCES dns_records(dns_id)
)
---
CREATE TABLE IF NOT EXISTS source_codes (
    source_code_id INTEGER AUTO_INCREMENT, source_code 
    MEDIUMTEXT NOT NULL, screenshot_path VARCHAR(512), 
    PRIMARY KEY(source_code_id)
)
---
CREATE TABLE IF NOT EXISTS headers (
    header_id INTEGER 
    AUTO_INCREMENT, header_dict MEDIUMTEXT NOT NULL, 
    PRIMARY KEY (header_id)
)
---
CREATE TABLE IF NOT EXISTS vulnerabilities (
    vulnerability_id INTEGER AUTO_INCREMENT, 
    subdomain_id INTEGER NOT NULL,
    endpoint VARCHAR(2083),
    vulnerability VARCHAR(64), 
    info VARCHAR(1024),
    severity VARCHAR(16),
    PRIMARY KEY (vulnerability_id), 
    FOREIGN KEY (subdomain_id) REFERENCES subdomains(subdomain_id)
)
---
    CREATE TABLE IF NOT EXISTS directories (
    directory_id INTEGER AUTO_INCREMENT,
    subdomain_id INTEGER NOT NULL,
    port INTEGER NOT NULL,
    tls TINYINT NOT NULL, 
    path VARCHAR(2083) NOT NULL,
    status_code INTEGER, 
    size INTEGER,
    source_code_id INTEGER,
    header_id INTEGER,
    source VARCHAR(16),
    PRIMARY KEY (directory_id),
    FOREIGN KEY (subdomain_id) REFERENCES subdomains(subdomain_id), 
    FOREIGN KEY (source_code_id) REFERENCES source_codes(source_code_id),
    FOREIGN KEY (header_id) REFERENCES headers(header_id)
)
---
CREATE TABLE IF NOT EXISTS emails (
    email_id INTEGER AUTO_INCREMENT,
    email_address VARCHAR(320) NOT NULL, 
    PRIMARY KEY (email_id)
)
---
CREATE TABLE IF NOT EXISTS links (
    link_id INTEGER AUTO_INCREMENT,
    path VARCHAR(2083) NOT NULL, 
    directory_id INTEGER,
    type VARCHAR(8), 
    PRIMARY KEY(link_id),
    FOREIGN KEY (directory_id) REFERENCES directories(directory_id)
)
---
CREATE TABLE IF NOT EXISTS targets (
    target_id INTEGER AUTO_INCREMENT, 
    hostname VARCHAR(255) NOT NULL, 
    PRIMARY KEY(target_id)
)
