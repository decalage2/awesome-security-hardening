# awesome-security-hardening

[![Awesome](https://cdn.rawgit.com/sindresorhus/awesome/d7305f38d29fed78fa85652e3a63e154dd8e8829/media/badge.svg)](https://github.com/sindresorhus/awesome)

A collection of awesome security hardening guides, tools and other resources.
This is work in progress: please contribute by forking, editing and sending pull requests.

------

# Security Hardening Guides

## Hardening Guide Collections

- [CIS Benchmarks](https://learn.cisecurity.org/benchmarks) (registration required)
- [ANSSI Best Practices](https://www.ssi.gouv.fr/en/best-practices/)
- [NSA Security Configuration Guidance](https://apps.nsa.gov/iaarchive/library/ia-guidance/security-configuration/index.cfm?PAGE=1&itemsQty=ALL)
- [NSA Cybersecurity Resources for Cybersecurity Professionals](https://www.nsa.gov/what-we-do/cybersecurity/) and [NSA Cybersecurity publications](https://nsacyber.github.io/publications.html)
- [US DoD DISA Security Technical Implementation Guides (STIGs) and Security Requirements Guides (SRGs)](https://iase.disa.mil/stigs/Pages/index.aspx)
- [Australian Cyber Security Center Publications](https://www.cyber.gov.au/publications)
- [FIRST Best Practice Guide Library (BPGL)](https://www.first.org/resources/guides/)

## GNU/Linux

- [ANSSI - Configuration recommendations of a GNU/Linux system](https://www.ssi.gouv.fr/en/guide/configuration-recommendations-of-a-gnulinux-system/)
- [nixCraft - 40 Linux Server Hardening Security Tips (2019 edition)](https://www.cyberciti.biz/tips/linux-security.html)
- [nixCraft - Tips To Protect Linux Servers Physical Console Access](https://www.cyberciti.biz/tips/tips-to-protect-linux-servers-physical-console-access.html)

### Red Hat Enterprise Linux - RHEL

- [A Guide to Securing Red Hat Enterprise Linux 7](https://access.redhat.com/documentation/en-us/red_hat_enterprise_linux/7/html-single/security_guide/index)
- [DISA STIGs RHEL](https://iase.disa.mil/stigs/os/unix-linux/Pages/red-hat.aspx)
- [nixCraft - How to set up a firewall using FirewallD on RHEL 8](https://www.cyberciti.biz/faq/configure-set-up-a-firewall-using-firewalld-on-rhel-8/)

### SUSE

- [SUSE Linux Enterprise Server 12 SP4 Security Guide](https://www.suse.com/documentation/sles-12/singlehtml/book_security/book_security.html)
- [SUSE Linux Enterprise Server 12 Security and Hardening Guide](https://www.suse.com/documentation/sles-12/book_hardening/data/book_hardening.html)

### Ubuntu


## Windows

- [Awesome Windows Domain Hardening](https://github.com/PaulSec/awesome-windows-domain-hardening)

## macOS

## Network Devices

- [NSA - Harden Network Devices](https://apps.nsa.gov/iaarchive/library/ia-guidance/security-tips/harden-network-devices.cfm) - very short but good summary

### Switches

- [DISA - Layer 2 Switch SRG](http://iasecontent.disa.mil/stigs/zip/U_Layer_2_Switch_V1R3_SRG.zip)

### Routers

- [NSA - A Guide to Border Gateway Protocol (BGP) Best Practices](https://www.nsa.gov/Portals/70/documents/what-we-do/cybersecurity/professional-resources/ctr-guide-to-border-gateway-protocol-best-practices.pdf?v=1)

## Virtualization - VMware

- [VMware Security Hardening Guides](https://www.vmware.com/security/hardening-guides.html)

## Services

### SSH

- [NIST IR 7966 - Security of Interactive and Automated Access Management Using Secure Shell (SSH)](https://nvlpubs.nist.gov/nistpubs/ir/2015/NIST.IR.7966.pdf)
- [ANSSI - (Open)SSH secure use recommendations](https://www.ssi.gouv.fr/en/guide/openssh-secure-use-recommendations/)
- [Linux Audit - OpenSSH security and hardening](https://linux-audit.com/audit-and-harden-your-ssh-configuration/)
- [Positron Security SSH Hardening Guides](https://www.sshaudit.com/hardening_guides.html) - focused on crypto algorithms

### TLS/SSL

- [NIST SP800-52 Rev 2 (2nd draft) - Guidelines for the Selection, Configuration, and Use of Transport Layer Security (TLS) Implementations](https://csrc.nist.gov/publications/detail/sp/800-52/rev-2/draft) - 2018, recommends TLS 1.3
- [ANSSI - Security Recommendations for TLS](https://www.ssi.gouv.fr/en/guide/security-recommendations-for-tls/) - 2017, does not cover TLS 1.3
- [Qualys SSL Labs - SSL and TLS Deployment Best Practices](https://github.com/ssllabs/research/wiki/SSL-and-TLS-Deployment-Best-Practices) - 2017, does not cover TLS 1.3

### Web Servers

### Mail Servers

### FTP Servers

### Database Servers

### LDAP

- [OpenLDAP Security Considerations](http://www.openldap.org/doc/admin24/security.html)
- [Best Practices in LDAP Security](https://www.skills-1st.co.uk/papers/ldap-best-2011/best-practices-in-ldap-security.pdf) (2011)
- [LDAP: Hardening Server Security (so administrators can sleep at night)](https://ff1959.wordpress.com/2013/07/31/ldap-hardening-server-security-so-administrators-can-sleep-at-night/)
- [LDAP Authentication Best Practices](http://web.archive.org/web/20130801091446/http://www.ldapguru.info/ldap/authentication-best-practices.html) - retrieved from web.archive.org
- [Hardening OpenLDAP on Linux with AppArmor and systemd](http://www.openldap.org/conf/odd-tuebingen-2018/Michael1.pdf) - slides
- [zytrax LDAP for Rocket Scientists - LDAP Security](http://www.zytrax.com/books/ldap/ch15/)
- [How To Encrypt OpenLDAP Connections Using STARTTLS](https://www.digitalocean.com/community/tutorials/how-to-encrypt-openldap-connections-using-starttls)

### DNS

- [NSA BIND 9 DNS Security](https://apps.nsa.gov/iaarchive/library/ia-guidance/security-configuration/applications/bind-9-dns-security.cfm) (2011)

## Authentication - Passwords

- [UK NCSC - Password administration for system owners](https://www.ncsc.gov.uk/collection/passwords)
- [NIST SP 800-63 Digital Identity Guidelines](https://pages.nist.gov/800-63-3/)

## Hardware - BIOS - UEFI

- [NSA Info Sheet: UEFI Lockdown Quick Guidance (March 2018)](https://www.nsa.gov/Portals/70/documents/what-we-do/cybersecurity/professional-resources/csi-uefi-lockdown.pdf?v=1)
- [NSA Tech Report: UEFI Defensive Practices Guidance (July 2017)](https://www.nsa.gov/Portals/70/documents/what-we-do/cybersecurity/professional-resources/ctr-uefi-defensive-practices-guidance.pdf?ver=2018-11-06-074836-090)

## Cloud

- [NSA Info Sheet: Cloud Security Basics (August 2018)](https://www.nsa.gov/Portals/70/documents/what-we-do/cybersecurity/professional-resources/csi-cloud-security-basics.pdf?v=1)
- [DISA DoD Cloud Computing Security](https://iase.disa.mil/cloud_security/Pages/index.aspx)

# Tools

## Tools to check security hardening

- [Lynis](https://cisofy.com/lynis/) - script to check the configuration of Linux hosts
- [Nipper-ng](https://github.com/arpitn30/nipper-ng) - to check the configuration of network devices (does not seem to be updated)

## Tools to apply security hardening

- [Bastille Linux](http://bastille-linux.sourceforge.net/) - outdated
- [Hardentools](https://github.com/securitywithoutborders/hardentools) - for Windows individual users (not corporate environments) at risk, who might want an extra level of security at the price of some usability.

# Books
