# awesome-security-hardening

[![Awesome](https://cdn.rawgit.com/sindresorhus/awesome/d7305f38d29fed78fa85652e3a63e154dd8e8829/media/badge.svg)](https://github.com/sindresorhus/awesome)

A collection of awesome security hardening guides, best practices, tools and other resources.
This is work in progress: please contribute by forking, editing and sending pull requests. You may also send suggestions on Twitter to [@decalage2](https://twitter.com/decalage2), or use https://www.decalage.info/contact

------

# Security Hardening Guides and Best Practices

## Hardening Guide Collections

- [CIS Benchmarks](https://learn.cisecurity.org/benchmarks) (registration required)
- [ANSSI Best Practices](https://www.ssi.gouv.fr/en/best-practices/)
- [NSA Security Configuration Guidance](https://apps.nsa.gov/iaarchive/library/ia-guidance/security-configuration/index.cfm?PAGE=1&itemsQty=ALL)
- [NSA Cybersecurity Resources for Cybersecurity Professionals](https://www.nsa.gov/what-we-do/cybersecurity/) and [NSA Cybersecurity publications](https://nsacyber.github.io/publications.html)
- [US DoD DISA Security Technical Implementation Guides (STIGs) and Security Requirements Guides (SRGs)](https://iase.disa.mil/stigs/Pages/index.aspx)
- [OpenSCAP Security Policies](https://www.open-scap.org/security-policies/)
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
- [RFC 7540 Appendix A TLS 1.2 Cipher Suite Black List](https://tools.ietf.org/html/rfc7540#appendix-A)

### Web Servers

- [Cipherli.st - Strong Ciphers for Apache, nginx and Lighttpd](https://cipherli.st/)

#### Apache HTTP Server

- [Apache HTTP Server documentation - Security Tips](http://httpd.apache.org/docs/current/misc/security_tips.html)
- [GeekFlare - Apache Web Server Hardening and Security Guide](https://geekflare.com/apache-web-server-hardening-security/)
- [Apache Config - Apache Security Hardening Guide](https://www.apachecon.eu/)

#### Apache Tomcat

- [Apache Tomcat 9 Security Considerations](https://tomcat.apache.org/tomcat-9.0-doc/security-howto.html) / [v8](https://tomcat.apache.org/tomcat-8.0-doc/security-howto.html) / [v7](https://tomcat.apache.org/tomcat-7.0-doc/security-howto.html)
- [OWASP Securing tomcat](https://www.owasp.org/index.php/Securing_tomcat)
- [How to get Tomcat 9 to work with authbind to bind to port 80](https://serverfault.com/questions/889122/how-to-get-tomcat-9-to-work-with-authbind-to-bind-to-port-80)

#### Eclipse Jetty

- [Eclipse Jetty - Configuring Security](https://www.eclipse.org/jetty/documentation/current/configuring-security.html)
- [Jetty hardening](https://virgo47.wordpress.com/2015/02/07/jetty-hardening/) (2015)

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

- [NIST SP 800-81-2 - Secure Domain Name System (DNS) Deployment Guide](https://csrc.nist.gov/publications/detail/sp/800-81/2/final) (2013)
- [CMU SEI - Six Best Practices for Securing a Robust Domain Name System (DNS) Infrastructure](https://insights.sei.cmu.edu/sei_blog/2017/02/six-best-practices-for-securing-a-robust-domain-name-system-dns-infrastructure.html)
- [NSA BIND 9 DNS Security](https://apps.nsa.gov/iaarchive/library/ia-guidance/security-configuration/applications/bind-9-dns-security.cfm) (2011)

### NTP

- [IETF - Network Time Protocol Best Current Practices draft-ietf-ntp-bcp](https://tools.ietf.org/html/draft-reilly-ntp-bcp) (2019)
- [CMU SEI - Best Practices for NTP Services](https://insights.sei.cmu.edu/sei_blog/2017/04/best-practices-for-ntp-services.html)
- [Linux.com - Arrive On Time With NTP -- Part 2: Security Options](https://www.linux.com/learn/arrive-time-ntp-part-2-security-options)
- [Linux.com - Arrive On Time With NTP -- Part 3: Secure Setup](https://www.linux.com/learn/2017/2/arrive-time-ntp-part-3-secure-setup)

### CUPS

- [CUPS Server Security](https://www.cups.org/doc/security.html)

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

### GNU/Linux

- [Lynis](https://cisofy.com/lynis/) - script to check the configuration of Linux hosts
- [OpenSCAP Base](https://www.open-scap.org/tools/openscap-base/) - oscap command line tool
- [SCAP Workbench](https://www.open-scap.org/tools/scap-workbench/) - GUI for oscap
- [Tiger - The Unix security audit and intrusion detection tool](https://www.nongnu.org/tiger/) (might be outdated)

### Network Devices

- [Nipper-ng](https://github.com/arpitn30/nipper-ng) - to check the configuration of network devices (does not seem to be updated)

### TLS/SSL

- [Qualys SSL Labs - List of tools to assess TLS/SSL servers and clients](https://github.com/ssllabs/research/wiki/Assessment-Tools)

## Tools to apply security hardening

### GNU/Linux

- [Bastille Linux](http://bastille-linux.sourceforge.net/) - outdated

### Windows

- [Hardentools](https://github.com/securitywithoutborders/hardentools) - for Windows individual users (not corporate environments) at risk, who might want an extra level of security at the price of some usability.

# Books
