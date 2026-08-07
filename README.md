# defcon34

You've Got Mail (That Was Meant For No One)

Description
In 2020, I registered a domain on a whim, mostly because I thought it would be hilarious for email, and then forgot about it. Then a city government faxed me their internal documents. Then an organization started sending me Cisco UCM alerts. Then 363,000 emails arrived in sixteen months. I never sent a single packet of attack traffic. The vulnerability is an assumption, that a domain nobody owns is safe to hardcode. Developers at enterprise software vendors, government agencies, and companies made that assumption. I registered the domains and the mail flowed in. This talk covers six years of passive email interception across more than 20 domains, the tooling built to systematically map this attack surface across hundreds of TLDs, and what 400,000 misdirected emails reveal about how production mail infrastructure actually fails. No exploits. No credentials. Just a $11 domain registration.

Sources: 
Sheward, M. "Deleteduser.com -- a $15 PII Magnet." Medium, April 2026. https://mike-sheward.medium.com/deleteduser-com-a-15-pii-magnet-c4396eb21061

Krebs, B. "They Told You Not To Reply." Washington Post Security Fix, March 2008. https://web.archive.org/web/20200905092128/http://voices.washingtonpost.com/securityfix/2008/03/they_told_you_not_to_reply.html

Krebs, B. “Chipotle Serves Up Chips, Guac & HR Email.” Krebs on Security, 16 Nov. 2015, https://krebsonsecurity.com/2015/11/chipotle-serves-up-chips-guac-hr-email/

Fitzpatrick, J. “Sears-Kmart MyGofer,” Internet Archive, archived May 1, 2014, https://web.archive.org/web/20140501153309/http://sears-kmart-mygofer.com/

Kim, P. and Gee, G. "Doppelganger Domains." Godai Group, 2011. https://godaigroup.net/wp-content/uploads/doppelganger/Doppelganger.Domains.pdf

Szurdi, J. and Christin, N. "Email Typosquatting." IMC 2017. ACM. https://dl.acm.org/doi/10.1145/3131365.3131399

Internet Assigned Numbers Authority. "RDAP Bootstrap File for Domain Name Space." https://data.iana.org/rdap/dns.json (RFC 7484)

Bradner, S., "RFC 2606: Reserved Top Level DNS Names", IETF, 1999 https://www.rfc-editor.org/rfc/rfc2606

Klensin, J., "Simple Mail Transfer Protocol", RFC 5321, IETF, October 2008. https://www.rfc-editor.org/rfc/rfc5321

DomainTools. "TLD Registration Count Statistics." https://research.domaintools.com/statistics/tld-counts/
