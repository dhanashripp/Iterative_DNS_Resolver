List of libraries(Python) used:
dns
dns.name
dns.message
dns.query
dns.flags
Time
sys
datetime
dns.rdtypes.ANY.NSEC
dns.rdtypes.ANY.NSEC3


Sample queries and output for dnssec queries:


Dhanashris-MacBook-Air:Homework1_111461286 dhanashri$ python mydig_dnssec.py verisigninc.com A
DNSSEC validation pass 1 done
DNSSEC validation pass 2 done
DNSSEC validation pass 3 skipped at root
DNSSEC validation pass 1 done
DNSSEC validation pass 2 done
DNSSEC validation pass 3 done


QUESTION SECTION:
verisigninc.com. IN A


ANSWER SECTION:
verisigninc.com. 3600 IN A 72.13.63.55


AUTHORITY SECTION:
verisigninc.com. 86400 IN NS a3.verisigndns.com.
verisigninc.com. 86400 IN NS a2.verisigndns.com.
verisigninc.com. 86400 IN NS a1.verisigndns.com.


Query time: 1130 msec
WHEN: 2018-02-20 01:25:31.825081
MSG SIZE  rcvd: 205




Dhanashris-MacBook-Air:Homework1_111461286 dhanashri$ python mydig_dnssec.py www.google.com A
DNSSEC validation pass 1 done
DNSSEC validation pass 2 done
DNSSEC validation pass 3 skipped at root
DNSSEC validation pass 1 done
DNSSEC not supported


Dhanashris-MacBook-Air:Homework1_111461286 dhanashri$ python mydig_dnssec.py www.dnssec-failed.org A
DNSSEC validation pass 1 done
DNSSEC validation pass 2 done
DNSSEC validation pass 3 skipped at root
DNSSEC validation pass 1 done
DNSSEC validation pass 2 done
DNSSEC validation failed




Sample queries and output for mydig:


Dhanashris-MacBook-Air:Patil-Dhanashri-HW1 dhanashri$ python mydig.py www.instagram.com A


QUESTION SECTION:
z-p42-instagram.c10r.facebook.com. IN A


ANSWER SECTION:
z-p42-instagram.c10r.facebook.com. 60 IN A 31.13.71.174


AUTHORITY SECTION:
c10r.facebook.com. 3600 IN NS a.ns.c10r.facebook.com.
c10r.facebook.com. 3600 IN NS b.ns.c10r.facebook.com.


Query time: 627 msec
WHEN: 2018-02-20 02:15:24.385970
MSG SIZE  rcvd: 201




Dhanashris-MacBook-Air:Patil-Dhanashri-HW1 dhanashri$ python mydig.py www.instagram.com NS


QUESTION SECTION:
www.instagram.com. IN NS


ANSWER SECTION:
www.instagram.com. 3600 IN CNAME z-p42-instagram.c10r.facebook.com.


AUTHORITY SECTION:
instagram.com. 172800 IN NS ns-1349.awsdns-40.org.
instagram.com. 172800 IN NS ns-2016.awsdns-60.co.uk.
instagram.com. 172800 IN NS ns-384.awsdns-48.com.
instagram.com. 172800 IN NS ns-868.awsdns-44.net.


Query time: 310 msec
WHEN: 2018-02-20 02:15:29.198328
MSG SIZE  rcvd: 294




Dhanashris-MacBook-Air:Patil-Dhanashri-HW1 dhanashri$ python mydig.py www.instagram.com MX


QUESTION SECTION:
www.instagram.com. IN MX


ANSWER SECTION:
www.instagram.com. 3600 IN CNAME z-p42-instagram.c10r.facebook.com.


AUTHORITY SECTION:
instagram.com. 172800 IN NS ns-1349.awsdns-40.org.
instagram.com. 172800 IN NS ns-2016.awsdns-60.co.uk.
instagram.com. 172800 IN NS ns-384.awsdns-48.com.
instagram.com. 172800 IN NS ns-868.awsdns-44.net.


Query time: 298 msec
WHEN: 2018-02-20 02:15:33.127205
MSG SIZE  rcvd: 294