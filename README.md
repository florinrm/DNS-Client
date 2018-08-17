# DNS-Client
## Short description
C++ implementation of a DNS resolver for sending requests for DNS interrogations, showing information about a given IP or domain name, using UDP sockets.

## How to use it?

Firstly, the types of DNS interrogation should be known:
- A - Host Address
- MX - Mail Exchange
- NS - Authoritative Name Server
- CNAME - canonical name for an alias
- SOA - Start Of a zone of Authority
- TXT - text strings - if in command line we gave a domain name
- PTR - Domain Name Pointer - if in command line we gave an IP address -> reverse lookup
Run the Makefile for building and for running the executable, follow these examples:
./dnsclient www.google.com TXT
./dnsclient 141.85.37.5 PTR
