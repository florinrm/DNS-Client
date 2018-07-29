build:
	g++ dns.cpp -o dnsclient
run:
	./dnsclient www.pornhub.com TXT
clean:
	rm -f dnsclient *.log
	
