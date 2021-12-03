all:
	python3 main.py dns.txt res.txt && cat res.txt

test:
	python3 test.py dns_query.txt test_res.txt && cat test_res.txt

udp:
	python3 main.py udp.txt res.txt && cat res.txt

dns1:
	python3 main.py dns_query.txt res.txt && cat res.txt

dns2:
	python3 main.py dns_response.txt res.txt && cat res.txt

tdhcp1:
	python3 test.py tramedhcp1.txt res.txt && cat res.txt

dhcp1:
	python3 main.py tramedhcp1.txt res.txt && cat res.txt

dhcp2:
	python3 main.py tramedhcp2.txt res.txt && cat res.txt

dhcp3:
	python3 main.py dhcp3.txt res.txt && cat res.txt

ipo:
	python3 main.py ip_option.txt res.txt && cat res.txt

trame:
	python3 main.py trame.txt res.txt && cat res.txt

test2:
	python3 test2.py trame.txt res.txt && cat res.txt

clean:
	rm res.txt