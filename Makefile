all:
	python3 main.py http.txt res.txt && cat res.txt

test:
	python3 test.py test.txt test_res.txt && cat test_res.txt

udp:
	python3 main.py udp.txt udp_res.txt && cat udp_res.txt

dns1:
	python3 main.py dns_query.txt dns_query_res.txt && cat dns_query_res.txt

dns2:
	python3 main.py dns_response.txt dns_response_res.txt && cat dns_response_res.txt

clean:
	rm res.txt