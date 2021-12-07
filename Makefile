all:
	python3 main.py all.txt res.txt && cat res.txt

ipo:
	python3 main.py ip_option.txt res.txt && cat res.txt

dns:
	python3 main.py dns.txt res.txt && cat res.txt

dhcp:
	python3 main.py dhcp.txt res.txt && cat res.txt

clean:
	rm res.txt