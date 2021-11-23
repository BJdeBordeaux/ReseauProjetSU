all:
	python3 main.py http.txt res.txt && cat res.txt

test:
	python3 test.py test.txt test_res.txt && cat test_res.txt

clean:
	rm res.txt