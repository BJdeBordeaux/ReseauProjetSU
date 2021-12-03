b = 0
try:
	b = 1
	a = [0, 1]
	b = a[2]
except IndexError:
	c = 2
finally:
	print(b)