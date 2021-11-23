dico_type_eternet = {
	"0800" : "IPv4",
}

dico_type_erreur = {
	"-1" : "octet non valide",
	"-2" : "ligne incomplète"
}

dico_type_ip_protocol = {
	"11" : "UDP",
	"06" : "TCP",
	"01" : "ICMP",
}

def liste_hex_2_dec(Liste):
	return str(int("".join(Liste), base = 16))

def LStrToInt(L):
	""" list[str] -> str : Transforme une liste d'hexa en liste d'entier"""
	res = list()
	for e in L:
		res.append(int("0x"+e, base=16))
	return res

def LStrToIp(L):
	""" list[str] -> str : Transforme une liste d'hexa en adresse ip en str"""
	L = LStrToInt(L)
	res = ""
	for e in L:
		res += str(e)+"."
	res = res[:len(res)-1]
	return  res

def LStrToMac(L):
	""" list[str] -> str : Transforme une liste d'hexa en adresse MAC en str"""
	res = ""
	for e in L:
		res += str(e)+":"
	res = res[:len(res)-1]
	return  res

def LStrToPort(L):
	""" list[str] -> str : Transforme une liste d'hexa en numéro de port en str"""
	res = 0
	tmp = LStrToStr(L)

	return str(int(tmp, base=16))

def LStrToStr(L):
	""" list[str] -> str : Transforme une liste d'hexa en un mot Ox"""
	res = "0x"
	for e in L:
		res+=e
	return res

def LStrToBin(L):
	""" list[str] -> str : Transforme une liste d'hexa en binaire sous forme de str"""
	res=list()
	tmp=LStrToInt(L)
	for e in tmp:
		b=bin(e)
		if len(b[2:]) < 8:
			for i in range(8-len(b[2:])):
				res.append("0")
		for i in range(len(b[2:])):
			res.append(b[2+i])
	return res