dico_type_eternet = {
	"0800" : "IPv4",
}

dico_type_udp = {
	"0035" : "DNS",
	"0043" : "DHCP",
	"0044" : "DHCP",
}

dico_type_dns_QR = {
	"0" : "Query",
	"1" : "Response",

}

dico_type_dns_type = {
	"01" : "A",
	"02" : "NS",
	"05" : "CNAME",
	"0f" : "MX",
	"1c" : "AAAA",
	"06" : "SOA",
}

dico_type_dns_typen = {
	"A" :"Host Adress",
	"NS" : "Name Server",
	"CNAME" : "Canonical Name for an alias",
	"MX" : "Mail Exchange",
	"AAAA" : "IPV6 Adress",
	"SOA" : "Start Of a zone of Authority",
}

dico_type_dns_AA = {
	"0" : "Server is not an authority for domain",
	"1" : "Server is not an authority for domain",
}

dico_type_dns_RD = {
	"0" : "Do not query recursively",
	"1" : "Do query recursively",
}


dico_type_dns_RA = {
	"0" : "Server can not do recursive queries",
	"1" : "Server can do recursive queries",
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

def sec_to_hours(seconds):
    a=str(seconds//3600)
    b=str((seconds%3600)//60)
    c=str((seconds%3600)%60)
    d=a+ "hours, "+b+"minutes, "+c+"seconds"
    return d



def liste_hex_2_dec(Liste):
	return str(int("".join(Liste), base = 16))

def info_erreur(erreur_str, longueur_trame):
	"""
	str * int -> str
	contruire la chaîne de caractères représentant l'erreur
	"""
	information_erreur = ""
	if erreur_str in dico_type_erreur:
		information_erreur = dico_type_erreur.get(erreur_str)
	else: 
		information_erreur = "Erreur inconnue"
	information_erreur += ", interrupture d'analyse. "
	information_erreur += "Erreur se trouve a l'octet " + str(longueur_trame+1)
	information_erreur += "\n"
	return information_erreur


def est_hex(cara):
	"""
	str -> bool
	verifier si un caractere est un nombre hexadecimal
	"""
	if len(cara) != 1:
		return False

	if not("a" <= cara.lower() <= "f" or "0" <= cara <= "9"):
		return False

	return True

def offset_valide(offset):
	"""
	str -> bool
	vérifier si le format des offset de la trame est valide
	"""
	if len(offset) < 3:
		return False

	for caractere in offset:
		if not est_hex(caractere):
			return False

	return True

def octet_valide(octet):
	"""
	str -> bool
	vérifier si le format des octets de la trame est valide
	"""
	if len(octet) != 2:
		return False

	for e in octet:
		if not est_hex(e):
			return False

	return True

# 
def liste_brute_2_liste(Liste):
	"""
	list[str] -> list[list[str]]
	convertir d'une liste composée de string représentant les lignes en une liste des listes et chaque liste intérieure est une trame
	"""
	liste_brute = []
	trame_courante = []
	ignorer_ligne = False # il y a une erreur et la lecture de cette trame doit etre arretee
	ignorer_element = False
	point_darret = 0 # pour voir s'il s'agit d'un octet invalide
	octet_invalide = False # pour marquer le type d'erreur

	for indice_ligne in range(len(Liste)):
		offset_de_la_ligne = Liste[indice_ligne][0] # qui doit etre offset
		offset_en_hex = int(offset_de_la_ligne, base = 16)
		# print("indice ligne = " + str(indice_ligne) + ", offset : " + offset_de_la_ligne)
		if offset_valide(offset_de_la_ligne) :
			if offset_en_hex == 0:
				if not ignorer_ligne:
					liste_brute.append(trame_courante)
				
				# remettre les variables pour une nouvelle trame
				trame_courante = []
				ignorer_ligne = False
				ignorer_element = False
				point_darret = 0
				octet_invalide = False

			# s'il y a une erreur, on ignore la trame
			if ignorer_ligne == False:
				if indice_ligne < len(Liste)-1 and offset_en_hex != 0:
					# en cas d'erreur
					# determiner s'il s'agit d'octet invalide ou ligne incomplète
					# une information pour indiquer une erreur dans le fichier
					if len(trame_courante) < offset_en_hex:
						# le cas d'octet invalide
						if octet_invalide:
							# print("point d'arret, offset détecté : "
								# + str(hex(point_darret)) + "," + "0x" + offset_de_la_ligne + ", trame " + str(len(liste_brute)))
							trame_courante.append("-1")
							
						else:
							# print("offset reel, offset détecté : "
								# + str(hex(len(trame_courante))) + "," + "0x" +  offset_de_la_ligne)
							trame_courante.append("-2")
						liste_brute.append(trame_courante)
						ignorer_ligne = True

				# on supprime des éléments qui ne sont pas attendu par l'offset
				while(len(trame_courante) > offset_en_hex):
					trame_courante.pop()
				if point_darret == offset_en_hex:
					ignorer_element = False
					
				# on prend des octets dans la ligne
				for indice_element in range(1, len(Liste[indice_ligne])):
					element_courant = Liste[indice_ligne][indice_element]
					if octet_valide(element_courant) and not ignorer_element:
						trame_courante.append(element_courant.lower())
					# si octet est invalide, on ignore le reste
					# s'il s'agit d'une valeur textuelle, on remettra ignorer_element pour la ligne suivante
					elif not octet_valide(element_courant): 
						point_darret = len(trame_courante)
						ignorer_element = True
						if(len(element_courant) == 2):
							octet_invalide = True

					
				else: # pour la dernière ligne
					for indice_element in range(1, len(Liste[indice_ligne])):
						element_courant = Liste[indice_ligne][indice_element]
						if octet_valide(element_courant) and not ignorer_element:
							trame_courante.append(element_courant.lower())
						elif not octet_valide(element_courant): 
							point_darret = len(trame_courante)
							ignorer_element = True
							if(len(element_courant) == 2):
								octet_invalide = True

				# dernière ligne, sans vérification avec offset
				if indice_ligne == len(Liste)-1:
					liste_brute.append(trame_courante)

	del liste_brute[0] # cet élément est une liste vide
	return liste_brute

def constructeur_chaine_caracteres(indentation, champs, valeur, interpretation = ""):
	"""
	int * str * str (* str) -> str
	construire des information pour afficher
	"""
	res = "\t"*indentation
	res += champs
	res += ": "
	res += str(valeur)
	if interpretation != "":
		res += " (" + interpretation + ")"
	res += "\n"
	return res

def verificateur_avant_constructeur(Liste, position_debut, position_fin):
	"""
	list[str]*int*int -> bool
	détermine si les octets sont suffisant pour remplir un champs
	"""
	if(len(Liste) >= position_fin):
		return True
	return False
