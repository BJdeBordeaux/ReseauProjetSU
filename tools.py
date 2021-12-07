
# des dictionnaire pour interpreter les octets
dico_type_eternet = {
	"0800" : "IPv4",
}

dico_type_ip_option = {
	"00" : "End of Operation",
	"01" : "No Operation",
	"07" : "Record Route",
	"44" : "TimeStamp",
	"83" : "Loose Routing",
	"89" : "Strict Routing",
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
	"-2" : "ligne incomplete"
}

dico_type_ip_protocol = {
	"11" : "UDP",
	"06" : "TCP",
	"01" : "ICMP",
}

dico_opcod_dhcp = {
	"01" : "Boot Request",
	"02" : "Boot Reply",
}

dico_option_dhcp = {
	"00" : "Pad",
	"01" : "Subnet Mask",
	"02" : "Time Offset",
	"03" : "Router",
	"06" : "DNS Name Server",
	"0c" : "Host Name",
	"21" : "Static Route",
	"2a" : "NTP Servers",
	"32" : "Request IP Address",
	"33" : "IP Address Lease",
	"35" : "DHCP Message Type",
	"36" : "DHCP Server Identifier",
	"37" : "Parameter Request List",
	"38" : "Renewal Time Value",
	"39" : "Maximum DHCP Message Size",
	"3a" : "Release Time Value",
	"3b" : "Rebinding Time Value",
	"3c" : "Vendor Class Identifier",
	"3d" : "Client Identifier",
	"74" : "DHCP Auto-configuration",
	"e0" : "Private",
	"ff" : "End",
}

dico_type_dhcp = {
	"01" : "Discover",
	"02" : "Offer",
	"03" : "Request",
	"04" : "Declin",
	"05" : "ACK",
	"06" : "NAK",
	"07" : "Release",
	"08" : "Inform",
}

# des listes pour optimiser la clause condition
dhcp_option_liste_sans_data = ["00", "ff"]
dhcp_option_liste_interpretation_dico = ["35", "74", ]
dhcp_option_liste_interpretation_IP = ["01", "03", "06", "32", "36", ]
dhcp_option_liste_interpretation_temps = ["33", "3a", "3b"]
dhcp_option_liste_interpretation_chaine = ["0c", "0f", "3c"]
dhcp_option_liste_interpretation_multichamps = ["37", "3d", ]

# fonction pour la convertion
def sec_to_hours(seconds):
    a=str(seconds//3600)
    b=str((seconds%3600)//60)
    c=str((seconds%3600)%60)
    d=a+ " hours, "+b+" minutes, "+c+" seconds"
    return d

def liste_hex_2_dec(Liste):
	"""
	list[str] -> str
	Prendre une liste d'octets et renvoir sa valeur en decimal en chaine de caracteres correspondant
	"""
	return str(int("".join(Liste), base = 16))

def liste_hex_2_IP(Liste):
	"""
	list[str] -> str
	Prendre une liste d'octets et la convertir en adresse IP correspondant
	"""
	return ".".join([str(int(hex, base = 16)) for hex in Liste])

def liste_hex_2_MAC(Liste):
	"""
	list[str] -> str
	Prendre une liste d'octets et la convertir en adresse MAC correspondant
	"""
	return ":".join(Liste)

def liste_hex_2_ASCII(Liste):
	fin = Liste.index("00")
	return bytes.fromhex(Liste[0:fin]).decode("ASCII")

def info_erreur(erreur_str, longueur_trame):
	"""
	str * int -> str
	contruire la chaîne de caracteres representant l'erreur
	a partir d'une trame sous forme une liste d'octets
	
	Si la lecture d'une trame est interrompue a cause d'une erreur,
	on va stocker le code pour l'erreur a la fin de la trame
	Puis le main va appeler cette fonction pour notifier cette erreur.
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
	verifier si le format des offset de la trame est valide
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
	verifier si le format des octets de la trame est valide
	"""
	if len(octet) != 2:
		return False

	for e in octet:
		if not est_hex(e):
			return False

	return True


def liste_brute_2_liste(liste_brute):
	"""
	list[list[str]] -> list[list[str]]
	convertir d'une liste composee de string representant les lignes 
	en une liste des listes et chaque liste interieure est une trame
	ex: list[0] == ["00", "3a", "ff", "50", "66", "21", ...] : trame numero 1
		list[0][0] == "33" : octet numero 1 de la trame numero 1
	"""
	#initiation des variables
	liste_res = []
	trame_courante = []
	ignorer_ligne = False # en cas d'erreur, la lecture de cette trame doit etre arretee
	ignorer_element = False # si on lit un octet invalide, le reste de la ligne doit etre abandonne
	point_darret = 0 # pour voir s'il s'agit d'une ligne incomplete
	octet_invalide = False # pour marquer le type d'erreur

	# pour chaque ligne
	for indice_ligne in range(len(liste_brute)):
		# on extrait l'offset
		offset_de_la_ligne = liste_brute[indice_ligne][0] # qui doit etre offset
		offset_en_hex = int(offset_de_la_ligne, base = 16) 
		# s'il est valide, on continue,
		# sinon, on ignore cette ligne
		if offset_valide(offset_de_la_ligne) :
			
			# si offset est egal a 0, on sait que c'est le debut d'une trame
			if offset_en_hex == 0:
				if not ignorer_ligne:
					liste_res.append(trame_courante)
				
				# remettre les variables pour une nouvelle trame
				trame_courante = []
				ignorer_ligne = False
				ignorer_element = False
				point_darret = 0
				octet_invalide = False

			# s'il y a une erreur, on ignore la trame
			if ignorer_ligne == False:
				if indice_ligne < len(liste_brute) and offset_en_hex != 0:
					
					# en cas d'erreur
					# determiner s'il s'agit d'octet invalide ou ligne incomplete
					# une information pour indiquer une erreur dans le fichier
					if len(trame_courante) < offset_en_hex:
						# le cas d'octet invalide
						if octet_invalide:
							trame_courante.append("-1")	
						# le cas de ligne incomplète
						else:
							trame_courante.append("-2")
						liste_res.append(trame_courante)
						ignorer_ligne = True
						continue

				# on supprime des elements qui ne sont pas attendu par l'offset
				while(len(trame_courante) > offset_en_hex):
					trame_courante.pop()
				
				# on verifie si la ligne est complete
				point_darret=len(trame_courante)
				if point_darret == offset_en_hex:
					ignorer_element = False
				
				# on prend des octets dans la ligne
				for indice_element in range(1, len(liste_brute[indice_ligne])):
					element_courant = liste_brute[indice_ligne][indice_element]
					
					if octet_valide(element_courant) and not ignorer_element:
						trame_courante.append(element_courant.lower())
					
					# si octet est invalide, on ignore le reste
					# s'il s'agit d'une valeur textuelle, on remettra ignorer_element pour la ligne suivante
					elif not octet_valide(element_courant): 
						point_darret = len(trame_courante)
						ignorer_element = True
						if(len(element_courant) == 2):
							octet_invalide = True

				# derniere ligne du ficher, sans verification avec offset
				if indice_ligne == len(liste_brute)-1:
					liste_res.append(trame_courante)

	del liste_res[0] # cet element est une liste vide
	return liste_res

def constructeur_chaine_caracteres(indentation, champs, valeur, interpretation = ""):
	"""DHCP option
	int * str * str (* str) -> str
	Construire des information pour afficher
	suivant le format ci-dessous:DHCP option

	(indentation) champs: valeur (interpretation)\n
			Type : 0800 (IPv4)
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
	Determine si les octets sont suffisant pour remplir un champs
	En cas d'insuffisance, le champs doit etre abandonne
	"""
	if(len(Liste) >= position_fin):
		return True
	return False

def debug_print_trame(Liste_trame, pos_db = 0, pos_fin = -1):
	res = ""
	if pos_fin < 0:
		res = ",".join(Liste_trame[pos_db:])
	else:
		res = ",".join(Liste_trame[pos_db:pos_fin])
	print(res)
	return res
