from os import posix_fadvise
import tools

def analyse_ethernet(Liste):
	"""
	list[str] -> str
	Renvoyer un str représentant l'entête ETHERNET
	"""
	res = "\tETHERNET :\n"
# Lecture de l'adresse Mac Destination
	position_debut = 0
	position_fin = 6
	if tools.verificateur_avant_constructeur(Liste, position_debut, position_fin):
		res += tools.constructeur_chaine_caracteres(2, "Adresse Mac Destination", ":".join(Liste[position_debut:position_fin]))
	
# Lecture de l'adresse Mac Source	
	position_debut = position_fin
	position_fin = 12
	if tools.verificateur_avant_constructeur(Liste, position_debut, position_fin):
		res += tools.constructeur_chaine_caracteres(2, "Adresse Mac Source", ":".join(Liste[position_debut:position_fin]))

# Lecture du type de protocole	
	position_debut = position_fin
	position_fin = 14
	if tools.verificateur_avant_constructeur(Liste, position_debut, position_fin):
		type_str = "".join(Liste[position_debut:position_fin])
		type_hex = tools.dico_type_eternet.get(type_str)
		if type_hex is not None:
			res += tools.constructeur_chaine_caracteres(2, "Protocol", "0x" + type_str, type_hex)
		else: 
			res += tools.constructeur_chaine_caracteres(2, "Protocol", "0x" + type_hex, "inconnu")	
	
	return res

# utiliser la meme structure pour faire la suite
def analyse_IP(Liste):
	"""
	list[str] -> str
	Renvoyer un str représentant l'entête IP
	"""
	res = "\tIP : \n"
	proto = ""
	option = False

	position_debut = 0
	position_fin = 1
	if tools.verificateur_avant_constructeur(Liste, position_debut, position_fin):
		res += tools.constructeur_chaine_caracteres(2, "Version", "0x" + Liste[position_debut:position_fin][0][0], "IPv" + Liste[position_debut:position_fin][0][0])	
	if tools.verificateur_avant_constructeur(Liste, position_debut, position_fin):
		res += tools.constructeur_chaine_caracteres(2, "Header length", "0x" + Liste[position_debut:position_fin][0][1], str(int(Liste[position_debut:position_fin][0][1], base = 16)*4))
		if Liste[position_debut:position_fin][0][1] == "f":
			option = True

	position_debut = position_fin
	position_fin = 2
	if tools.verificateur_avant_constructeur(Liste, position_debut, position_fin):
		res += tools.constructeur_chaine_caracteres(2, "Type of service", "0x" + Liste[position_debut:position_fin][0])

	position_debut = position_fin
	position_fin = 4
	if tools.verificateur_avant_constructeur(Liste, position_debut, position_fin):
		res += tools.constructeur_chaine_caracteres(2, "Total Length", "0x" + "".join(Liste[position_debut:position_fin]), tools.liste_hex_2_dec(Liste[position_debut:position_fin]) + " octets")	
	
	position_debut = position_fin
	position_fin = 6
	if tools.verificateur_avant_constructeur(Liste, position_debut, position_fin):
		res += tools.constructeur_chaine_caracteres(2, "Identifier", "0x" + "".join(Liste[position_debut:position_fin]))	
	
	position_debut = position_fin
	position_fin = 8
	if tools.verificateur_avant_constructeur(Liste, position_debut, position_fin):
		res += tools.constructeur_chaine_caracteres(2, "Flags", "0x" + "".join(Liste[position_debut:position_fin]))
		Lb = format(int("".join(Liste[6:8]), base = 16), '016b') 
		res += tools.constructeur_chaine_caracteres(3, "Reserve", Lb[0])
		res += tools.constructeur_chaine_caracteres(3, "DF", Lb[1])
		res += tools.constructeur_chaine_caracteres(3, "MF", Lb[2])
		res += tools.constructeur_chaine_caracteres(3, "Fragment offset", str(hex(int(Lb[3:], base = 2))), str(int(Lb[3:], base = 2)*8) + " octets")
	
	position_debut = position_fin
	position_fin = 9
	if tools.verificateur_avant_constructeur(Liste, position_debut, position_fin):
		res += tools.constructeur_chaine_caracteres(2, "Time To Live", "0x" + "".join(Liste[position_debut:position_fin]), tools.liste_hex_2_dec(Liste[position_debut:position_fin]))
	
	position_debut = position_fin
	position_fin = 10
	if tools.verificateur_avant_constructeur(Liste, position_debut, position_fin):
		protocol_hex = "".join(Liste[position_debut:position_fin])
		proto = "inconnu" if protocol_hex not in tools.dico_type_ip_protocol else tools.dico_type_ip_protocol.get(protocol_hex)
		res += tools.constructeur_chaine_caracteres(2, "Protocol", "0x" + protocol_hex, proto)
	position_debut = position_fin
	position_fin = 12
	if tools.verificateur_avant_constructeur(Liste, position_debut, position_fin):
		res += tools.constructeur_chaine_caracteres(2, "Header checksum", "0x" + "".join(Liste[position_debut:position_fin]))
	
	position_debut = position_fin
	position_fin = 16
	ip = [str(int(hex, base = 16)) for hex in Liste[position_debut:position_fin]]
	if tools.verificateur_avant_constructeur(Liste, position_debut, position_fin):
		res += tools.constructeur_chaine_caracteres(2, "Adresse IP Source", "0x" + "".join(Liste[position_debut:position_fin]),".".join(ip))


	position_debut = position_fin
	position_fin = 20
	ip = [str(int(hex, base = 16)) for hex in Liste[position_debut:position_fin]]
	if tools.verificateur_avant_constructeur(Liste, position_debut, position_fin):
		res += tools.constructeur_chaine_caracteres(2, "Adresse IP Destination", "0x" + "".join(Liste[position_debut:position_fin]), ".".join(ip))	
	
	return res, proto, option

# a écrire
def analyse_IP_option(Liste):
	"""
	list[str] -> str
	Renvoyer un str représentant l'entête IP option
	"""
	res = "\t\tOPTION IP : \n"
	indentation = 3
	position_debut = 0
	position_fin = 1
	if tools.verificateur_avant_constructeur(Liste, position_debut, position_fin):
		sous_liste = Liste[position_debut:position_fin]
		valeur = "".join(sous_liste)
		interpretation = "inconnu" if valeur not in tools.dico_type_ip_option else tools.dico_type_ip_option.get(valeur)
		res += tools.constructeur_chaine_caracteres(indentation, "Type", "0x" + valeur, interpretation)
	position_debut = position_fin
	position_fin = 2
	if tools.verificateur_avant_constructeur(Liste, position_debut, position_fin):
		sous_liste = Liste[position_debut:position_fin]
		valeur = "".join(sous_liste)
		longueur_en_int = int(valeur, 16)
		interpretation = tools.liste_hex_2_dec(sous_liste)
		res += tools.constructeur_chaine_caracteres(indentation, "Length", "0x" + valeur, interpretation)
	position_debut = position_fin
	position_fin = 3
	if tools.verificateur_avant_constructeur(Liste, position_debut, position_fin):
		sous_liste = Liste[position_debut:position_fin]
		valeur = "".join(sous_liste)
		interpretation = tools.liste_hex_2_dec(sous_liste)
		res += tools.constructeur_chaine_caracteres(indentation, "Pointer", "0x" + valeur, interpretation)
	position_debut = position_fin
	position_fin = longueur_en_int
	for index_routeur in range((position_fin-3)//4):
		if tools.verificateur_avant_constructeur(Liste, position_debut, position_fin):
			sous_liste = Liste[position_debut+index_routeur*4:position_debut+index_routeur*4+4]
			valeur = "".join(sous_liste)
			interpretation = tools.liste_hex_2_IP(sous_liste)
			res += tools.constructeur_chaine_caracteres(indentation, "Router", "0x" + valeur, interpretation)
			position_debut += 4
			position_fin += 4
	position_fin = 40
	if tools.verificateur_avant_constructeur(Liste, position_debut, position_fin):
		sous_liste = Liste[position_debut:position_fin]
		
		valeur = "".join(sous_liste)
		interpretation = tools.liste_hex_2_dec(sous_liste)
		res += tools.constructeur_chaine_caracteres(indentation, "Pading", valeur)
	return res

# a écrire
def analyse_UDP(Liste):
	"""
	list[str] -> str
	Renvoyer un str représentant l'entête UPD
	"""
	res = "\tUDP : \n"
	position_debut = 0
	position_fin = 2
	if tools.verificateur_avant_constructeur(Liste, position_debut, position_fin):
		res += tools.constructeur_chaine_caracteres(2, "Source Port","0x" +"".join(Liste[position_debut:position_fin]), tools.liste_hex_2_dec(Liste[position_debut:position_fin]))
		if tools.dico_type_udp.get("".join(Liste[position_debut:position_fin])) is not None:
			app = tools.dico_type_udp.get("".join(Liste[position_debut:position_fin]))
		else: 
			app="inconnu"
	position_debut = position_fin
	position_fin = 4
	if tools.verificateur_avant_constructeur(Liste, position_debut, position_fin):
		res += tools.constructeur_chaine_caracteres(2, "Destination Port","0x" +"".join(Liste[position_debut:position_fin]), tools.liste_hex_2_dec(Liste[position_debut:position_fin]))
		if (app == "inconnu") and tools.dico_type_udp.get("".join(Liste[position_debut:position_fin])) is not None:
			app = tools.dico_type_udp.get("".join(Liste[position_debut:position_fin]))
	position_debut = position_fin
	position_fin = 6
	if tools.verificateur_avant_constructeur(Liste, position_debut, position_fin):
		res += tools.constructeur_chaine_caracteres(2, "Lenght","0x" +"".join(Liste[position_debut:position_fin]), tools.liste_hex_2_dec(Liste[position_debut:position_fin]) + " octets")		
	position_debut = position_fin
	position_fin = 8
	if tools.verificateur_avant_constructeur(Liste, position_debut, position_fin):
		res += tools.constructeur_chaine_caracteres(2, "Checksum","0x" +"".join(Liste[position_debut:position_fin]), tools.liste_hex_2_dec(Liste[position_debut:position_fin]))
	return res, app

def analyse_DNS(Liste):
	"""
	list[str] -> str
	Renvoyer un str représentant l'entête DNS
	"""
	res = "\tDNS : \n"
	position_debut = 0
	position_fin = 2
	if tools.verificateur_avant_constructeur(Liste, position_debut, position_fin):
		res += tools.constructeur_chaine_caracteres(2, "Transaction ID","0x" +"".join(Liste[position_debut:position_fin]), tools.liste_hex_2_dec(Liste[position_debut:position_fin]))
	position_debut = position_fin
	position_fin = 4
	if tools.verificateur_avant_constructeur(Liste, position_debut, position_fin):
		res += tools.constructeur_chaine_caracteres(2, "Flags", "0x" + "".join(Liste[position_debut:position_fin]))
		Lb = format(int("".join(Liste[2:4]), base = 16), '016b')
		QR = "".join(Lb[0]) 
		res += tools.constructeur_chaine_caracteres(3,Lb[0]+"... .... .... ....	= Response", Lb[0], tools.dico_type_dns_QR.get(QR))
		res += tools.constructeur_chaine_caracteres(3,"."+Lb[1:4]+" "+Lb[4:5]+"... .... ....	= OPCode", int(Lb[1:5]), "Standard query")
		AA = "".join(Lb[5])
		res += tools.constructeur_chaine_caracteres(3, ".... ."+Lb[5]+".. .... ....	= Authoritative Answer", Lb[5],tools.dico_type_dns_AA.get(AA))
		res += tools.constructeur_chaine_caracteres(3, ".... .."+Lb[6]+". .... ....	= Truncated", Lb[6])
		RD = "".join(Lb[7])
		res += tools.constructeur_chaine_caracteres(3, ".... ..."+Lb[7]+" .... ....	= Recursion Desired", Lb[7],tools.dico_type_dns_RD.get(RD))
		RA = "".join(Lb[8])
		res += tools.constructeur_chaine_caracteres(3, ".... .... "+ Lb[8]+"... ....	= Recursion Available", Lb[8],tools.dico_type_dns_RA.get(RA))
		res += tools.constructeur_chaine_caracteres(3, ".... .... ."+Lb[9:12]+" ....	= Z", int(Lb[9:12]),"Reserved")
		res += tools.constructeur_chaine_caracteres(3, ".... .... .... "+Lb[12:16]+"	= Reply Code", int(Lb[12:16]), "No Error")
	position_debut = position_fin
	position_fin = 6
	if tools.verificateur_avant_constructeur(Liste, position_debut, position_fin):
		res += tools.constructeur_chaine_caracteres(2, "Questions","0x" +"".join(Liste[position_debut:position_fin]), tools.liste_hex_2_dec(Liste[position_debut:position_fin]))
	position_debut = position_fin
	position_fin = 8
	if tools.verificateur_avant_constructeur(Liste, position_debut, position_fin):
		res += tools.constructeur_chaine_caracteres(2, "Answers","0x" +"".join(Liste[position_debut:position_fin]), tools.liste_hex_2_dec(Liste[position_debut:position_fin]))
	n_answers=int(tools.liste_hex_2_dec(Liste[position_debut:position_fin]))
	position_debut = position_fin
	position_fin = 10
	if tools.verificateur_avant_constructeur(Liste, position_debut, position_fin):
		res += tools.constructeur_chaine_caracteres(2, "Authority","0x" +"".join(Liste[position_debut:position_fin]), tools.liste_hex_2_dec(Liste[position_debut:position_fin]))
	n_authority=int(tools.liste_hex_2_dec(Liste[position_debut:position_fin]))
	position_debut = position_fin
	position_fin = 12
	if tools.verificateur_avant_constructeur(Liste, position_debut, position_fin):
		res += tools.constructeur_chaine_caracteres(2, "Additional","0x" +"".join(Liste[position_debut:position_fin]), tools.liste_hex_2_dec(Liste[position_debut:position_fin]))
	n_additional=int(tools.liste_hex_2_dec(Liste[position_debut:position_fin]))
	res += "\t\tQueries: \n"
	position_debut = position_fin
	position_fin = position_debut + 1
	name =''
	label=0
# Tant que l'on ne rencontre pas de 0x00 on continue a lire le nom
	while int(tools.liste_hex_2_dec(Liste[position_debut:position_fin])) != 0:
# On prend la taille du label a lire
		taille = int(tools.liste_hex_2_dec(Liste[position_debut:position_fin]))	
		for i in range(taille):
			position_debut = position_fin
			position_fin = position_debut + 1
			if tools.verificateur_avant_constructeur(Liste, position_debut, position_fin):
				name +=  bytes.fromhex(str(Liste[position_debut:position_fin][0][0])+str(Liste[position_debut:position_fin][0][1])).decode('utf-8')
		position_debut = position_fin
		position_fin = position_debut + 1
# On vérifie si c'est le dernier label qui a été écrit pour mettre '.' ou ':'
		if int(tools.liste_hex_2_dec(Liste[position_debut:position_fin])) != 0:
			name +="."
		label += 1
	lenght=len(name)-1
	position_debut = position_fin
	position_fin = position_debut + 2
	if tools.verificateur_avant_constructeur(Liste, position_debut, position_fin):
		Type = tools.constructeur_chaine_caracteres(0, "Type","0x" +"".join(Liste[position_debut:position_fin]),tools.dico_type_dns_typen.get(tools.dico_type_dns_type.get(Liste[position_debut:position_fin][1])))
		Typen = tools.dico_type_dns_type.get(Liste[position_debut:position_fin][1])
	position_debut = position_fin
	position_fin = position_debut + 2
	if tools.verificateur_avant_constructeur(Liste, position_debut, position_fin):
		Class = tools.constructeur_chaine_caracteres(0, "Class","0x" +"".join(Liste[position_debut:position_fin]),"Internet")
	res += tools.constructeur_chaine_caracteres(3, name , " type "+ Typen + ", class IN")
	res += tools.constructeur_chaine_caracteres(4, "Name" , name)
	res += tools.constructeur_chaine_caracteres(4, "Name Lenght" , lenght)
	res += tools.constructeur_chaine_caracteres(4, "Label Count" , label)
	res += tools.constructeur_chaine_caracteres(4, "Class" , "IN")
	if n_answers >0:	
		res += "\t\tAnswers: \n"
	nombre =1
	for i in range(n_answers):
		aux=""

		ret=DNS_Answer(Liste, nombre, position_debut,position_fin, aux)
		position_debut=ret[1]-1
		position_fin=ret[2]
		res+=ret[0]
	if n_authority > 0:
		res += "\t\tAuthoritative nameservers: \n"
	for i in range(n_authority):
		aux=""
		ret=DNS_Authoritative(Liste, nombre, position_debut,position_fin, aux)
		position_debut=ret[1]-1
		position_fin=ret[2]
		res+=ret[0]
	if n_additional > 0:	
		res += "\t\tAdditional informations: \n"
	for i in range(n_additional):
		aux=""
		ret=DNS_Answer(Liste, nombre, position_debut,position_fin, aux)
		position_debut=ret[1]-1
		position_fin=ret[2]
		res+=ret[0]
	#print(Liste[position_debut:position_fin])
	#ret= DNS_Answer(Liste, nombre, position_debut,position_fin, aux)
	#position_debut=ret[1]
	#position_fin=ret[2]
	#res+=ret[0]	
	#res+=ret[0]
	#position_debut=ret[1]
	#position_fin=ret[2]
	#print(Liste[position_debut:position_fin])
	return res

# a écrire
def analyse_DHCP(Liste):
	"""
	list[str] -> str
	Renvoyer un str représentant l'entête DHCP
	"""
	res = "\tDHCP : \n"
	position_debut = 0
	position_fin = 1
	if tools.verificateur_avant_constructeur(Liste, position_debut, position_fin):
		valeur = "".join(Liste[position_debut:position_fin])
		interpretation = "non connue" if valeur not in tools.dico_opcod_dhcp else tools.dico_opcod_dhcp.get(valeur)
		res += tools.constructeur_chaine_caracteres(2, "Operation Code", "0x" + valeur, interpretation)
	position_debut = position_fin
	position_fin = 2
	if tools.verificateur_avant_constructeur(Liste, position_debut, position_fin):
		valeur = "".join(Liste[position_debut:position_fin])
		res += tools.constructeur_chaine_caracteres(2, "Hardware Type", "0x" + valeur, "Ethernet" if valeur == "01" else "")
	position_debut = position_fin
	position_fin = 3
	if tools.verificateur_avant_constructeur(Liste, position_debut, position_fin):
		valeur = "".join(Liste[position_debut:position_fin])
		interpretation = tools.liste_hex_2_dec(valeur)
		longueur_hardware = int(interpretation)
		res += tools.constructeur_chaine_caracteres(2, "Hardware Address Length", "0x" + valeur, interpretation)
	position_debut = position_fin
	position_fin = 4
	if tools.verificateur_avant_constructeur(Liste, position_debut, position_fin):
		valeur = "".join(Liste[position_debut:position_fin])
		res += tools.constructeur_chaine_caracteres(2, "Hops", "0x" + valeur)
	position_debut = position_fin
	position_fin = 8
	if tools.verificateur_avant_constructeur(Liste, position_debut, position_fin):
		valeur = "".join(Liste[position_debut:position_fin])
		interpretation = tools.liste_hex_2_dec(valeur)
		res += tools.constructeur_chaine_caracteres(2, "Transaction Identifier", "0x" + valeur, interpretation)
	position_debut = position_fin
	position_fin = 10
	if tools.verificateur_avant_constructeur(Liste, position_debut, position_fin):
		valeur = "".join(Liste[position_debut:position_fin])
		interpretation = tools.liste_hex_2_dec(valeur) + " seconds"
		res += tools.constructeur_chaine_caracteres(2, "Seconds", "0x" + valeur, interpretation)
	position_debut = position_fin
	position_fin = 12
	if tools.verificateur_avant_constructeur(Liste, position_debut, position_fin):
		valeur = "".join(Liste[position_debut:position_fin])
		valeur = format(int(valeur, base = 16), '016b')
		res += tools.constructeur_chaine_caracteres(2, "Flags", "0x" + valeur)
		boardcast_flag = valeur[0]
		boardcast_interpretation = "boardcast" if boardcast_flag == "1" else "unicast"
		res += tools.constructeur_chaine_caracteres(3, "Boardcast Flags", "0x" + boardcast_flag, boardcast_interpretation)
		reserve_flag = valeur[1:]
		res += tools.constructeur_chaine_caracteres(3, "Reserved Flags", "0x" + reserve_flag)
	position_debut = position_fin
	position_fin = 16
	if tools.verificateur_avant_constructeur(Liste, position_debut, position_fin):
		valeur = "".join(Liste[position_debut:position_fin])
		interpretation = ".".join([str(int(hex, base = 16)) for hex in Liste[position_debut:position_fin]])
		res += tools.constructeur_chaine_caracteres(2, "Client IP Adress", "0x" + valeur, interpretation)
	position_debut = position_fin
	position_fin = 20
	if tools.verificateur_avant_constructeur(Liste, position_debut, position_fin):
		valeur = "".join(Liste[position_debut:position_fin])
		interpretation = ".".join([str(int(hex, base = 16)) for hex in Liste[position_debut:position_fin]])
		res += tools.constructeur_chaine_caracteres(2, "Your IP Adress", "0x" + valeur, interpretation)
	position_debut = position_fin
	position_fin = 24
	if tools.verificateur_avant_constructeur(Liste, position_debut, position_fin):
		valeur = "".join(Liste[position_debut:position_fin])
		interpretation = ".".join([str(int(hex, base = 16)) for hex in Liste[position_debut:position_fin]])
		res += tools.constructeur_chaine_caracteres(2, "Server IP Adress", "0x" + valeur, interpretation)
	position_debut = position_fin
	position_fin = 28
	if tools.verificateur_avant_constructeur(Liste, position_debut, position_fin):
		valeur = "".join(Liste[position_debut:position_fin])
		interpretation = tools.liste_hex_2_IP(Liste[position_debut:position_fin])
		res += tools.constructeur_chaine_caracteres(2, "Gateway IP Adress", "0x" + valeur, interpretation)
	position_debut = position_fin
	position_fin = 44
	if tools.verificateur_avant_constructeur(Liste, position_debut, position_debut + longueur_hardware):
		valeur = "".join(Liste[position_debut:position_debut + longueur_hardware])
		interpretation = tools.liste_hex_2_MAC(Liste[position_debut: position_debut + longueur_hardware])
		res += tools.constructeur_chaine_caracteres(2, "Client Hardware Adress", "0x" + valeur, interpretation)
	position_debut = position_fin
	position_fin = 108
	if tools.verificateur_avant_constructeur(Liste, position_debut, position_fin):
		valeur = "".join(Liste[position_debut:position_fin])
		if(valeur[0:2] == "00"):
			interpretation = "Not given"
		else:
			interpretation = tools.liste_hex_2_ASCII(Liste[position_debut:position_fin])
		res += tools.constructeur_chaine_caracteres(2, "Server Host Name", interpretation)
	position_debut = position_fin
	position_fin = 236
	if tools.verificateur_avant_constructeur(Liste, position_debut, position_fin):
		valeur = "".join(Liste[position_debut:position_fin])
		if(valeur[0:2] == "00"):
			interpretation = "Not given"
		else:
			interpretation = tools.liste_hex_2_ASCII(Liste[position_debut:position_fin])
		res += tools.constructeur_chaine_caracteres(2, "Boot File Name", interpretation)
	position_debut = position_fin
	position_fin = 240
	if tools.verificateur_avant_constructeur(Liste, position_debut, position_fin):
		valeur = "".join(Liste[position_debut:position_fin])
		res += tools.constructeur_chaine_caracteres(2, "Magic cookie", "Magic cookie")
	position_debut = position_fin
	position_fin = 241
	
	res += analyse_DHCP_option(Liste[position_debut:])
	
	return res

def DNS_Answer(Liste, nombre, position_debut,position_fin, res):
	name =''
	label = 0
	# On passe au premier octet de la réponse
	position_debut = position_fin
	position_fin = position_debut + 1
	while int(tools.liste_hex_2_dec(Liste[position_debut:position_fin])) != 0: 
		if Liste[position_debut:position_fin][0] == "c0":
			# On passe a l'octet qui nous indique ou lire le label
			position_debut = position_fin
			position_fin = position_debut + 1
			# On se place a l'endroit indiqué par l'octet au dessus
			debut_aux = int(tools.liste_hex_2_dec(Liste[position_debut:position_fin]))
			fin_aux = debut_aux + 1
			while int(tools.liste_hex_2_dec(Liste[debut_aux:fin_aux])) != 0 and Liste[debut_aux:fin_aux][0] !="c0":
				taille = int(tools.liste_hex_2_dec(Liste[debut_aux:fin_aux]))		
				for i in range(taille):			
					# On lit chacun des octets jusqu'a la fin du label
					debut_aux = fin_aux
					fin_aux = debut_aux + 1
					if tools.verificateur_avant_constructeur(Liste, debut_aux, fin_aux):
						name +=  bytes.fromhex(str(Liste[debut_aux:fin_aux][0][0])+str(Liste[debut_aux:fin_aux][0][1])).decode('utf-8')
				# On passe au prochain label
				debut_aux = fin_aux
				fin_aux = debut_aux + 1
				# On vérifie si c'est le dernier label qui a été écrit pour mettre '.' ou ':'
				if int(tools.liste_hex_2_dec(Liste[debut_aux:fin_aux])) != 0:
					name +="."
				label += 1
			# On passe au prochain champ de la réponse
			position_debut = position_fin
			position_fin = position_debut + 1
			break
		# On prend la taille du label a lire dans le cas ou l'on doit le lire dans les octets qui suivent
		taille = int(tools.liste_hex_2_dec(Liste[position_debut:position_fin]))	
		for i in range(taille):
			# On lit chacun des octets jusqu'a la fin du label
			position_debut = position_fin
			position_fin = position_debut + 1
			if tools.verificateur_avant_constructeur(Liste, position_debut, position_fin):
				name +=  bytes.fromhex(str(Liste[position_debut:position_fin][0][0])+str(Liste[position_debut:position_fin][0][1])).decode('utf-8')
		# On passe au prochain label
		position_debut = position_fin
		position_fin = position_debut + 1
		# On vérifie si c'est le dernier label qui a été écrit pour mettre '.' ou ':'
		if int(tools.liste_hex_2_dec(Liste[position_debut:position_fin])) != 0:
			name +="."
		label += 1
	lenght=len(name)-1
	position_fin = position_debut + 2
	if tools.verificateur_avant_constructeur(Liste, position_debut, position_fin):
		Type = tools.constructeur_chaine_caracteres(0, "Type","0x" +"".join(Liste[position_debut:position_fin]),str(tools.dico_type_dns_typen.get(str(tools.dico_type_dns_type.get(Liste[position_debut:position_fin][1])))))
		Typen = str(tools.dico_type_dns_type.get(Liste[position_debut:position_fin][1]))
		Typeall = str(tools.dico_type_dns_typen.get(tools.dico_type_dns_type.get(Liste[position_debut:position_fin][1])))
	position_debut = position_fin
	position_fin = position_debut + 2
	if tools.verificateur_avant_constructeur(Liste, position_debut, position_fin):
		Class = "0x" +"".join(Liste[position_debut:position_fin])
	position_debut = position_fin
	position_fin = position_debut + 4
	if tools.verificateur_avant_constructeur(Liste, position_debut, position_fin):
		ttl = str(int(tools.liste_hex_2_dec(Liste[position_debut:position_fin]))) + " (" + tools.sec_to_hours(int(tools.liste_hex_2_dec(Liste[position_debut:position_fin])))+")"
	position_debut = position_fin
	position_fin = position_debut + 2
	if tools.verificateur_avant_constructeur(Liste, position_debut, position_fin):
		dl = int(tools.liste_hex_2_dec(Liste[position_debut:position_fin]))
	head = ""
	ret = ["", 0, 0]
	if Typen == "CNAME":
		cname=""
		ret =cnamef(Liste, position_debut,position_fin,cname)
		position_debut=ret[1]
		position_fin=ret[2]
		head = "cname"
	if Typen == "A":
		ret = adresse(Liste, position_debut,position_fin)
		position_debut=ret[1]
		position_fin=ret[2]
		head="addr"
	if Typen == "AAAA":
		ret = adresse6(Liste, position_debut,position_fin)
		position_debut=ret[1]
		position_fin=ret[2]
		head="addr"
	res += tools.constructeur_chaine_caracteres(3, name , " type "+ Typen + ", class IN" + ", "+head+" "+ret[0])
	res += tools.constructeur_chaine_caracteres(4, "Name" , name)
	res += tools.constructeur_chaine_caracteres(4, "Type" , Typen, Typeall)
	res += tools.constructeur_chaine_caracteres(4, "Class",Class,"Internet")
	res += tools.constructeur_chaine_caracteres(4, "Time to live",ttl)
	res+=tools.constructeur_chaine_caracteres(4, "Data lenght",dl)
	res += tools.constructeur_chaine_caracteres(4, Typen ,ret[0])
	return res, position_debut, position_fin

def cnamef(Liste, position_debut,position_fin, res):
	name=""
	position_debut += 1
	position_fin = position_debut + 1
	
	while int(tools.liste_hex_2_dec(Liste[position_debut:position_fin])) != 0: 
		position_debut = position_fin
		position_fin = position_debut + 1
		if Liste[position_debut:position_fin][0] == "c0":
			position_debut = position_fin
			position_fin = position_debut + 1
			debut_aux = int(tools.liste_hex_2_dec(Liste[position_debut:position_fin]))
			fin_aux = debut_aux + 1
			while int(tools.liste_hex_2_dec(Liste[debut_aux:fin_aux])) != 0 and Liste[debut_aux:fin_aux][0] !="c0":
				taille = int(tools.liste_hex_2_dec(Liste[debut_aux:fin_aux]))	
				for i in range(taille):
					debut_aux = fin_aux
					fin_aux = debut_aux + 1
					if tools.verificateur_avant_constructeur(Liste, debut_aux, fin_aux):
						name +=  bytes.fromhex(str(Liste[debut_aux:fin_aux][0][0])+str(Liste[debut_aux:fin_aux][0][1])).decode('utf-8')
				debut_aux = fin_aux
				fin_aux = debut_aux + 1
	# On vérifie si c'est le dernier label qui a été écrit pour mettre '.' ou ':'
				if int(tools.liste_hex_2_dec(Liste[debut_aux:fin_aux])) != 0:
					name +="."
			#position_debut = position_fin
			#position_fin = position_debut + 1
			break
			# On prend la taille du label a lire
		taille = int(tools.liste_hex_2_dec(Liste[position_debut:position_fin]))	
		for i in range(taille):
			position_debut = position_fin
			position_fin = position_debut + 1
			if tools.verificateur_avant_constructeur(Liste, position_debut, position_fin):
				name +=  bytes.fromhex(str(Liste[position_debut:position_fin][0][0])+str(Liste[position_debut:position_fin][0][1])).decode('utf-8')
		position_debutt = position_fin
		position_fint = position_debutt + 1
	# On vérifie si c'est le dernier label qui a été écrit pour mettre '.' ou pas
		if int(tools.liste_hex_2_dec(Liste[position_debutt:position_fint])) != 0 and int(tools.liste_hex_2_dec(Liste[position_debut:position_fin])) != 0:
			name +="."
		#else:
			#position_debut = position_fin
			#position_fin = position_debut + 1
	res += name
	return res, position_debut,position_fin

def mnamef(Liste, position_debut,position_fin, res):
	name=""
	#position_debut += 1
	#position_fin = position_debut +1
	while int(tools.liste_hex_2_dec(Liste[position_debut:position_fin])) != 0:
		# Cas spécial ou deux noms se suivent il faut faire en sorte que l'on a pas '00' avant d'entrer dans la boucle 
		position_fin = position_debut +1
		position_debut = position_fin
		position_fin = position_debut + 1
		if Liste[position_debut:position_fin][0] == "c0":
			position_debut = position_fin
			position_fin = position_debut + 1
			debut_aux = int(tools.liste_hex_2_dec(Liste[position_debut:position_fin]))
			fin_aux = debut_aux + 1
			while int(tools.liste_hex_2_dec(Liste[debut_aux:fin_aux])) != 0 and Liste[debut_aux:fin_aux][0] !="c0":
				taille = int(tools.liste_hex_2_dec(Liste[debut_aux:fin_aux]))	
				for i in range(taille):
					debut_aux = fin_aux
					fin_aux = debut_aux + 1
					if tools.verificateur_avant_constructeur(Liste, debut_aux, fin_aux):
						name +=  bytes.fromhex(str(Liste[debut_aux:fin_aux][0][0])+str(Liste[debut_aux:fin_aux][0][1])).decode('utf-8')
				debut_aux = fin_aux
				fin_aux = debut_aux + 1
	# On vérifie si c'est le dernier label qui a été écrit pour mettre '.' ou ':'
				if int(tools.liste_hex_2_dec(Liste[debut_aux:fin_aux])) != 0:
					name +="."
			#position_debut = position_fin
			#position_fin = position_debut + 1
			break
			# On prend la taille du label a lire
		taille = int(tools.liste_hex_2_dec(Liste[position_debut:position_fin]))	
		for i in range(taille):
			position_debut = position_fin
			position_fin = position_debut + 1
			if tools.verificateur_avant_constructeur(Liste, position_debut, position_fin):
				name +=  bytes.fromhex(str(Liste[position_debut:position_fin][0][0])+str(Liste[position_debut:position_fin][0][1])).decode('utf-8')
		#position_debut = position_fin
		#position_fin = position_debut + 1
		position_debutt = position_fin
		position_fint = position_debutt + 1
	# On vérifie si c'est le dernier label qui a été écrit pour mettre '.' ou ':'
		if int(tools.liste_hex_2_dec(Liste[position_debutt:position_fint])) != 0 and int(tools.liste_hex_2_dec(Liste[position_debut:position_fin])) != 0:
			name +="."
		#else:
			#position_debut = position_fin
			#position_fin = position_debut + 1
	res += name
	return res, position_debut,position_fin

def adresse(Liste, position_debut,position_fin):
	res=""
	position_debut = position_fin
	position_fin = position_debut + 4
	ip = [str(int(hex, base = 16)) for hex in Liste[position_debut:position_fin]]
	if tools.verificateur_avant_constructeur(Liste, position_debut, position_fin):
		res +=  ".".join(ip)
	return res, position_debut,position_fin

def adresse6(Liste, position_debut,position_fin):
	res=""
	for i in range(8):
		position_debut = position_fin
		position_fin = position_debut + 2
		if tools.verificateur_avant_constructeur(Liste, position_debut, position_fin):
			res +=  Liste[position_debut:position_fin][0] + Liste[position_debut:position_fin][1]
			if i != 7:
				res+=":"
	return res, position_debut,position_fin


def DNS_Authoritative(Liste, nombre, position_debut,position_fin, res):
	name =''
	label = 0
	# On passe au premier octet de la réponse
	position_debut = position_fin
	position_fin = position_debut + 1
	while int(tools.liste_hex_2_dec(Liste[position_debut:position_fin])) != 0: 
		if Liste[position_debut:position_fin][0] == "c0":
			# On passe a l'octet qui nous indique ou lire le label
			position_debut = position_fin
			position_fin = position_debut + 1
			# On se place a l'endroit indiqué par l'octet au dessus
			debut_aux = int(tools.liste_hex_2_dec(Liste[position_debut:position_fin]))
			fin_aux = debut_aux + 1
			while int(tools.liste_hex_2_dec(Liste[debut_aux:fin_aux])) != 0 and Liste[debut_aux:fin_aux][0] !="c0":
				taille = int(tools.liste_hex_2_dec(Liste[debut_aux:fin_aux]))		
				for i in range(taille):			
					# On lit chacun des octets jusqu'a la fin du label
					debut_aux = fin_aux
					fin_aux = debut_aux + 1
					if tools.verificateur_avant_constructeur(Liste, debut_aux, fin_aux):
						name +=  bytes.fromhex(str(Liste[debut_aux:fin_aux][0][0])+str(Liste[debut_aux:fin_aux][0][1])).decode('utf-8')
				# On passe au prochain label
				debut_aux = fin_aux
				fin_aux = debut_aux + 1
				# On vérifie si c'est le dernier label qui a été écrit pour mettre '.' ou ':'
				if int(tools.liste_hex_2_dec(Liste[debut_aux:fin_aux])) != 0:
					name +="."
				label += 1
			# On passe au prochain champ de la réponse
			position_debut = position_fin
			position_fin = position_debut + 1
			break
		# On prend la taille du label a lire dans le cas ou l'on doit le lire dans les octets qui suivent
		taille = int(tools.liste_hex_2_dec(Liste[position_debut:position_fin]))	
		for i in range(taille):
			# On lit chacun des octets jusqu'a la fin du label
			position_debut = position_fin
			position_fin = position_debut + 1
			if tools.verificateur_avant_constructeur(Liste, position_debut, position_fin):
				name +=  bytes.fromhex(str(Liste[position_debut:position_fin][0][0])+str(Liste[position_debut:position_fin][0][1])).decode('utf-8')
		# On passe au prochain label
		position_debut = position_fin
		position_fin = position_debut + 1
		# On vérifie si c'est le dernier label qui a été écrit pour mettre '.' ou ':'
		if int(tools.liste_hex_2_dec(Liste[position_debut:position_fin])) != 0:
			name +="."
		label += 1
	lenght=len(name)-1
	position_fin = position_debut + 2
	if tools.verificateur_avant_constructeur(Liste, position_debut, position_fin):
		Type = tools.constructeur_chaine_caracteres(0, "Type","0x" +"".join(Liste[position_debut:position_fin]),str(tools.dico_type_dns_typen.get(str(tools.dico_type_dns_type.get(Liste[position_debut:position_fin][1])))))
		Typen = str(tools.dico_type_dns_type.get(Liste[position_debut:position_fin][1]))
		Typeall = str(tools.dico_type_dns_typen.get(tools.dico_type_dns_type.get(Liste[position_debut:position_fin][1])))
	position_debut = position_fin
	position_fin = position_debut + 2
	if tools.verificateur_avant_constructeur(Liste, position_debut, position_fin):
		Class = "0x" +"".join(Liste[position_debut:position_fin])
	position_debut = position_fin
	position_fin = position_debut + 4
	if tools.verificateur_avant_constructeur(Liste, position_debut, position_fin):
		ttl = str(int(tools.liste_hex_2_dec(Liste[position_debut:position_fin]))) + " (" + tools.sec_to_hours(int(tools.liste_hex_2_dec(Liste[position_debut:position_fin])))+")"
	position_debut = position_fin
	position_fin = position_debut + 2
	if tools.verificateur_avant_constructeur(Liste, position_debut, position_fin):
		dl = int(tools.liste_hex_2_dec(Liste[position_debut:position_fin]))
	cname=""
	
	ret1 =cnamef(Liste, position_debut,position_fin,cname)
	position_debut=ret1[1]
	position_fin=ret1[2]
	cname=""
	position_fin = position_fin + 1
	ret2 =mnamef(Liste, position_debut,position_fin,cname)
	position_debut=ret2[1]
	position_fin=ret2[2]
	res += tools.constructeur_chaine_caracteres(3, name , " type "+ Typen + ", class IN" + ", "+"mname"+" "+ret1[0])
	res += tools.constructeur_chaine_caracteres(4, "Name" , name)
	res += tools.constructeur_chaine_caracteres(4, "Type" , Typen, Typeall)
	res += tools.constructeur_chaine_caracteres(4, "Class",Class,"Internet")
	res += tools.constructeur_chaine_caracteres(4, "Time to live",ttl)
	res+=tools.constructeur_chaine_caracteres(4, "Data lenght",dl)
	res += tools.constructeur_chaine_caracteres(4, "Primary Name Server" ,ret1[0])
	res += tools.constructeur_chaine_caracteres(4, "Responsible authority's mailbox" ,ret2[0])
	position_debut = position_fin
	position_fin = position_debut + 4
	if tools.verificateur_avant_constructeur(Liste, position_debut, position_fin):
		res += tools.constructeur_chaine_caracteres(4, "Serial Number",int(tools.liste_hex_2_dec(Liste[position_debut:position_fin])))
	position_debut = position_fin
	position_fin = position_debut + 4
	if tools.verificateur_avant_constructeur(Liste, position_debut, position_fin):
		res += tools.constructeur_chaine_caracteres(4, "Refresh Interval",int(tools.liste_hex_2_dec(Liste[position_debut:position_fin])),tools.sec_to_hours(int(tools.liste_hex_2_dec(Liste[position_debut:position_fin]))))
	position_debut = position_fin
	position_fin = position_debut + 4
	if tools.verificateur_avant_constructeur(Liste, position_debut, position_fin):
		res += tools.constructeur_chaine_caracteres(4, "Retry Interval",int(tools.liste_hex_2_dec(Liste[position_debut:position_fin])),tools.sec_to_hours(int(tools.liste_hex_2_dec(Liste[position_debut:position_fin]))))
	position_debut = position_fin
	position_fin = position_debut + 4
	if tools.verificateur_avant_constructeur(Liste, position_debut, position_fin):
		res += tools.constructeur_chaine_caracteres(4, "Expire Limit",int(tools.liste_hex_2_dec(Liste[position_debut:position_fin])),tools.sec_to_hours(int(tools.liste_hex_2_dec(Liste[position_debut:position_fin]))))
	position_debut = position_fin
	position_fin = position_debut + 4
	if tools.verificateur_avant_constructeur(Liste, position_debut, position_fin):
		res += tools.constructeur_chaine_caracteres(4, "Minimum TTL",int(tools.liste_hex_2_dec(Liste[position_debut:position_fin])),tools.sec_to_hours(int(tools.liste_hex_2_dec(Liste[position_debut:position_fin]))))
	return res, position_debut, position_fin

def analyse_DHCP_option(Liste):
	"""
	list[str] -> str, int, list[str, str, str]
	Renvoyer un les résultats d'analyse d'otpion DHCP
	"""
	position_debut = 0
	position_fin = 1
	res = ""
	
	# res += (str(position_debut) + ";" + str(position_fin) + ";" + ",".join(Liste[position_debut:position_fin]))
	# initialisation des variables
	tag_option = Liste[position_debut]
	longueur_data = 0
	longueur_totale = 1
	liste_champs_valeur_interpretation = list()
	interpretation = "option non connue" if tag_option not in tools.dico_option_dhcp else tools.dico_option_dhcp.get(tag_option)

	while tools.verificateur_avant_constructeur(Liste, position_debut, position_fin) and Liste[position_debut] not in ["00", "ff"]:
		
		# reinitialisation des variables
		tag_option = Liste[position_debut]
		longueur_data = 0
		longueur_totale = 1
		interpretation = "option non connue" if tag_option not in tools.dico_option_dhcp else tools.dico_option_dhcp.get(tag_option)
		

		if(len(Liste[position_debut:]) <= 2): # option format non valide
			res += "Format DHCP option non valide.Interruption d'analyse.\n"
			break
		# DHCP option : type, longueur, valeur
		longueur_data = Liste[position_debut+1]
		longueur_data_en_int = int(Liste[position_debut+1], 16)
		position_fin = position_debut + longueur_data_en_int + 2
		if tools.verificateur_avant_constructeur(Liste, position_debut, position_fin):
			# information sur option
			champs = "Option" if tag_option not in tools.dico_option_dhcp else tools.dico_option_dhcp.get(tag_option)
			res += tools.constructeur_chaine_caracteres(2, champs, Liste[position_debut], interpretation)
			res += tools.constructeur_chaine_caracteres(3, "Length", longueur_data, str(longueur_data_en_int))
			
			# valeur par defaut
			indentation = 3
			interpretation_sous_champs = "Option" if tag_option not in tools.dico_option_dhcp else tools.dico_option_dhcp.get(tag_option)
			valeur_en_liste = Liste[position_debut+2:position_fin]
			valeur_chainee = "".join(valeur_en_liste)

			# pour differents types de champs, on va dans le bloc correspondant
			# dico
			if tag_option in tools.dhcp_option_liste_interpretation_dico:
				if tag_option == "35": # DHCP Message Type
					interpretation_sous_champs = "inconnu" if valeur_chainee not in tools.dico_type_dhcp else tools.dico_type_dhcp.get(valeur_chainee)
				elif tag_option == "74": # DHCP Auto-configuration
					interpretation_sous_champs = "Set" if valeur_chainee == "01" else "Not Set"
				res += tools.constructeur_chaine_caracteres(indentation, champs, valeur_chainee, interpretation_sous_champs)
			
			# adresse IP 
			elif tag_option in tools.dhcp_option_liste_interpretation_IP:
				for cpt in range(longueur_data_en_int//4):
					interpretation_sous_champs = tools.liste_hex_2_IP(valeur_en_liste[cpt:cpt+4])
					res += tools.constructeur_chaine_caracteres(indentation, champs, valeur_chainee[cpt*8:cpt*8+8], interpretation_sous_champs)
			
			# temps
			elif tag_option in tools.dhcp_option_liste_interpretation_temps:
				interpretation_sous_champs = tools.sec_to_hours(int(valeur_chainee, 16))
				res += tools.constructeur_chaine_caracteres(indentation, champs, valeur_chainee, interpretation_sous_champs)
			
			# chaine de caractères
			elif tag_option in tools.dhcp_option_liste_interpretation_chaine:
				interpretation_sous_champs = bytes.fromhex(valeur_chainee).decode("ASCII")
				res += tools.constructeur_chaine_caracteres(indentation, champs, interpretation_sous_champs)
			
			# plusieurs champs
			elif tag_option in tools.dhcp_option_liste_interpretation_multichamps:
				if tag_option == "37": # Parameter Request List
					# champs, valeur_chainee, interpretation = 
					for cpt in range(len(valeur_en_liste)):
						res += tools.constructeur_chaine_caracteres(indentation, champs + " Item", valeur_en_liste[cpt], "" if valeur_en_liste[cpt] not in tools.dico_option_dhcp else tools.dico_option_dhcp.get(valeur_en_liste[cpt]))
				elif tag_option == "3d": # Client Identifier
					res += tools.constructeur_chaine_caracteres(indentation, "Hardware Type", valeur_en_liste[0], "Ethernet" if valeur_chainee[0] == "01" else "")
					res += tools.constructeur_chaine_caracteres(indentation, "Client MAC Address", tools.liste_hex_2_MAC(valeur_en_liste[1:]))
			
			# on ne connait pas le protocol, et on imprime les octets directement
			else :
				res += tools.constructeur_chaine_caracteres(indentation, champs, valeur_chainee)
			
			#deplacer le pointeur de position
			# if(tag_option == "0c"):
				
			position_debut = position_fin
			position_fin += 1
	if tools.verificateur_avant_constructeur(Liste, position_debut, position_fin):
		tag_option = Liste[position_debut]
		if tag_option == "ff":
			res += tools.constructeur_chaine_caracteres(2, "End", tag_option, tools.dico_option_dhcp.get(tag_option))
			position_debut = position_fin
			position_fin += 1
	if tools.verificateur_avant_constructeur(Liste, position_debut, position_fin):
		tag_option = Liste[position_debut]
		if tag_option == "00":
			nb_00 = len(Liste[position_debut:])
			res += tools.constructeur_chaine_caracteres(2, "Padding", ",".join(Liste[position_debut:position_fin]))
	return res