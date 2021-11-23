import convertions

# Indique qu'il y a une erreur et sa position
def erreur(trame, info):
	i = len(trame)-1
	while i>=0:
		if formatValideOffset(trame[i]):
			print("erreur :" + info, trame[i])
			break
		i-=1

# verifier si un caractere est un nombre hexadecimal
def est_hex(cara):
	if len(cara) != 1:
		return False

	if not("a" <= cara.lower() <= "f" or "0" <= cara <= "9"):
		return False

	return True

# Valide le format des offset de la trame
def formatValideOffset(offset):
	if len(offset) < 3:
		return False

	for caractere in offset:
		if not est_hex(caractere):
			return False

	return True

# Valide le format des octets de la trame
def formatValideByte(x):
	if len(x) != 2:
		return False

	for e in x:
		if not est_hex(e):
			return False

	return True

# Créer la structure générale des trames : créer une liste composée de listes et chaque liste est une trame
def LtoLL(L):
	LL = []
	trame_courante = []
	ignorer_ligne = False # il y a une erreur et la lecture de cette trame doit etre arretee
	ignorer_element = False
	point_darret = 0 # pour voir s'il s'agit d'un octet invalide
	octet_invalide = False # pour marquer le type d'erreur

	for indice_ligne in range(len(L)):
		offset_de_la_ligne = L[indice_ligne][0] # qui doit etre offset
		offset_en_hex = int(offset_de_la_ligne, base = 16)
		# print("indice ligne = " + str(indice_ligne) + ", offset : " + offset_de_la_ligne)
		if formatValideOffset(offset_de_la_ligne) :
			if offset_en_hex == 0:
				if not ignorer_ligne:
					LL.append(trame_courante)
				trame_courante = []
				ignorer_ligne = False
				ignorer_element = False
				point_darret = 0
				octet_invalide = False

			if ignorer_ligne == False:
				if indice_ligne < len(L)-1 and offset_en_hex != 0:
					# en cas d'erreur
					if len(trame_courante) < offset_en_hex:
						# determiner s'il s'agit d'octet invalide ou ligne incomplète
						# le cas d'octet invalide

						if octet_invalide:
							print("point d'arret, offset détecté : "
								+ str(hex(point_darret)) + "," + "0x" + offset_de_la_ligne + ", trame " + str(len(LL)))
							erreur(trame_courante, "octet invalide")
							trame_courante.append("-1")
							
						else:
							print("offset reel, offset détecté : "
								+ str(hex(len(trame_courante))) + "," + "0x" +  offset_de_la_ligne)
							# une information pour indiquer une erreur dans le fichier
							trame_courante.append("-2")
							erreur(trame_courante, "ligne incomplète")
						LL.append(trame_courante)
						ignorer_ligne = True

				while(len(trame_courante) > offset_en_hex):
					trame_courante.pop()
				if point_darret == offset_en_hex:
					ignorer_element = False
					

				for indice_element in range(1, len(L[indice_ligne])):
					element_courant = L[indice_ligne][indice_element]
					# print(element_courant, formatValideByte(element_courant), ignorer_element)
					if formatValideByte(element_courant) and not ignorer_element:
						trame_courante.append(element_courant)
						# print("append: " + element_courant)
					elif not formatValideByte(element_courant): 
						point_darret = len(trame_courante)
						ignorer_element = True
						if(len(element_courant) == 2):
								octet_invalide = True
								# print(hex(len(trame_courante)), element_courant)

					
				else:
					for indice_element in range(1, len(L[indice_ligne])):
						element_courant = L[indice_ligne][indice_element]
						# if formatValideByte(element_courant):
						if formatValideByte(element_courant) and not ignorer_element:
							# print("append: " + element_courant)
							trame_courante.append(element_courant)
						elif not formatValideByte(element_courant): 
							point_darret = len(trame_courante)
							ignorer_element = True
							if(len(element_courant) == 2):
								octet_invalide = True
								# print(hex(len(trame_courante)), element_courant)

				if indice_ligne == len(L)-1:
					LL.append(trame_courante)
	del LL[0]
	return LL

def constructeur_chaine_caracteres(indentation, champs, valeur, interpretation = ""):
	res = "\t"*indentation
	res += champs
	res += " : "
	res += str(valeur)
	if interpretation != "":
		res += " (" + interpretation + ")"
	res += "\n"
	return res

def verificateur_avant_constructeur(Liste, position_debut, position_fin):
	if(len(Liste) >= position_fin):
		return True
	return False

def constructeur_chaine_integre(Liste, position_debut, position_fin, indentation, champs, valeur, interpretation = ""):
	if verificateur_avant_constructeur(Liste, position_debut, position_fin):
		return constructeur_chaine_caracteres(indentation, champs, valeur, interpretation)
	return ""

# Renvoie un str représentant l'entête ETHERNET
def analyseETHERNET(L):
	res = "\tETHERNET :\n"

	position_debut = 0
	position_fin = 6
	if verificateur_avant_constructeur(L, position_debut, position_fin):
		res += constructeur_chaine_caracteres(2, "Adresse Mac Destination", ":".join(L[position_debut:position_fin]))
	
	
	position_debut = position_fin
	position_fin = 12
	if verificateur_avant_constructeur(L, position_debut, position_fin):
		res += constructeur_chaine_caracteres(2, "Adresse Mac Source", ":".join(L[position_debut:position_fin]))
	
	position_debut = position_fin
	position_fin = 14
	if verificateur_avant_constructeur(L, position_debut, position_fin):
		type_str = "".join(L[position_debut:position_fin])
		type_hex = convertions.dico_type_eternet.get(type_str)
		if type_hex is not None:
			res += constructeur_chaine_caracteres(2, "Protocol", "0x" + type_str, type_hex)
		else: 
			res += constructeur_chaine_caracteres(2, "Protocol", "0x" + type_hex, "inconnu")	
	
	return res

# Renvoie un str représentant l'entête IP
# utiliser la meme structure pour faire la suite
# commencer par 0 au lieu de 14
def analyseIP(L):
	res = "\tIP : \n"

	position_debut = 0
	position_fin = 1
	if verificateur_avant_constructeur(L, position_debut, position_fin):
		res += constructeur_chaine_caracteres(2, "Version", "0x" + L[position_debut:position_fin][0][0], "IPv" + L[position_debut:position_fin][0][0])	
	if verificateur_avant_constructeur(L, position_debut, position_fin):
		res += constructeur_chaine_caracteres(2, "Header length", "0x" + L[position_debut:position_fin][0][1], str(int(L[position_debut:position_fin][0][1])*4))

	position_debut = position_fin
	position_fin = 2
	if verificateur_avant_constructeur(L, position_debut, position_fin):
		res += constructeur_chaine_caracteres(2, "Type of service", "0x" + L[position_debut:position_fin][0])

	position_debut = position_fin
	position_fin = 4
	if verificateur_avant_constructeur(L, position_debut, position_fin):
		res += constructeur_chaine_caracteres(2, "Total Length", "0x" + "".join(L[position_debut:position_fin]), convertions.liste_hex_2_dec(L[position_debut:position_fin]) + " octets")	
	
	position_debut = position_fin
	position_fin = 6
	if verificateur_avant_constructeur(L, position_debut, position_fin):
		res += constructeur_chaine_caracteres(2, "Identifier", "0x" + "".join(L[position_debut:position_fin]))	
	
	position_debut = position_fin
	position_fin = 8
	if verificateur_avant_constructeur(L, position_debut, position_fin):
		res += constructeur_chaine_caracteres(2, "Flags", "0x" + "".join(L[position_debut:position_fin]))
		Lb = format(int("".join(L[6:8]), base = 16), '016b') 
		res += constructeur_chaine_caracteres(3, "Reserve", Lb[0])
		res += constructeur_chaine_caracteres(3, "DF", Lb[1])
		res += constructeur_chaine_caracteres(3, "MF", Lb[2])
		res += constructeur_chaine_caracteres(3, "Fragment offset", str(hex(int(Lb[3:], base = 2))), str(int(Lb[3:], base = 2)*8) + " octets")
	
	position_debut = position_fin
	position_fin = 9
	if verificateur_avant_constructeur(L, position_debut, position_fin):
		res += constructeur_chaine_caracteres(2, "Time To Live", "0x" + "".join(L[position_debut:position_fin]), convertions.liste_hex_2_dec(L[position_debut:position_fin]))
	
	position_debut = position_fin
	position_fin = 10
	if verificateur_avant_constructeur(L, position_debut, position_fin):
		protocol_hex = "".join(L[position_debut:position_fin])
		if convertions.dico_type_ip_protocol.get(protocol_hex) is not None:
			res += constructeur_chaine_caracteres(2, "Protocol", "0x" + protocol_hex, convertions.dico_type_ip_protocol.get(protocol_hex))
		else: 
			res += constructeur_chaine_caracteres(2, "Protocol", "0x" + protocol_hex, "inconnu")
	
	position_debut = position_fin
	position_fin = 12
	if verificateur_avant_constructeur(L, position_debut, position_fin):
		res += constructeur_chaine_caracteres(2, "Header checksum", "0x" + "".join(L[position_debut:position_fin]))
	
	position_debut = position_fin
	position_fin = 16
	ip = [str(int(hex, base = 16)) for hex in L[position_debut:position_fin]]
	if verificateur_avant_constructeur(L, position_debut, position_fin):
		res += constructeur_chaine_caracteres(2, "Adresse IP Source", "0x" + "".join(L[position_debut:position_fin]),".".join(ip))


	position_debut = position_fin
	position_fin = 20
	ip = [str(int(hex, base = 16)) for hex in L[position_debut:position_fin]]
	if verificateur_avant_constructeur(L, position_debut, position_fin):
		res += constructeur_chaine_caracteres(2, "Adresse IP Destination", "0x" + "".join(L[position_debut:position_fin]), ".".join(ip))	
	return res,int(L[0][1])*4+14

# Renvoie l'option representant l'entete IP option
# à écrire
def analyse_IP_option(Liste):
	return ""

# Renvoie l'option representant l'entete UDP
# à écrire
def analyse_UDP(Liste):
	return ""

# Renvoie un str représentant l'entête TCP
# à modifier
def analyseTCP(L):
	a, i=analyseIP(L)
	res = "\tTCP : \n"
	res += "		Source port number : "+convertions.LStrToStr(L[i:i+2])+"("+convertions.LStrToPort(L[i:i+2])+")"+"\n"
	res += "		Destination port number : "+convertions.LStrToStr(L[i+2:i+4])+"("+convertions.LStrToPort(L[i+2:i+4])+")"+"\n"
	res += "		Sequence Number : "+convertions.LStrToStr(L[i+4:i+8])+"("+convertions.LStrToPort(L[i+4:i+8])+")"+"\n"
	res += "		Acknowledgment number : "+convertions.LStrToStr(L[i+8:i+12])+" ("+convertions.LStrToPort(L[i+8:i+12])+")"+"\n"
	Lb = convertions.LStrToBin(L[i+12:i+14])
	res += "		Transport Header Length: "+Lb[0]+Lb[1]+Lb[2]+Lb[3]+"("+str(int("0b"+Lb[0]+Lb[1]+Lb[2]+Lb[3], base=2)*4)+")"+"\n"
	res += "		Flags : 0x"+L[i+12][1]+L[i+13]+"\n"
	res += "			Reserved : "
	for j in range(4,10):
		res+= Lb[j]
	res += "\n"
	res += "			URG : "+Lb[10]+"\n"
	res += "			ACK : "+Lb[11]+"\n"
	res += "			PSH : "+Lb[12]+"\n"
	res += "			RST : "+Lb[13]+"\n"
	res += "			SYN : "+Lb[14]+"\n"
	res += "			FIN : "+Lb[15]+"\n"
	res += "		Window : "+convertions.LStrToStr(L[i+14:i+16])+"("+convertions.LStrToPort(L[i+14:i+16])+")"+"\n"
	res += "		Checksum : "+convertions.LStrToStr(L[i+16:i+18])+"("+convertions.LStrToPort(L[i+16:i+18])+")"+"\n"
	res += "		Urgent Pointer : "+convertions.LStrToStr(L[i+18:i+20])+"("+convertions.LStrToPort(L[i+18:i+20])+")"+"\n"
	return res,int("0b"+Lb[0]+Lb[1]+Lb[2]+Lb[3], base=2)*4+i

# Renvoie l'option representant l'entete DNS
# à écrire
def analyse_DNS(Liste):
	return ""

# Renvoie l'option representant l'entete DHCP
# à écrire
def analyse_DHCP(Liste):
	return ""