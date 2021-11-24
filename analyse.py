import tools

def analyse_ethernet(Liste):
	"""
	list[str] -> str
	Renvoyer un str représentant l'entête ETHERNET
	"""
	res = "\tETHERNET :\n"

	position_debut = 0
	position_fin = 6
	if tools.verificateur_avant_constructeur(Liste, position_debut, position_fin):
		res += tools.constructeur_chaine_caracteres(2, "Adresse Mac Destination", ":".join(Liste[position_debut:position_fin]))
	
	
	position_debut = position_fin
	position_fin = 12
	if tools.verificateur_avant_constructeur(Liste, position_debut, position_fin):
		res += tools.constructeur_chaine_caracteres(2, "Adresse Mac Source", ":".join(Liste[position_debut:position_fin]))
	
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

	position_debut = 0
	position_fin = 1
	if tools.verificateur_avant_constructeur(Liste, position_debut, position_fin):
		res += tools.constructeur_chaine_caracteres(2, "Version", "0x" + Liste[position_debut:position_fin][0][0], "IPv" + Liste[position_debut:position_fin][0][0])	
	if tools.verificateur_avant_constructeur(Liste, position_debut, position_fin):
		res += tools.constructeur_chaine_caracteres(2, "Header length", "0x" + Liste[position_debut:position_fin][0][1], str(int(Liste[position_debut:position_fin][0][1], base = 16)*4))

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
		if tools.dico_type_ip_protocol.get(protocol_hex) is not None:
			res += tools.constructeur_chaine_caracteres(2, "Protocol", "0x" + protocol_hex, tools.dico_type_ip_protocol.get(protocol_hex))
		else: 
			res += tools.constructeur_chaine_caracteres(2, "Protocol", "0x" + protocol_hex, "inconnu")
	
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
	return res

# à écrire
def analyse_IP_option(Liste):
	return ""

# à écrire
def analyse_UDP(Liste):
	return ""

# à écrire
def analyse_DNS(Liste):
	return ""

# à écrire
def analyse_DHCP(Liste):
	return ""


# # Renvoie un str représentant l'entête TCP
# # à modifier
# def analyseTCP(Liste):
# 	a, i=analyse_IP(Liste)
# 	res = "\tTCP : \n"
# 	res += "		Source port number : "+tools.LStrToStr(Liste[0:2])+"("+tools.LStrToPort(Liste[0:2])+")"+"\n"
# 	res += "		Destination port number : "+tools.LStrToStr(Liste[2:4])+"("+tools.LStrToPort(Liste[2:4])+")"+"\n"
# 	res += "		Sequence Number : "+tools.LStrToStr(Liste[4:8])+"("+tools.LStrToPort(Liste[4:8])+")"+"\n"
# 	res += "		Acknowledgment number : "+tools.LStrToStr(Liste[8:12])+" ("+tools.LStrToPort(Liste[8:12])+")"+"\n"
# 	Lb = tools.LStrToBin(Liste[12:14])
# 	res += "		Transport Header Length: "+Lb[0]+Lb[1]+Lb[2]+Lb[3]+"("+str(int("0b"+Lb[0]+Lb[1]+Lb[2]+Lb[3], base=2)*4)+")"+"\n"
# 	res += "		Flags : 0x"+Liste[12][1]+Liste[13]+"\n"
# 	res += "			Reserved : "
# 	for j in range(4,10):
# 		res+= Lb[j]
# 	res += "\n"
# 	res += "			URG : "+Lb[10]+"\n"
# 	res += "			ACK : "+Lb[11]+"\n"
# 	res += "			PSH : "+Lb[12]+"\n"
# 	res += "			RST : "+Lb[13]+"\n"
# 	res += "			SYN : "+Lb[14]+"\n"
# 	res += "			FIN : "+Lb[15]+"\n"
# 	res += "		Window : "+tools.LStrToStr(Liste[14:16])+"("+tools.LStrToPort(Liste[14:16])+")"+"\n"
# 	res += "		Checksum : "+tools.LStrToStr(Liste[16:18])+"("+tools.LStrToPort(Liste[16:18])+")"+"\n"
# 	res += "		Urgent Pointer : "+tools.LStrToStr(Liste[18:20])+"("+tools.LStrToPort(Liste[18:20])+")"+"\n"
# 	return res,int("0b"+Lb[0]+Lb[1]+Lb[2]+Lb[3], base=2)*4+i