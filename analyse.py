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
	
# Lecture de la version et du header length
	position_debut = 0
	position_fin = 1
	if tools.verificateur_avant_constructeur(Liste, position_debut, position_fin):
		res += tools.constructeur_chaine_caracteres(2, "Version", "0x" + Liste[position_debut:position_fin][0][0], "IPv" + Liste[position_debut:position_fin][0][0])	
	if tools.verificateur_avant_constructeur(Liste, position_debut, position_fin):
		res += tools.constructeur_chaine_caracteres(2, "Header length", "0x" + Liste[position_debut:position_fin][0][1], str(int(Liste[position_debut:position_fin][0][1], base = 16)*4))

# Lecture du type of service
	position_debut = position_fin
	position_fin = 2
	if tools.verificateur_avant_constructeur(Liste, position_debut, position_fin):
		res += tools.constructeur_chaine_caracteres(2, "Type of service", "0x" + Liste[position_debut:position_fin][0])

# Lecture du total length
	position_debut = position_fin
	position_fin = 4
	if tools.verificateur_avant_constructeur(Liste, position_debut, position_fin):
		res += tools.constructeur_chaine_caracteres(2, "Total Length", "0x" + "".join(Liste[position_debut:position_fin]), tools.liste_hex_2_dec(Liste[position_debut:position_fin]) + " octets")	

# Lecture du Identifier
	position_debut = position_fin
	position_fin = 6
	if tools.verificateur_avant_constructeur(Liste, position_debut, position_fin):
		res += tools.constructeur_chaine_caracteres(2, "Identifier", "0x" + "".join(Liste[position_debut:position_fin]))	

# Lecture de Reserve, DF, MF, Fragment offset
	position_debut = position_fin
	position_fin = 8
	if tools.verificateur_avant_constructeur(Liste, position_debut, position_fin):
		res += tools.constructeur_chaine_caracteres(2, "Flags", "0x" + "".join(Liste[position_debut:position_fin]))
		Lb = format(int("".join(Liste[6:8]), base = 16), '016b') 
		res += tools.constructeur_chaine_caracteres(3, "Reserve", Lb[0])
		res += tools.constructeur_chaine_caracteres(3, "DF", Lb[1])
		res += tools.constructeur_chaine_caracteres(3, "MF", Lb[2])
		res += tools.constructeur_chaine_caracteres(3, "Fragment offset", str(hex(int(Lb[3:], base = 2))), str(int(Lb[3:], base = 2)*8) + " octets")

# Lecture du TTL
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
		proto = tools.dico_type_ip_protocol.get(protocol_hex)
		
# Lecture du header checksum
	position_debut = position_fin
	position_fin = 12
	if tools.verificateur_avant_constructeur(Liste, position_debut, position_fin):
		res += tools.constructeur_chaine_caracteres(2, "Header checksum", "0x" + "".join(Liste[position_debut:position_fin]))

# Lecture de l'adresse IP Source
	position_debut = position_fin
	position_fin = 16
	ip = [str(int(hex, base = 16)) for hex in Liste[position_debut:position_fin]]
	if tools.verificateur_avant_constructeur(Liste, position_debut, position_fin):
		res += tools.constructeur_chaine_caracteres(2, "Adresse IP Source", "0x" + "".join(Liste[position_debut:position_fin]),".".join(ip))

# Lecture de l'adresse IP Destination
	position_debut = position_fin
	position_fin = 20
	ip = [str(int(hex, base = 16)) for hex in Liste[position_debut:position_fin]]
	if tools.verificateur_avant_constructeur(Liste, position_debut, position_fin):
		res += tools.constructeur_chaine_caracteres(2, "Adresse IP Destination", "0x" + "".join(Liste[position_debut:position_fin]), ".".join(ip))	
	return res, proto

# à écrire
def analyse_IP_option(Liste):
	res = "\tOPTION IP : \n"

	return res

# à écrire
def analyse_UDP(Liste):
	res = "\tUDP : \n"

# Lecture du Port source
	position_debut = 0
	position_fin = 2
	if tools.verificateur_avant_constructeur(Liste, position_debut, position_fin):
		res += tools.constructeur_chaine_caracteres(2, "Source Port","0x" +"".join(Liste[position_debut:position_fin]), tools.liste_hex_2_dec(Liste[position_debut:position_fin]))
		if tools.dico_type_udp.get("".join(Liste[position_debut:position_fin])) is not None:
			app = tools.dico_type_udp.get("".join(Liste[position_debut:position_fin]))
		else: 
			app="inconnu"
# Lecture du Port destination
	position_debut = position_fin
	position_fin = 4
	if tools.verificateur_avant_constructeur(Liste, position_debut, position_fin):
		res += tools.constructeur_chaine_caracteres(2, "Destination Port","0x" +"".join(Liste[position_debut:position_fin]), tools.liste_hex_2_dec(Liste[position_debut:position_fin]))

# Lecture du Length
	position_debut = position_fin
	position_fin = 6
	if tools.verificateur_avant_constructeur(Liste, position_debut, position_fin):
		res += tools.constructeur_chaine_caracteres(2, "Lenght","0x" +"".join(Liste[position_debut:position_fin]), tools.liste_hex_2_dec(Liste[position_debut:position_fin]) + " octets")

# Lecture du checksum	
	position_debut = position_fin
	position_fin = 8
	if tools.verificateur_avant_constructeur(Liste, position_debut, position_fin):
		res += tools.constructeur_chaine_caracteres(2, "Checksum","0x" +"".join(Liste[position_debut:position_fin]), tools.liste_hex_2_dec(Liste[position_debut:position_fin]))
	return res, app

# à écrire
def analyse_DNS(Liste):
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
# Tant que l'on ne rencontre pas de 0x00 on continue à lire le nom
	while int(tools.liste_hex_2_dec(Liste[position_debut:position_fin])) != 0:
# On prend la taille du label à lire
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

def DNS_Answer(Liste, nombre, position_debut,position_fin, res):
	name =''
	label = 0
# On passe au premier octet de la réponse
	position_debut = position_fin
	position_fin = position_debut + 1
	while int(tools.liste_hex_2_dec(Liste[position_debut:position_fin])) != 0: 
		if Liste[position_debut:position_fin][0] == "c0":
# On passe à l'octet qui nous indique ou lire le label
			position_debut = position_fin
			position_fin = position_debut + 1
# On se place à l'endroit indiqué par l'octet au dessus
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
# On prend la taille du label à lire dans le cas ou l'on doit le lire dans les octets qui suivent
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
			# On prend la taille du label à lire
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
			# On prend la taille du label à lire
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
# On passe à l'octet qui nous indique ou lire le label
			position_debut = position_fin
			position_fin = position_debut + 1
# On se place à l'endroit indiqué par l'octet au dessus
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
# On prend la taille du label à lire dans le cas ou l'on doit le lire dans les octets qui suivent
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
