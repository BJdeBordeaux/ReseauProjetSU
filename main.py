import tools, analyse, sys

if len(sys.argv) != 3: # verifier s'il y a 2 arguments :  fichiers source et destination
	print("Erreur : Usage : <nom du fichier source> <nom du fichier destination>")
	exit()

# Verifier l'existence du fichier source
try:
	fichier_source = open(sys.argv[1], "r")
except:
    print("Erreur: Le fichier source n'existe pas.")
    exit()

fichier_destination = open(sys.argv[2], "w")
liste_brut = list()

# Construit une liste brute a partir d'un fichier text
# les elements sont des string representant une ligne
for line in fichier_source:
	liste_brut.extend(line.split("\t"))

# Construire une liste de listes, dont chacun represente une trame
# list[list[str]]
liste = list()
for ligne in liste_brut:
	# decouvrir l'offset pour faciliter la lecture
	# s'il est valide, on prend cette ligne
	indice_premier_espace = 0
	for i in range(len(ligne)):
		if ligne[i] == ' ':
			indice_premier_espace = i
			break
	if tools.offset_valide(ligne[0:indice_premier_espace]):
		liste.append(ligne.split())

# Retirer les offset et les valeurs textuelles
liste = tools.liste_brute_2_liste(liste)
res = ""


# declaration de variables
longueur_ethernet = 14
longueur_IP = 20
longueur_IP_option = 40
longueur_UDP = 8
longueur_TCP = 20

# construire les chaînes de caracteres correspondant aux trames
for index_trame in range(len(liste)):
	
	res += "\nTrame "+str(index_trame+1)+" :\n"
	#afficher information d'erreur
	information_erreur = ""
	if(not tools.octet_valide(liste[index_trame][-1])):
		information_erreur += tools.info_erreur(liste[index_trame][-1], len(liste[index_trame]))
		liste[index_trame].pop()
	try :
		# analyse Ethernet
		position_courante = 0
		res += "\n"+analyse.analyse_ethernet(liste[index_trame][position_courante:])
		position_courante = longueur_ethernet
		prochain_protocol = ""
		
		# analyse IP
		if len(liste[index_trame]) > position_courante:
			res_annalyse_IP = analyse.analyse_IP(liste[index_trame][position_courante:])
			res += res_annalyse_IP[0]
			position_courante += longueur_IP
			prochain_protocol = res_annalyse_IP[1]
			IP_option_set = res_annalyse_IP[2]

			# analyse option IP
			if len(liste[index_trame]) > position_courante:
				if liste[index_trame][position_courante-longueur_IP][1].lower() not in ['5', 'f']:
					res += "Longueur IP non valide. Passe a la trame prochaine.\n"
					continue
				if IP_option_set == True:
					res += analyse.analyse_IP_option(liste[index_trame][position_courante:])
					position_courante += longueur_IP_option
			#tools.debug_print_trame(liste[index_trame])
				# analyse UDP
			
			#if len(liste[index_trame]) > position_courante:
				if prochain_protocol == "UDP":
					res_annalyse_UDP = analyse.analyse_UDP(liste[index_trame][position_courante:])
					res+= res_annalyse_UDP[0]
					position_courante += longueur_UDP
					prochain_app =res_annalyse_UDP[1]
					
					if prochain_app == "DNS":
						res += analyse.analyse_DNS(liste[index_trame][position_courante:])
					elif prochain_app == "DHCP":
						res += analyse.analyse_DHCP(liste[index_trame][position_courante:])
					else:
						res += "Protocol couche 3 non supporte. Passe a la trame prochaine.\n"
						continue
				else:
					res += "Protocol couche 4 non supporte. Passe a la trame prochaine.\n"
					continue
		# ajout d'information d'erreur a la fin
		res += information_erreur
	except IndexError:
		continue

# Ecrire le trame dans le fichier destination

fichier_destination.write(res+"\n")

# Ferme les fichiers
fichier_destination.close()
fichier_source.close()
