import tools, analyse, sys

if len(sys.argv) != 3: # vérifier s'il y a 2 arguments :  fichiers source et destination
	print("Erreur : Usage : <nom du fichier source> <nom du fichier destination>")
	exit()

# Vérifier l'existence du fichier source
try:
	fichier_source = open(sys.argv[1], "r")
except:
    print("Erreur: Le fichier source n'existe pas.")
    exit()

fichier_destination = open(sys.argv[2], "w")
liste_brut = list()

# Construit une liste brute à partir d'un fichier text
# les éléments sont des string représentant une ligne
for line in fichier_source:
	liste_brut.extend(line.split("\t"))

# Construire une liste de listes, dont chacun représente une trame
# list[list[str]]
liste = list()
for ligne in liste_brut:
	# découvrir l'offset pour faciliter la lecture
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

# construire les chaînes de caractères correspondant aux trames
for index_trame in range(len(liste)):
	res += "\nTrame "+str(index_trame+1)+" :\n"

	#afficher information d'erreur
	information_erreur = ""
	if(not tools.octet_valide(liste[index_trame][-1])):
		information_erreur += tools.info_erreur(liste[index_trame][-1], len(liste[index_trame]))
		liste[index_trame].pop()

	# analyse Ethernet
	position_courante = 0
	res += "\n"+analyse.analyse_ethernet(liste[index_trame][position_courante:])
	position_courante = longueur_ethernet
	prochain_protocol = ""
	
	# analyse IP
	if len(liste[index_trame]) > position_courante:
		res_annalyse_IP = analyse.analyse_IP(liste[index_trame][position_courante:])
		res += res_annalyse_IP
		position_courante += longueur_IP

		# analyse option IP
		if len(liste[index_trame]) > position_courante:
			if liste[index_trame][position_courante-longueur_IP][1].lower() not in ['5', 'f']:
				res += "Longueur IP non valide. Passe à la trame prochaine.\n"
				continue
			if liste[index_trame][position_courante][1].lower() == 'f':
				res += analyse.analyse_IP_option(liste[index_trame][position_courante:])
				position_courante += longueur_IP_option

		# analyse UDP
		if len(liste[index_trame]) > position_courante:
			if prochain_protocol == "UDP":
				res += analyse.analyse_UDP(liste[index_trame][position_courante:])[0]
				position_courante += longueur_UDP

			# if len(liste[index_trame]) > position_courante:
				# print("analyse ???")
			# if len(liste[index_trame]) > position_courante and liste[index_trame][len(liste[index_trame])-4:len(liste[index_trame])] == ["0d", "0a", "0d", "0a"]:
	
	# ajout d'information d'erreur à la fin
	res += information_erreur

# Ecrire le trame dans le fichier destination
fichier_destination.write(res+"\n")

# Ferme les fichiers
fichier_destination.close()
fichier_source.close()
