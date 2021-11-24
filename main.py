import convertions, fonctions, sys

if len(sys.argv) != 3: # Si il y a bien 2 arguments, correspondant aux fichiers source et destination
	print("Erreur : Usage : <nom du fichier source> <nom du fichier destination>")
	exit()

# Vérifie l'existence du fichier source
try:
	f = open(sys.argv[1], "r")
except:
    print("Erreur: Le fichier source n'existe pas.")
    exit()

d = open(sys.argv[2], "w")
liste_brut = list()

# Construit une liste à partir d'un fichier text, ligne par ligne
for line in f:
	liste_brut.extend(line.split("\t"))

# Construit la structure générale du programme, une liste composée de listes, dont chaque représente une trame (sans commentaire)
liste = list()
for ligne in liste_brut:
	indice_premier_espace = 0
	for i in range(len(ligne)):
		if ligne[i] == ' ':
			indice_premier_espace = i
			break
	if fonctions.offset_valide(ligne[0:indice_premier_espace]):
		liste.append(ligne.split())

# Retire les offset
# liste = fonctions.LLtoLLclean(fonctions.LtoLL(liste))
liste = fonctions.LtoLL(liste)
res = ""

# declaration de variables
longueur_ethernet = 14
longueur_IP = 20
longueur_IP_option = 40
longueur_UDP = 8
longueur_TCP = 20

# Affiche les trames, et les entêtes qui correspondent
for index_trame in range(len(liste)):
	res += "\nTrame "+str(index_trame+1)+" :\n"

	#afficher information d'erreur
	information_erreur = ""
	if(not fonctions.octet_valide(liste[index_trame][-1])):
		if liste[index_trame][-1] in convertions.dico_type_erreur:
			information_erreur = convertions.dico_type_erreur.get(liste[index_trame][-1])
		else: 
			information_erreur = "Erreur inconnue"
		information_erreur += ", interrupture d'analyse. "
		information_erreur += "Erreur se trouve a l'octet " + str(len(liste[index_trame])+1)
		information_erreur += "\n"
		liste[index_trame].pop()

	position_courante = 0
	res += "\n"+fonctions.analyseETHERNET(liste[index_trame][position_courante:])
	position_courante = longueur_ethernet
	prochain_protocol = ""
	
	if len(liste[index_trame]) > position_courante:
		res_annalyse_IP = fonctions.analyseIP(liste[index_trame][position_courante:])
		res += res_annalyse_IP[0]
		position_courante += longueur_IP
		if liste[index_trame][position_courante][1] == 'f':
			res += fonctions.analyse_IP_option(liste[index_trame][position_courante:])

		if len(liste[index_trame]) > position_courante:
			if prochain_protocol == "UDP":
				res += fonctions.analyse_UDP(liste[index_trame][position_courante:])[0]
				position_courante += longueur_UDP

			if len(liste[index_trame]) > position_courante:
				print("analyse ???")
			# if len(liste[index_trame]) > position_courante and liste[index_trame][len(liste[index_trame])-4:len(liste[index_trame])] == ["0d", "0a", "0d", "0a"]:
	
	res += information_erreur

# Ecrit le résultat dans le fichier destination
d.write(res+"\n")

# Ferme les fichiers
d.close()
f.close()
