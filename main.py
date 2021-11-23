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
L = list()

# Construit une liste à partir d'un fichier text, ligne par ligne
for line in f:
	L.extend(line.split("\t"))

# Construit la structure générale du programme, une liste composée de listes, dont chaque représente une trame (sans commentaire)
LL = list()
for e in L:
	indice_premier_espace = 0
	for i in range(len(e)):
		if e[i] == ' ':
			indice_premier_espace = i
			break
	if fonctions.formatValideOffset(e[0:indice_premier_espace]):
		LL.append(e.split())

# Retire les offset
# LL = fonctions.LLtoLLclean(fonctions.LtoLL(LL))
LL = fonctions.LtoLL(LL)
res = ""

# declaration de variables
longueur_ethernet = 14
longueur_IP = 20
longueur_IP_option = 40
longueur_UDP = 8
longueur_TCP = 20

# Affiche les trames, et les entêtes qui correspondent
for i in range(len(LL)):
	res += "\nTrame "+str(i+1)+" :\n"

	#afficher information d'erreur
	information_erreur = ""
	if(not fonctions.formatValideByte(LL[i][-1])):
		if LL[i][-1] in convertions.dico_type_erreur:
			information_erreur = convertions.dico_type_erreur.get(LL[i][-1])
		else: 
			information_erreur = "Erreur inconnue"
		information_erreur += ", interrupture d'analyse."
		information_erreur += "\n"
		LL[i].pop()

	position_courante = 0
	res += "\n"+fonctions.analyseETHERNET(LL[i][position_courante:])
	position_courante = longueur_ethernet
	prochain_protocol = ""
	
	if len(LL[i]) > position_courante:
		res_annalyse_IP = fonctions.analyseIP(LL[i][position_courante:])
		res += res_annalyse_IP[0]
		position_courante += longueur_IP
		if LL[i][position_courante][1] == 'f':
			res += fonctions.analyse_IP_option(LL[i][position_courante:])

		if len(LL[i]) > position_courante:
			if prochain_protocol == "TCP":
				res += fonctions.analyseTCP(LL[i])[0]
				position_courante += longueur_TCP
			elif prochain_protocol == "UDP":
				res += fonctions.analyse_UDP(LL[i][position_courante:])[0]
				position_courante += longueur_UDP

			if len(LL[i]) > position_courante:
				print("analyse ???")
			# if len(LL[i]) > position_courante and LL[i][len(LL[i])-4:len(LL[i])] == ["0d", "0a", "0d", "0a"]:
	
	res += information_erreur

# Ecrit le résultat dans le fichier destination
d.write(res+"\n")

# Ferme les fichiers
d.close()
f.close()
