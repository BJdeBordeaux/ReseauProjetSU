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

# Affiche les trames, et les entêtes qui correspondent
for i in range(len(LL)):
	res += "\nTrame "+str(i+1)+" :\n"

	#afficher information d'erreur
	information_erreur = ""
	if(not fonctions.formatValideByte(LL[i][-1])):
		print(LL[i][-1])
		if convertions.dico_type_erreur.has_key(LL[i][-1]):
			information_erreur = convertions.dico_type_erreur.get(LL[i][-1])
		else: 
			information_erreur = "Erreur inconnue"
		information_erreur += "\n"

	position_debut = 0
	position_fin = 14
	res += "\n"+fonctions.analyseETHERNET(LL[i][position_debut:position_fin])
	
	# if len(LL[i]) > 14:
	# 	res += fonctions.analyseIP(LL[i])[0]
	# if len(LL[i]) > 34:
	# 	res += fonctions.analyseTCP(LL[i])[0]
	# if len(LL[i]) > 54 and LL[i][len(LL[i])-4:len(LL[i])] == ["0d", "0a", "0d", "0a"]:
	# 	res += fonctions.analyseHTTP(LL[i])
	
	res += information_erreur

# Ecrit le résultat dans le fichier destination
res = ""
for l in LL :
    res += ",".join(l)
    res += "\n"
d.write(res+"\n")

# Ferme les fichiers
d.close()
f.close()
