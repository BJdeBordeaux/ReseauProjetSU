# ReseauProjetSU
## par LI Junji, BABAALI Mohamed

### mode d'emploi
* Il faut installer python3 avant d'utiliser ce programme.
* Pour lancer le programme, veuiller ouvrir un terminal au répertoire contenant les fichiers sources : main, analyse et tools et
* tapez la commande `make` ou `make all`.
* Pour changer de fichier source de la trame ou destination de la trame, veuillez ouvrir le fichier `Makefile` et remplacer `http.txt` par un autre fichier source ou `res.txt` par un autre fichier destination (dans ce cas dans les 2 commandes).

* format : `python3 main.py nom_fichier_source nom_fichier_destination`
* Exemple: `python3 main.py trame.txt res.txt`

* Or, des commandes peuvent servir pour la démonstration:
    ```shell
        make all
        make ipo #pour une trame avec ip option
        make dns
        make dhcp
    ```
* Pour supprimer le fichier destination créé veuillez tapez la commande `make clean`

[Voici le vidéo pour la démonstration](https://www.youtube.com/watch?v=-_0B-vxWRDo)

### structure des fichiers
```shell
    .
    ├── all.txt     #tous types de trame confondu
    ├── analyse.py  #des fontions pricipales pour le programme
        ├── analyse_ethernet
        ├── analyse_IP
        ├── analyse_IP_option
        ├── analyse_UDP
        ├── analyse_DNS
        └── analyse_DHCP
    ├── dhcp.txt    #trames de DHCP
    ├── dns.txt     #trames de DNS
    ├── howto.txt   #mode d'utilisation
    ├── ip_option.txt   #trame d'IP Option
    ├── main.py     #le programme principal
    ├── Makefile    #des commande Makefile
    ├── README.md   #la structure du projet
    ├── res.txt     #les informations en sortie
    └── tools.py    #des outils pour développer le programme
    0 directories, 11 files
```