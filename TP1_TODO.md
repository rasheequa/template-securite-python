# TP1 — Plan d'implémentation

## Ordre d'implémentation

`Capture` passe avant `Report`, car le rapport utilise ses données.
Mais `choose_interface()` passe encore avant, parce que `Capture.__init__` l'appelle.

| #   | Méthode                                                     | Fichier                    | Dépend de | Difficulté | Ce qu'elle doit faire                                                                                                                                                  |
| --- | ----------------------------------------------------------- | -------------------------- | --------- | ---------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| 0   | *(préparation)* ajouter `self.packets = []` dans `__init__` | `src/tp1/utils/capture.py` | rien      | ⭐          | Stocker les paquets capturés pour que les autres méthodes y aient accès.                                                                                               |
| 1   | `choose_interface()`                                        | `src/tp1/utils/lib.py`     | rien      | ⭐          | Lister les interfaces (`scapy.all.get_if_list()`), les afficher numérotées, demander un choix avec `input()` et renvoyer le nom choisi.                                |
| 2   | `capture_traffic()`                                         | `capture.py`               | 0, 1      | ⭐⭐         | `self.packets = sniff(iface=self.interface, count=...)` ou `timeout=...`. Il faut les droits root.                                                                     |
| 3   | `get_all_protocols()`                                       | `capture.py`               | 2         | ⭐⭐         | Parcourir `self.packets` et compter les paquets par protocole (ARP, TCP, UDP, DNS, ICMP…) avec un `dict` ou un `collections.Counter`.                                  |
| 4   | `sort_network_protocols()`                                  | `capture.py`               | 3         | ⭐          | Trier le résultat de 3 par nombre de paquets : `sorted(..., key=..., reverse=True)`.                                                                                   |
| 5   | `analyse(protocols)`                                        | `capture.py`               | 2, 3, 4   | ⭐⭐⭐⭐       | Repérer le trafic illégitime et relever le protocole, l'IP et la MAC de l'attaquant (voir plus bas). Stocker les alertes dans un attribut, par ex. `self.alerts = []`. |
| 6   | `_gen_summary()`                                            | `capture.py`               | 3, 5      | ⭐⭐         | Construire le texte du résumé : protocoles avec leur nombre de paquets, puis les attaques détectées, ou « tout va bien » s'il n'y en a pas.                            |
| 7   | `get_summary()`                                             | `capture.py`               | —         | ✅          | Déjà écrite.                                                                                                                                                           |
| 8   | `Report.generate("graph")`                                  | `src/tp1/utils/report.py`  | 3         | ⭐⭐         | Graphique de répartition des protocoles avec `pygal`.                                                                                                                  |
| 9   | `Report.generate("array")`                                  | `report.py`                | 3         | ⭐⭐         | Tableau protocole / nombre de paquets.                                                                                                                                 |
| 10  | `Report.save()`                                             | `report.py`                | 8, 9      | ⭐⭐⭐        | Générer un vrai PDF avec `fpdf2`. Pour l'instant, la méthode écrit du texte brut dans un `.pdf`.                                                                       |

### Idées de détection pour `analyse()`

- **ARP spoofing** : une même IP annoncée par plusieurs MAC différentes (`ARP` avec `op == 2`, comparer `psrc` et `hwsrc`).
- **Injection SQL** : chercher `' OR 1=1`, `UNION SELECT`, `--`, `' OR '1'='1`… dans le contenu `Raw` des paquets TCP/HTTP.
- Pour chaque alerte, noter : type d'attaque, protocole, IP source, MAC source.
- *(Facultatif)* Bloquer la machine attaquante.

## Répartition

| Qui                             | Tâches                                                                                      |
| ------------------------------- | ------------------------------------------------------------------------------------------- |
| **Personne A**                  | Étapes 0 → 4 (récupération et comptage des paquets).                                        |
| **Personne B**                  | Étape 5 (détection d'attaques), puis 6. C'est la partie la plus difficile, à commencer tôt. |
| **Ensuite, chacun de son côté** | A : étape 8 (graph). B : étapes 9 + 10 (tableau + PDF).                                     |

B n'a pas besoin d'attendre A pour commencer. Le `.pcap` à la racine du repo donne directement une liste de paquets :

```python
from scapy.all import rdpcap
packets = rdpcap("tp1-grp-fa25de68-3ae9-49b7-814b-a5d7be53edfb-996d39.pcap")
```

### À décider ensemble avant de commencer

Le **format de retour de `get_all_protocols()`**. Toutes les méthodes suivantes l'utilisent, donc c'est votre point de rencontre. Un `dict` ira mieux qu'une `str` comme le prévoit le squelette :

```python
{"TCP": 120, "UDP": 45, "ARP": 14}
```

## Points à surveiller

- [ ] **Les tests vont échouer** dès qu'une méthode est implémentée : ils vérifient que tout renvoie `""`. Il faudra les mettre à jour au fur et à mesure (`tests/tp1/utils/`).
- [ ] **Les imports sont incohérents** : `capture.py` importe `from src.tp1.utils.lib` à un endroit et `from tp1.utils.config` à un autre. Si `poetry run tp1` plante sur un `ModuleNotFoundError`, ça vient de là.
- [ ] **La capture a besoin des droits root** (`sudo`).

---

## Guide fonction par fonction (en langage humain, sans code)

Pour chaque fonction : **à quoi elle sert**, **ce qu'elle reçoit**, **ce qu'elle rend**, puis les **étapes** à traduire en Python.

### Par où commencer (le premier jour)

1. **Ne commencez pas par le sniff en direct.** Travaillez d'abord sur `file.pcap` (à la racine) : pas besoin de `sudo`, pas besoin d'interface, et tout le monde a les mêmes paquets. `main.py` le lit déjà et affiche les paquets.
2. **Explorez à la main avant d'écrire les fonctions.** Ouvrez un shell Python (`poetry run python`), chargez le pcap et regardez un paquet : sa méthode `show()` affiche toutes ses couches. `summary()` donne une ligne courte. Repérez les noms des couches (Ether, IP, TCP, UDP, ARP, DNS, Raw…) : c'est ce que vous allez compter.
3. **Mettez-vous d'accord sur le format** de `get_all_protocols()` (un dictionnaire `nom du protocole → nombre de paquets`). C'est la seule chose que A et B doivent fixer ensemble.
4. **Ajoutez une astuce pour tester sans sniffer** : dans `capture_traffic()`, prévoyez la possibilité de remplir `self.packets` depuis le pcap plutôt que depuis le réseau (par ex. un paramètre optionnel « chemin du fichier »). Comme ça `analyse()` marche pareil dans les deux cas.
5. Avancez dans l'ordre du tableau du haut, et lancez les tests après chaque fonction.

---

### `choose_interface()` — `lib.py`

- **Rôle** : demander à l'utilisateur sur quelle carte réseau écouter.
- **Reçoit** : rien. **Rend** : le nom de l'interface (texte, ex. `"eth0"`).
- **Étapes** :
  1. Récupérer la liste des interfaces de la machine (déjà fait avec `get_if_list`).
  2. Les afficher une par ligne, **avec un numéro devant** (1, 2, 3…) — plus agréable que d'afficher la liste brute.
  3. Demander à l'utilisateur de taper un numéro.
  4. Vérifier que ce qu'il a tapé est bien un nombre et qu'il est dans la liste. Sinon, redemander (boucle).
  5. Renvoyer le **nom** de l'interface correspondant au numéro (attention : la liste commence à 0, l'humain à 1).
- **État actuel** : ça marche déjà, mais l'utilisateur doit taper le nom exact et rien n'est vérifié. Étapes 2 à 5 à améliorer.

### `Capture.__init__()` — `capture.py`

- **Rôle** : préparer l'objet. ✅ `self.packets` est déjà là.
- **À ajouter** : un attribut pour stocker les alertes (liste vide au départ), et éventuellement un pour stocker le résultat du comptage des protocoles, pour ne pas le recalculer partout.

### `capture_traffic()` — `capture.py`

- **Rôle** : récupérer des paquets et les ranger dans `self.packets`.
- **Reçoit** : rien (ou un chemin de pcap optionnel, cf. astuce plus haut). **Rend** : rien, elle remplit l'attribut.
- **Étapes** :
  1. Écrire dans le log qu'on commence (déjà fait).
  2. Si on a donné un fichier pcap → le lire et mettre les paquets dans `self.packets`.
  3. Sinon → lancer `sniff` sur `self.interface`, en limitant la capture (soit un nombre de paquets, soit une durée en secondes, sinon ça ne s'arrête jamais).
  4. Écrire dans le log combien de paquets ont été récupérés.
- **Piège** : le sniff en direct demande `sudo`. Sans droits, scapy lève une erreur de permission.

### `get_all_protocols()` — `capture.py`

- **Rôle** : compter combien de paquets il y a pour chaque protocole.
- **Reçoit** : rien (elle lit `self.packets`). **Rend** : un dictionnaire, ex. `{"TCP": 120, "UDP": 45, "ARP": 14}`.
- **Étapes** :
  1. Partir d'un compteur vide.
  2. Pour chaque paquet de `self.packets`, regarder quelles couches il contient (un paquet a la méthode `haslayer(...)` pour tester une couche).
  3. Pour chaque protocole qui vous intéresse et qui est présent, ajouter 1 dans le compteur.
  4. Renvoyer le compteur.
- **Choix à faire** : un paquet DNS est aussi un paquet UDP et IP. Est-ce qu'on le compte dans les trois, ou seulement dans la couche la plus haute ? Les deux se défendent, mais **choisissez et écrivez-le** dans le rapport. Le plus simple : compter chaque couche présente.
- **Penser à** changer le type de retour dans la signature (`-> str` devient `-> dict`).

### `sort_network_protocols()` — `capture.py`

- **Rôle** : renvoyer les mêmes protocoles, **du plus fréquent au moins fréquent**.
- **Reçoit** : rien (elle appelle `get_all_protocols()` ou réutilise le résultat stocké). **Rend** : une liste de couples `(protocole, nombre)` triée, ou un dictionnaire trié.
- **Étapes** :
  1. Récupérer le dictionnaire de comptage.
  2. Le trier sur la valeur (le nombre), en ordre décroissant.
  3. Renvoyer le résultat.
- C'est une fonction de 2-3 lignes. Si elle devient longue, c'est qu'on se complique la vie.

### `analyse(protocols)` — `capture.py` ⚠️ la plus dure

- **Rôle** : chercher des attaques dans les paquets et les noter.
- **Reçoit** : `protocols` (actuellement `main.py` passe `"tcp"`). Vous pouvez l'utiliser comme filtre (« n'analyse que ce protocole ») ou l'ignorer. Décidez-le ensemble. **Rend** : rien, elle remplit `self.alerts` puis `self.summary`.
- **Étapes générales** :
  1. Calculer le comptage et le tri (déjà appelés dans le squelette).
  2. Lancer chaque détecteur l'un après l'autre (une petite fonction privée par type d'attaque, c'est plus lisible : `_detect_arp_spoofing`, `_detect_sqli`…).
  3. Chaque détecteur ajoute ses trouvailles dans `self.alerts`. Une alerte contient au minimum : le **type d'attaque**, le **protocole**, l'**IP source** et la **MAC source**.
  4. À la fin, générer le résumé (déjà appelé).
- **Détecteur ARP spoofing, en mots** :
  1. Garder un « carnet » qui associe une IP à la MAC qui l'a annoncée.
  2. Pour chaque paquet ARP qui est une **réponse** (op = 2), lire l'IP annoncée (`psrc`) et la MAC qui l'annonce (`hwsrc`).
  3. Si l'IP n'est pas encore dans le carnet → l'y noter.
  4. Si elle y est déjà **avec une autre MAC** → quelqu'un usurpe cette IP : créer une alerte avec la MAC suspecte.
  5. Pour éviter 500 alertes identiques, ne pas re-signaler le même couple IP/MAC.
- **Détecteur injection SQL, en mots** :
  1. Préparer une liste de motifs suspects (`' OR 1=1`, `UNION SELECT`, `' OR '1'='1`, `--`, `DROP TABLE`…).
  2. Pour chaque paquet TCP qui a une couche `Raw` (le contenu brut), récupérer ce contenu et le transformer en texte (il arrive en octets : le décoder en ignorant les erreurs).
  3. Le passer en minuscules et en version « URL décodée » (dans une requête HTTP, les espaces deviennent `%20` ou `+`) — sinon vous raterez la moitié des attaques.
  4. Si un des motifs apparaît → alerte avec l'IP source (couche IP) et la MAC source (couche Ether).
- **Bonus possibles** : scan de ports (une même IP qui envoie des SYN vers beaucoup de ports différents), flood ICMP, etc.
- **Conseil** : regardez d'abord le pcap à la main pour voir **quelles attaques il contient vraiment**, et commencez par celles-là.

### `_gen_summary()` — `capture.py`

- **Rôle** : fabriquer le texte lisible qui ira dans le rapport.
- **Reçoit** : rien (elle lit le comptage et `self.alerts`). **Rend** : une chaîne de caractères.
- **Étapes** :
  1. Une ligne d'en-tête (interface, nombre total de paquets).
  2. La liste des protocoles triés avec leur nombre de paquets, une ligne chacun.
  3. Si `self.alerts` est vide → une phrase du genre « Aucun trafic illégitime détecté ».
  4. Sinon → une ligne par alerte : type, protocole, IP, MAC.
  5. Renvoyer le texte.

### `get_summary()` — `capture.py`

✅ Rien à faire, elle renvoie `self.summary`.

### `Report.generate("graph")` — `report.py`

- **Rôle** : produire un graphique de la répartition des protocoles.
- **Étapes** :
  1. Récupérer le comptage depuis `self.capture`.
  2. Créer un graphique pygal (camembert ou barres), ajouter une entrée par protocole avec son nombre.
  3. L'exporter en image (pygal sort du SVG ; pour le mettre dans un PDF il faudra sans doute le convertir en PNG, ou bien utiliser un camembert dessiné avec une autre lib, à voir).
  4. Ranger le chemin de l'image (ou son contenu) dans `self.graph`.

### `Report.generate("array")` — `report.py`

- **Rôle** : produire un tableau « Protocole | Nombre de paquets ».
- **Étapes** :
  1. Récupérer le comptage trié.
  2. Construire les lignes du tableau (en-tête + une ligne par protocole).
  3. Ranger le résultat dans `self.array` (sous une forme que `save()` saura dessiner : une liste de lignes est plus pratique qu'une grosse chaîne).

### `Report.save()` — `report.py`

- **Rôle** : écrire le vrai fichier PDF.
- **Étapes** :
  1. Créer un document PDF avec fpdf2 et ajouter une page.
  2. Écrire le titre (pensez à changer `"TITRE DU RAPPORT"`).
  3. Écrire le résumé.
  4. Dessiner le tableau à partir de `self.array`.
  5. Insérer l'image du graphique.
  6. Enregistrer sous `self.filename`.
- Aujourd'hui elle écrit du texte brut dans un `.pdf`, donc le fichier ne s'ouvre pas dans un lecteur PDF. C'est normal.

### `main.py`

- À la fin, **retirer la boucle qui affiche tous les paquets du pcap** (c'était juste pour explorer).
- `print_menu()` existe dans `lib.py` mais n'est appelé nulle part. Soit vous l'utilisez dans `main` (boucle : capturer / analyser / rapport / quitter), soit vous le supprimez.

### Note

Le pcap s'appelle maintenant `file.pcap`. L'exemple `rdpcap(...)` plus haut utilise encore l'ancien nom.
