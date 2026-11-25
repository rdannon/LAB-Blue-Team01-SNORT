# 🛡️ Détection d'intrusion réseau avec Snort 2 : installation, configuration et règles personnalisées

![Domaine](https://img.shields.io/badge/Domaine-Blue%20Team%20%2F%20NIDS-blue)
![Outil](https://img.shields.io/badge/Outil-Snort%202.9.7.0-red)
![OS](https://img.shields.io/badge/OS-Ubuntu%2020.04-E95420)
![Attaquant](https://img.shields.io/badge/Attaquant-Kali%20Linux-557C94)
![Cible](https://img.shields.io/badge/Cibles-Metasploitable%202%20%7C%20Windows%207-lightgrey)

> Déploiement d'un **système de détection d'intrusion réseau (NIDS)** avec **Snort 2** dans un laboratoire virtualisé : installation, configuration du fichier `snort.conf`, écriture de règles personnalisées (ICMP, SSH, FTP), chargement de règles communautaires (détection d'**EternalBlue**) et journalisation des alertes et du trafic.

<!-- 📸 IMAGE : schéma d'architecture du lab (Kali, Ubuntu/Snort, Metasploitable 2, Windows 7) ou capture d'ensemble -->
![Vue d'ensemble du lab](images/00-vue-ensemble.png)

---

## 📑 Sommaire

1. [Présentation du projet](#1--présentation-du-projet)
2. [Objectifs](#2--objectifs)
3. [Notions théoriques](#3--notions-théoriques)
4. [Architecture du laboratoire](#4--architecture-du-laboratoire)
5. [Installation de Snort](#5--installation-de-snort)
6. [Configuration de Snort](#6--configuration-de-snort)
7. [Écriture de règles personnalisées](#7--écriture-de-règles-personnalisées)
8. [Exécution de Snort et tests de détection](#8--exécution-de-snort-et-tests-de-détection)
9. [Génération de règles avec Snorpy](#9--génération-de-règles-avec-snorpy)
10. [Règles communautaires : détection d'EternalBlue](#10--règles-communautaires--détection-deternalblue)
11. [Journalisation des alertes et du trafic](#11--journalisation-des-alertes-et-du-trafic)
12. [Synthèse des résultats](#12--synthèse-des-résultats)
13. [Compétences démontrées](#13--compétences-démontrées)
14. [Bonnes pratiques](#14--bonnes-pratiques)
15. [Structure du dépôt](#15--structure-du-dépôt)
16. [Ressources et crédits](#16--ressources-et-crédits)

---

## 1. 📌 Présentation du projet

Ce laboratoire fait partie de mon parcours de montée en compétences **Blue Team**. Il consiste à mettre en place **Snort**, l'un des systèmes de détection d'intrusion open source les plus utilisés, et à démontrer sa capacité à détecter plusieurs types d'activités réseau : **pings**, **connexions SSH**, **connexions FTP** et une **exploitation EternalBlue** (SMBv1).

Le projet couvre :

- l'installation et la configuration de Snort 2 sur Ubuntu ;
- la compréhension du **fichier de configuration** `snort.conf` ;
- l'**écriture de règles** de détection personnalisées ;
- l'utilisation de **règles communautaires** ;
- des **tests réels** avec une machine attaquante (Kali Linux) ;
- la **journalisation** des alertes et du trafic pour analyse ultérieure.

---

## 2. 🎯 Objectifs

| # | Objectif |
|---|----------|
| 1 | Comprendre le fonctionnement d'un IDS et la différence entre HIDS et NIDS |
| 2 | Installer et configurer Snort 2 sur Ubuntu |
| 3 | Définir les variables réseau (`HOME_NET`, `EXTERNAL_NET`) et valider la configuration |
| 4 | Écrire des règles personnalisées et vérifier leur déclenchement |
| 5 | Utiliser Snorpy pour générer des règles |
| 6 | Charger des règles communautaires et détecter une attaque réelle (EternalBlue) |
| 7 | Journaliser les alertes et analyser le trafic capturé avec Wireshark |

---

## 3. 📚 Notions théoriques

### 3.1 IDS : HIDS et NIDS

Un **système de détection d'intrusion (IDS)** découvre activement des menaces, des attaques ou des intrusions sur un réseau, un hôte ou des services. Il capture le trafic, identifie les activités malveillantes selon des **règles prédéfinies**, les journalise et alerte les responsables.

| Type | Description |
|---|---|
| **HIDS** (Host-based) | Installé sur un hôte, surveille uniquement le trafic de cette machine |
| **NIDS** (Network-based) | Placé dans le réseau, surveille le trafic de et vers tous les hôtes. **Snort est un NIDS.** |

### 3.2 Les trois modes de Snort

| Mode | Fonction |
|---|---|
| **Sniffer** | Capture et affiche le trafic (comme Wireshark) |
| **Packet Logger** | Capture et enregistre le trafic dans un fichier |
| **NIDS** | Analyse les paquets et les compare aux signatures définies dans les règles ← *mode utilisé dans ce lab* |

Snort capture les paquets, les réassemble, les analyse, puis décide de l'action à appliquer selon les règles. **Sans règles, Snort est inopérant.**

<!-- 📸 IMAGE : schéma du fonctionnement de Snort (capture, préprocesseur, décodage, moteur de détection, alertes et logs) -->
![Fonctionnement de Snort](images/01-fonctionnement-snort.png)

### 3.3 Snort 2 et Snort 3

| Version | Caractéristiques |
|---|---|
| **Snort 2.x** | Version la plus répandue, avec le plus de règles et de documentation. **Utilisée dans ce lab.** |
| **Snort 3.0** | Plus performant, plus évolutif ; la configuration est écrite en **Lua** et les règles Snort 2 doivent être converties |

### 3.4 Types de règles

- **Community rules** : gratuites, créées par la communauté ;
- **Registered rules** : gratuites, mais nécessitent un compte ;
- **Subscription rules** : payantes (abonnement), pour disposer des dernières règles face aux nouvelles vulnérabilités.

On peut aussi **écrire ses propres règles**, par exemple après avoir analysé un nouvel exploit.

### 3.5 Syntaxe d'une règle Snort

Une règle comporte un **en-tête** (action, protocole, adresse et port source, direction, adresse et port destination) et des **options** entre parenthèses :

```text
action  protocole  ip_source  port_source  ->  ip_destination  port_destination  (options)
```

Exemple : `alert icmp any any -> $HOME_NET any (msg:"..."; sid:1001; rev:1;)`

Actions possibles : `alert`, `log`, `pass`, `drop`, `reject` (les deux dernières relèvent du mode IPS).

### 3.6 Placement de Snort dans le réseau

- **Mode IDS (ce lab)** : Snort est connecté au **commutateur** et observe le trafic de tout le réseau ;
- **Mode IPS (inline)** : Snort est placé à un **point de passage obligé** (entre le routeur et le commutateur) pour pouvoir bloquer les paquets. Il nécessite deux cartes réseau et le transfert du trafic.

<!-- 📸 IMAGE : schéma de placement de Snort en mode IDS et en mode IPS -->
![Placement de Snort](images/02-placement-snort.png)

---

## 4. 🧪 Architecture du laboratoire

Le laboratoire est virtualisé sous **VirtualBox**.

| Machine | Rôle | Adresse |
|---|---|---|
| **Ubuntu 20.04** | Serveur Snort (NIDS) | 192.168.2.179 |
| **Kali Linux** | Machine attaquante | Réseau NAT externe |
| **Metasploitable 2** | Serveur Linux vulnérable (cible SSH et FTP) | 192.168.2.157 |
| **Windows 7** | Cible de l'exploitation EternalBlue | 192.168.2.35 |

Réseau interne surveillé : **192.168.2.0/24**. Le commutateur virtuel de VirtualBox joue le rôle du commutateur du schéma.

<!-- 📸 IMAGE : schéma du lab réalisé (adresses IP des machines) -->
![Architecture du lab](images/03-architecture-lab.png)

<!-- 📸 IMAGE : liste des VM dans VirtualBox -->
![VM VirtualBox](images/04-vms-virtualbox.png)

---

## 5. ⚙️ Installation de Snort

### 5.1 Installation depuis les dépôts Ubuntu

```bash
sudo apt-get update
sudo apt-get install snort
```

Pendant l'installation, deux questions sont posées :

1. **L'interface à surveiller** : par exemple `enp0s3` (à repérer avec `ifconfig` ou `ip a`) ;
2. **La plage d'adresses du réseau** : par exemple `192.168.2.0/24`.

<!-- 📸 IMAGE : installation de Snort, fenêtre de choix de l'interface -->
![Choix de l'interface](images/05-install-interface.png)

<!-- 📸 IMAGE : installation de Snort, fenêtre de saisie de la plage d'adresses -->
![Plage d'adresses](images/06-install-plage-adresses.png)

### 5.2 Vérification de la version

```bash
snort --version
```

Résultat : **Snort 2.9.7.0 (build 149)**, avec ses dépendances (dont `libpcap`, la bibliothèque de capture utilisée aussi par Wireshark).

<!-- 📸 IMAGE : sortie de snort --version -->
![Version de Snort](images/07-snort-version.png)

### 5.3 Activation du mode promiscuité

Pour que l'interface capture le trafic destiné aux autres machines :

- **Sous VirtualBox** : `Paramètres` → `Réseau` → `Avancé` → *Mode promiscuité* : **Autoriser tout** ;
- **Sur une machine physique** :

```bash
sudo ip link set enp0s3 promisc on
```

<!-- 📸 IMAGE : paramètres réseau VirtualBox avec le mode promiscuité sur « Autoriser tout » -->
![Mode promiscuité](images/08-mode-promiscuite.png)

---

## 6. 🔧 Configuration de Snort

### 6.1 Arborescence

```text
/etc/snort/
├── snort.conf        # fichier de configuration principal
└── rules/
    ├── local.rules   # règles personnalisées (vide par défaut)
    └── *.rules       # règles fournies avec le paquet
```

> 💡 Bonne pratique : **sauvegarder** `snort.conf` avant de le modifier, ou travailler sur une copie (`-c` permet de choisir un fichier de configuration).

<!-- 📸 IMAGE : contenu du répertoire /etc/snort -->
![Répertoire /etc/snort](images/09-repertoire-snort.png)

### 6.2 Structure de `snort.conf`

Le fichier est organisé en sections : variables réseau, décodeur, moteur de détection de base, préprocesseurs, plugins de sortie, jeu de règles, etc.

<!-- 📸 IMAGE : index des sections au début de snort.conf -->
![Sections de snort.conf](images/10-sections-snort-conf.png)

### 6.3 Définition des variables réseau (étape 1)

| Variable | Valeur | Explication |
|---|---|---|
| `HOME_NET` | `192.168.2.0/24` | Le réseau à protéger |
| `EXTERNAL_NET` | `any` | Laisser sur `any` : les attaques peuvent venir de partout |

Il est aussi possible de définir des variables pour des serveurs critiques (DNS, SMTP, web) et les ports des serveurs web.

<!-- 📸 IMAGE : snort.conf, section ipvar HOME_NET et EXTERNAL_NET -->
![Variables réseau](images/11-home-net.png)

### 6.4 Chemin des règles et jeu de règles (étape 7)

- `RULE_PATH` pointe vers `/etc/snort/rules` ;
- `include $RULE_PATH/local.rules` charge les règles personnalisées ;
- les autres lignes `include` chargent les règles fournies par Snort et la communauté (une ligne commentée par `#` est désactivée).

<!-- 📸 IMAGE : snort.conf, étape 7 « customize your rule set » -->
![Étape 7 du fichier de configuration](images/12-etape7-regles.png)

### 6.5 Test de la configuration

```bash
sudo snort -T -i enp0s3 -c /etc/snort/snort.conf
```

Résultat : **3 476 règles de détection** chargées (3 476 chaînes d'options liées à 290 en-têtes de chaîne), avec des avertissements de **SID dupliqués** liés aux règles communautaires.

<!-- 📸 IMAGE : sortie de snort -T avec le nombre de règles chargées -->
![Test de configuration](images/13-test-configuration.png)

### 6.6 Désactivation des règles par défaut (pour apprendre)

Pour montrer le fonctionnement des règles écrites soi-même, les règles fournies ont été **commentées** (lignes 578 à 696) avec `vim` :

```vim
:set number
:578,696s/^/#/
```

Nouveau test : **0 règle de détection** chargée et plus d'erreurs de SID dupliqués. Seules les règles de `local.rules` seront désormais utilisées.

<!-- 📸 IMAGE : vim, commande de mise en commentaire des lignes 578 à 696 -->
![Désactivation des règles](images/14-desactivation-regles.png)

<!-- 📸 IMAGE : sortie de snort -T avec 0 règle chargée -->
![Test avec 0 règle](images/15-test-zero-regle.png)

---

## 7. ✍️ Écriture de règles personnalisées

Les règles sont écrites dans `/etc/snort/rules/local.rules`.

### 7.1 Détection des pings (ICMP)

```text
alert icmp any any -> $HOME_NET any (msg:"ICMP ping detected"; sid:1001; rev:1;)
```

Génère une alerte pour tout trafic ICMP provenant de n'importe quelle adresse et visant le réseau protégé.

### 7.2 Détection des tentatives de connexion SSH

```text
alert tcp any any -> $HOME_NET 22 (msg:"SSH authentication attempt"; sid:1002; rev:1;)
```

SSH utilise TCP sur le **port 22** : le port doit être précisé, sinon la règle ne fonctionne pas.

> 📌 Chaque règle possède un **SID unique** (ici 1001, 1002…) pour éviter les conflits avec les autres signatures.

<!-- 📸 IMAGE : fichier local.rules avec les règles ICMP et SSH -->
![Fichier local.rules](images/16-local-rules.png)

---

## 8. 🚀 Exécution de Snort et tests de détection

### 8.1 Commande de lancement

```bash
sudo snort -q -l /var/log/snort -i enp0s3 -A console -c /etc/snort/snort.conf
```

| Option | Rôle |
|---|---|
| `-q` | Mode silencieux (pas de bannière ni d'initialisation) |
| `-l /var/log/snort` | Répertoire des journaux |
| `-i enp0s3` | Interface surveillée |
| `-A console` | Alertes affichées dans la console |
| `-c /etc/snort/snort.conf` | Fichier de configuration |

> ⚠️ En mode IPS (inline), on utiliserait l'option `-Q`, à ne pas employer en mode IDS.

<!-- 📸 IMAGE : lancement de Snort dans le terminal -->
![Lancement de Snort](images/17-lancement-snort.png)

### 8.2 Test 1 : détection d'un ping

Depuis **Kali Linux** :

```bash
ping 192.168.2.157
```

Snort affiche des alertes **« ICMP ping detected »** en temps réel ; elles cessent dès l'arrêt du ping, ce qui valide la règle. Une alerte contient la date et l'heure, le SID, le message, la priorité, le protocole, l'adresse source et l'adresse destination.

<!-- 📸 IMAGE : ping depuis Kali vers Metasploitable 2 -->
![Ping depuis Kali](images/18-ping-kali.png)

<!-- 📸 IMAGE : alertes « ICMP ping detected » dans la console Snort -->
![Alertes ICMP](images/19-alertes-icmp.png)

### 8.3 Test 2 : détection d'une connexion SSH

Depuis **Kali Linux** :

```bash
ssh msfadmin@192.168.2.157
```

Snort affiche l'alerte **« SSH authentication attempt »**. Ce test illustre le point de vue du défenseur : l'activité réseau d'un attaquant devient visible grâce à une règle adaptée.

<!-- 📸 IMAGE : connexion SSH depuis Kali vers Metasploitable 2 -->
![Connexion SSH](images/20-connexion-ssh.png)

<!-- 📸 IMAGE : alerte « SSH authentication attempt » dans la console Snort -->
![Alerte SSH](images/21-alerte-ssh.png)

---

## 9. 🧩 Génération de règles avec Snorpy

**Snorpy** est une interface web qui facilite la création de règles : on choisit l'action, le protocole, les adresses, les ports, le message, le SID et la révision, puis on copie la règle générée dans `local.rules`.

Règle créée pour **FTP** (port 21) limitée à la machine Metasploitable 2 :

```text
alert tcp any any -> 192.168.2.157 21 (msg:"FTP authentication attempt on MS2"; sid:1003; rev:1;)
```

Test depuis Kali :

```bash
ftp 192.168.2.157
```

Snort détecte la tentative de connexion FTP vers la cible précise.

> 🔎 **Observation :** une alerte SSH est également apparue au redémarrage de Snort, vraisemblablement liée à une connexion antérieure ; elle mérite d'être investiguée (démarche normale d'un analyste).

<!-- 📸 IMAGE : interface Snorpy avec la règle FTP -->
![Snorpy](images/22-snorpy.png)

<!-- 📸 IMAGE : local.rules avec la règle FTP ajoutée -->
![Règle FTP](images/23-regle-ftp.png)

<!-- 📸 IMAGE : alerte « FTP authentication attempt on MS2 » -->
![Alerte FTP](images/24-alerte-ftp.png)

---

## 10. 🔥 Règles communautaires : détection d'EternalBlue

### 10.1 Réactivation et récupération des règles

1. Réactivation des règles précédemment commentées dans `snort.conf` (suppression des `#`) ;
2. Téléchargement des **règles communautaires** (Snort 2.9) depuis le site de Snort ;
3. Consultation du fichier `community.rules`, qui regroupe des signatures pour des **CVE**, des **malwares** et des **exploits** (par exemple la règle **log4j**).

<!-- 📸 IMAGE : page de téléchargement des règles sur snort.org -->
![Téléchargement des règles communautaires](images/25-telechargement-regles.png)

<!-- 📸 IMAGE : fichier community.rules (recherche d'EternalBlue ou de log4j) -->
![community.rules](images/26-community-rules.png)

### 10.2 La règle EternalBlue

**EternalBlue** exploite une vulnérabilité de **SMBv1 sous Windows** et permet l'**exécution de code à distance**. La règle récupérée dans `community.rules` :

- surveille le trafic TCP vers le réseau protégé sur le **port 445** ;
- vérifie le **flux** (`to_server, established`) ;
- recherche dans le **contenu** des paquets la **signature** propre à l'exploit ;
- comporte des **références** (code CVE, URL).

Elle a été copiée dans `local.rules` en veillant à ce que son **SID soit unique**.

<!-- 📸 IMAGE : règle EternalBlue copiée dans local.rules -->
![Règle EternalBlue](images/27-regle-eternalblue.png)

### 10.3 Test : exploitation d'une machine Windows 7

1. Démarrage de Snort et de la VM **Windows 7** (192.168.2.35) ;
2. Depuis **Kali Linux**, lancement du module **EternalBlue** de **Metasploit** avec l'adresse de la cible ;
3. Observation des alertes dans la console Snort.

Alertes observées :

- **Microsoft Windows SMB remote code execution attempt** : classification *attempted administrator privilege gain*, **priorité 1**, port **445** ;
- alerte **NetBIOS** indiquant l'accès à un partage **SMB IPC** ;
- alertes de type **« potentially bad traffic »** ;
- **plusieurs alertes** générées, car l'exploit envoie de nombreux paquets.

<!-- 📸 IMAGE : module EternalBlue configuré dans Metasploit sur Kali -->
![Exploit EternalBlue](images/28-exploit-eternalblue.png)

<!-- 📸 IMAGE : alertes EternalBlue dans la console Snort (priorité 1, port 445) -->
![Alertes EternalBlue](images/29-alertes-eternalblue.png)

---

## 11. 🗃️ Journalisation des alertes et du trafic

### 11.1 Journal du trafic (paquets)

Avec l'option `-l /var/log/snort`, Snort enregistre le **trafic brut** (fichiers de capture). Ces fichiers appartiennent à `root` : on les ouvre dans **Wireshark** avec `sudo wireshark`, ce qui permet d'analyser, par exemple, tous les paquets SMB de l'exploitation EternalBlue.

<!-- 📸 IMAGE : fichiers de log dans /var/log/snort -->
![Fichiers de log](images/30-fichiers-log.png)

<!-- 📸 IMAGE : capture de trafic SMB (EternalBlue) ouverte dans Wireshark -->
![Trafic dans Wireshark](images/31-wireshark-smb.png)

### 11.2 Journal des alertes (mode `fast`)

Pour enregistrer les **alertes** (et non plus seulement les afficher), on remplace `-A console` par `-A fast` :

```bash
sudo snort -q -l /var/log/snort -i enp0s3 -A fast -c /etc/snort/snort.conf
```

Snort écrit alors les alertes sur **une ligne**, au format syslog, dans le fichier `alert` du répertoire de logs. Ce format est idéal pour une **intégration à un SIEM** (Splunk, Wazuh) afin de centraliser et de visualiser les alertes.

<!-- 📸 IMAGE : lancement de Snort avec l'option -A fast -->
![Mode fast](images/32-mode-fast.png)

<!-- 📸 IMAGE : contenu du fichier d'alertes /var/log/snort/alert -->
![Fichier d'alertes](images/33-fichier-alertes.png)

---

## 12. ✅ Synthèse des résultats

| Test | Règle | Résultat |
|---|---|---|
| Ping (ICMP) | `sid:1001` | ✅ Alertes générées pendant le ping, arrêt à la fin |
| Connexion SSH | `sid:1002` | ✅ Tentative d'authentification détectée |
| Connexion FTP | `sid:1003` | ✅ Tentative détectée vers Metasploitable 2 |
| EternalBlue (SMB) | Règle communautaire | ✅ Tentative d'exécution de code détectée, priorité 1 |
| Journalisation | `-l` et `-A fast` | ✅ Trafic enregistré et alertes sauvegardées |

**Conclusion :** Snort détecte efficacement des activités réseau précises grâce à des règles simples, et la puissance de la détection dépend directement de la **qualité et de la mise à jour des règles**.

---

## 13. 🎓 Compétences démontrées

- **Installation et configuration d'un NIDS** (Snort 2) sous Linux
- **Administration du fichier `snort.conf`** : variables, chemins de règles, validation (`snort -T`)
- **Écriture de signatures** (règles personnalisées) et gestion des SID
- **Exploitation de règles communautaires** et détection de **CVE** (EternalBlue)
- **Tests offensifs / défensifs** : Kali, Metasploit, Metasploitable 2, Windows 7
- **Analyse de trafic** avec Wireshark à partir des journaux Snort
- **Journalisation** adaptée à l'intégration SIEM
- **Notions IDS / IPS** : placement réseau, modes, HIDS et NIDS
- **Utilisation d'outils en ligne de commande** (`vim`, `ip`, `ifconfig`, `ssh`, `ftp`)

---

## 14. 🛡️ Bonnes pratiques

- Sauvegarder `snort.conf` avant toute modification ;
- Donner un **SID unique** à chaque règle personnalisée ;
- Tester la configuration avec `snort -T` avant chaque lancement ;
- Garder les **règles à jour** pour détecter les dernières attaques ;
- Séparer les règles personnalisées (`local.rules`) des règles communautaires ;
- **Journaliser** les alertes dans un format exploitable par un SIEM ;
- Placer le NIDS sur un point du réseau voyant **tout le trafic** utile.

---

## 15. 🗂️ Structure du dépôt

```text
snort-nids-lab/
├── README.md
├── images/
│   ├── 00-vue-ensemble.png
│   ├── 01-fonctionnement-snort.png
│   ├── ...
│   └── 33-fichier-alertes.png
└── rules/
    └── local.rules   (optionnel : règles personnalisées du lab)
```

---

## 16. 📎 Ressources et crédits

- **Snort** : [snort.org](https://www.snort.org)
- **Snorpy** : générateur de règles Snort en ligne
- **Metasploitable 2** et **Kali Linux** : environnement de test
- **Série Blue Team Training** (HackerSploit, avec Linode) : démonstration suivie pour ce laboratoire, reproduite et documentée ici

---

### 👤 Auteur

**Dannon Rock** : Réseaux, systèmes et cybersécurité
🔗 [LinkedIn](https://www.linkedin.com/in/rock-dannon)

> ℹ️ *Ce dépôt est un projet d'apprentissage réalisé dans un environnement de laboratoire isolé. Les tests d'attaque ont été menés uniquement sur des machines virtuelles dédiées.*
