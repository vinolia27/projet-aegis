#!/usr/bin/env python3
"""
╔══════════════════════════════════════════════════════════════════╗
║           AEGIS — Script d'audit SSI · Projet BTC1              ║
║           IPSSI · Réf. TS-2026-SSI-001                          ║
║           Auteurs : Groupe AEGIS                                 ║
╚══════════════════════════════════════════════════════════════════╝
Description :
   Script d'audit automatisé simulant l'analyse de l'infrastructure
   de la PME TechSud suite à un incident de sécurité.
   Fonctionnalités :
     - Inventaire des hôtes et services (scan de ports)
     - Vérification de la configuration SSH
     - Vérification du pare-feu (ufw)
     - Vérification de fail2ban
     - Analyse des utilisateurs et permissions suspectes
     - Export des résultats en JSON et CSV
Usage :
   sudo python3 audit_aegis.py [--target <IP ou réseau CIDR>] [--output <dossier>]
   Exemples :
       sudo python3 audit_aegis.py
       sudo python3 audit_aegis.py --target 192.168.1.0/24
       sudo python3 audit_aegis.py --target 192.168.1.10 --output ./resultats
Avertissement :
   Ce script est destiné à un usage pédagogique exclusivement.
   N'utilisez cet outil que sur des systèmes vous appartenant ou
   pour lesquels vous disposez d'une autorisation explicite.
"""
import argparse
import csv
import json
import os
import platform
import pwd
import re
import socket
import subprocess
import sys
from datetime import datetime
from pathlib import Path

# ──────────────────────────────────────────────────────────────────────────────
#  Configuration
# ──────────────────────────────────────────────────────────────────────────────
VERSION = "1.0.0"
PROJET = "AEGIS · BTC1 · IPSSI"
REFERENCE = "TS-2026-SSI-001"
# Infrastructure TechSud à auditer
HOSTS_TECHSUD = {
   "192.168.1.10": "SRV-PROD-01",
   "192.168.1.20": "SRV-WEB-01",
   "192.168.1.30": "SRV-BDD-01",
   "192.168.1.1":  "FW-01",
   "192.168.1.50": "NAS-01",
   "192.168.1.100": "PC-ADM-01",
}
# Ports à scanner et leur description
PORTS_TO_SCAN = {
   21:   "FTP",
   22:   "SSH",
   23:   "Telnet",
   25:   "SMTP",
   80:   "HTTP",
   443:  "HTTPS",
   445:  "SMB",
   3306: "MariaDB/MySQL",
   3389: "RDP",
   4444: "Metasploit/C2 (suspect)",
   5001: "Synology DSM",
   8080: "HTTP alternatif",
   8443: "HTTPS alternatif",
}
# Ports considérés comme dangereux si exposés sur Internet
PORTS_DANGEREUX = {
   21:   "FTP — transfert en clair",
   23:   "Telnet — protocole non chiffré",
   445:  "SMB — cible privilégiée des ransomwares",
   3306: "Base de données exposée directement",
   3389: "RDP — cible fréquente de brute force",
   4444: "Port C2 connu (Metasploit)",
}
# Fichiers et entrées suspects à rechercher
FICHIERS_SUSPECTS = [
   "/tmp/.x11-unix/sshd_bak",
   "/var/www/html/upload/shell.php",
   "/etc/cron.d/sysupdate",
]
CRON_SUSPECTS_PATTERNS = [
   r"/tmp/",
   r"\.sh\b",
   r"wget\s",
   r"curl\s",
   r"base64",
   r"nc\s",
   r"ncat",
   r"python.*-c",
   r"bash\s+-i",
]
# Couleurs ANSI
class C:
   RESET   = "\033[0m"
   BOLD    = "\033[1m"
   RED     = "\033[91m"
   YELLOW  = "\033[93m"
   GREEN   = "\033[92m"
   CYAN    = "\033[96m"
   MAGENTA = "\033[95m"
   GREY    = "\033[90m"
def colored(text, color):
   """Retourne le texte coloré si le terminal le supporte."""
   if sys.stdout.isatty():
       return f"{color}{text}{C.RESET}"
   return text

# ──────────────────────────────────────────────────────────────────────────────
#  Utilitaires
# ──────────────────────────────────────────────────────────────────────────────
def banner():
   print(colored("""
╔══════════════════════════════════════════════════════════════════╗
║           AEGIS — Script d'audit SSI · Projet BTC1              ║
║           IPSSI · Réf. TS-2026-SSI-001                          ║
╚══════════════════════════════════════════════════════════════════╝
""", C.CYAN))

def titre_section(titre: str):
   largeur = 66
   print()
   print(colored("─" * largeur, C.GREY))
   print(colored(f"  {titre}", C.BOLD))
   print(colored("─" * largeur, C.GREY))

def ok(msg):    print(colored(f"  [✓] {msg}", C.GREEN))
def warn(msg):  print(colored(f"  [!] {msg}", C.YELLOW))
def err(msg):   print(colored(f"  [✗] {msg}", C.RED))
def info(msg):  print(colored(f"  [i] {msg}", C.CYAN))

def run_cmd(cmd: list[str], timeout: int = 10) -> tuple[int, str, str]:
   """Exécute une commande et retourne (code_retour, stdout, stderr)."""
   try:
       result = subprocess.run(
           cmd,
           capture_output=True,
           text=True,
           timeout=timeout,
       )
       return result.returncode, result.stdout.strip(), result.stderr.strip()
   except subprocess.TimeoutExpired:
       return -1, "", "Timeout"
   except FileNotFoundError:
       return -1, "", f"Commande introuvable : {cmd[0]}"
   except Exception as e:
       return -1, "", str(e)

# ──────────────────────────────────────────────────────────────────────────────
#  1. Informations système
# ──────────────────────────────────────────────────────────────────────────────
def audit_systeme() -> dict:
   """Collecte les informations de base du système audité."""
   titre_section("1. Informations système")
   hostname = socket.gethostname()
   os_info  = platform.platform()
   kernel   = platform.release()
   arch     = platform.machine()
   try:
       ip_local = socket.gethostbyname(hostname)
   except Exception:
       ip_local = "Inconnue"
   code, uptime_out, _ = run_cmd(["uptime", "-p"])
   uptime = uptime_out if code == 0 else "Inconnu"
   code, uname_out, _ = run_cmd(["uname", "-r"])
   kernel_ver = uname_out if code == 0 else kernel
   data = {
       "hostname":    hostname,
       "ip_locale":   ip_local,
       "os":          os_info,
       "kernel":      kernel_ver,
       "architecture": arch,
       "uptime":      uptime,
       "date_audit":  datetime.now().isoformat(),
   }
   info(f"Hôte       : {hostname} ({ip_local})")
   info(f"OS         : {os_info}")
   info(f"Kernel     : {kernel_ver}")
   info(f"Uptime     : {uptime}")
   return data

# ──────────────────────────────────────────────────────────────────────────────
#  2. Scan de ports
# ──────────────────────────────────────────────────────────────────────────────
def scan_port(host: str, port: int, timeout: float = 1.0) -> bool:
   """Tente une connexion TCP sur un port. Retourne True si ouvert."""
   try:
       with socket.create_connection((host, port), timeout=timeout):
           return True
   except (socket.timeout, ConnectionRefusedError, OSError):
       return False

def audit_ports(cibles: dict[str, str]) -> list[dict]:
   """Scanne les ports des hôtes TechSud et retourne les résultats."""
   titre_section("2. Scan de ports — Infrastructure TechSud")
   resultats = []
   for ip, nom in cibles.items():
       info(f"Scan de {nom} ({ip}) ...")
       for port, service in PORTS_TO_SCAN.items():
           ouvert = scan_port(ip, port)
           criticite = "CRITIQUE" if port in PORTS_DANGEREUX else "INFO"
           raison_danger = PORTS_DANGEREUX.get(port, "")
           entree = {
               "host":       ip,
               "nom":        nom,
               "port":       port,
               "service":    service,
               "etat":       "OUVERT" if ouvert else "FERME",
               "criticite":  criticite if ouvert else "OK",
               "remarque":   raison_danger if ouvert else "",
           }
           resultats.append(entree)
           if ouvert:
               if port in PORTS_DANGEREUX:
                   err(f"  {nom}:{port} ({service}) — OUVERT — {raison_danger}")
               else:
                   warn(f"  {nom}:{port} ({service}) — ouvert")
   # Résumé
   ouverts = [r for r in resultats if r["etat"] == "OUVERT"]
   critiques = [r for r in ouverts if r["criticite"] == "CRITIQUE"]
   print()
   info(f"Ports ouverts : {len(ouverts)} | Critiques : {len(critiques)}")
   return resultats

# ──────────────────────────────────────────────────────────────────────────────
#  3. Configuration SSH
# ──────────────────────────────────────────────────────────────────────────────
def audit_ssh() -> list[dict]:
   """Analyse la configuration SSH du serveur local."""
   titre_section("3. Vérification SSH")
   chemin_config = "/etc/ssh/sshd_config"
   verifications = []
   if not os.path.exists(chemin_config):
       warn(f"{chemin_config} introuvable — SSH non installé ou chemin différent")
       return verifications
   try:
       with open(chemin_config, "r") as f:
           contenu = f.read()
   except PermissionError:
       warn("Impossible de lire sshd_config — relancez avec sudo")
       return verifications
   def check(param: str, valeur_attendue: str, valeur_dangereuse: str,
             description: str, recommandation: str) -> dict:
       """Vérifie une directive SSH dans le fichier de configuration."""
       pattern = rf"^\s*{param}\s+(.+)$"
       match = re.search(pattern, contenu, re.MULTILINE | re.IGNORECASE)
       valeur_actuelle = match.group(1).strip() if match else "(non définie)"
       conforme = valeur_actuelle.lower() not in valeur_dangereuse.lower().split(",")
       etat = "OK" if conforme else "NON_CONFORME"
       return {
           "parametre":       param,
           "valeur_actuelle": valeur_actuelle,
           "conforme":        conforme,
           "etat":            etat,
           "description":     description,
           "recommandation":  recommandation,
       }
   # Règles SSH à vérifier
   regles = [
       check("PermitRootLogin",       "no",          "yes,without-password,prohibit-password",
             "Connexion root directe en SSH",
             "Définir PermitRootLogin no dans sshd_config"),
       check("PasswordAuthentication", "no",          "yes",
             "Authentification par mot de passe activée",
             "Utiliser uniquement des clés SSH : PasswordAuthentication no"),
       check("PermitEmptyPasswords",   "no",          "yes",
             "Mots de passe vides autorisés",
             "Définir PermitEmptyPasswords no"),
       check("X11Forwarding",          "no",          "yes",
             "Redirection X11 activée (surface d'attaque inutile)",
             "Définir X11Forwarding no"),
       check("Protocol",               "2",           "1,1 2",
             "Version du protocole SSH",
             "Utiliser uniquement SSHv2 : Protocol 2"),
   ]
   # Vérification du port non-standard
   match_port = re.search(r"^\s*Port\s+(\d+)", contenu, re.MULTILINE)
   port_ssh = int(match_port.group(1)) if match_port else 22
   port_custom = {
       "parametre":       "Port",
       "valeur_actuelle": str(port_ssh),
       "conforme":        port_ssh != 22,
       "etat":            "OK" if port_ssh != 22 else "NON_CONFORME",
       "description":     "Port SSH par défaut (22) utilisé",
       "recommandation":  "Utiliser un port non-standard (ex. 2222, 2200)",
   }
   regles.append(port_custom)
   # Vérification MaxAuthTries
   match_tries = re.search(r"^\s*MaxAuthTries\s+(\d+)", contenu, re.MULTILINE)
   max_tries = int(match_tries.group(1)) if match_tries else 6
   regles.append({
       "parametre":       "MaxAuthTries",
       "valeur_actuelle": str(max_tries),
       "conforme":        max_tries <= 4,
       "etat":            "OK" if max_tries <= 4 else "NON_CONFORME",
       "description":     "Nombre de tentatives d'authentification SSH",
       "recommandation":  "Réduire MaxAuthTries à 3 ou 4",
   })
   for r in regles:
       if r["conforme"]:
           ok(f"{r['parametre']} = {r['valeur_actuelle']}")
       else:
           err(f"{r['parametre']} = {r['valeur_actuelle']} — {r['recommandation']}")
       verifications.append(r)
   return verifications

# ──────────────────────────────────────────────────────────────────────────────
#  4. Pare-feu (ufw)
# ──────────────────────────────────────────────────────────────────────────────
def audit_firewall() -> dict:
   """Vérifie l'état et les règles du pare-feu ufw."""
   titre_section("4. Vérification du pare-feu (ufw)")
   resultat = {
       "outil":   "ufw",
       "actif":   False,
       "regles":  [],
       "alertes": [],
   }
   code, stdout, stderr = run_cmd(["ufw", "status", "verbose"])
   if code == -1 and "introuvable" in stderr:
       warn("ufw non installé — sudo apt install ufw")
       resultat["alertes"].append("ufw non installé")
       return resultat
   if "inactive" in stdout.lower():
       err("Le pare-feu ufw est INACTIF")
       resultat["alertes"].append("pare-feu inactif")
       return resultat
   resultat["actif"] = True
   ok("ufw est actif")
   # Extraction des règles
   for ligne in stdout.splitlines():
       ligne = ligne.strip()
       if ligne and not ligne.startswith("Status") and not ligne.startswith("To"):
           resultat["regles"].append(ligne)
           if "ALLOW" in ligne.upper() and "Anywhere" in ligne:
               warn(f"Règle permissive détectée : {ligne}")
               resultat["alertes"].append(f"Règle permissive : {ligne}")
           else:
               info(f"Règle : {ligne}")
   return resultat

# ──────────────────────────────────────────────────────────────────────────────
#  5. fail2ban
# ──────────────────────────────────────────────────────────────────────────────
def audit_fail2ban() -> dict:
   """Vérifie l'état de fail2ban et les jails actives."""
   titre_section("5. Vérification de fail2ban")
   resultat = {
       "installe":    False,
       "actif":       False,
       "jails":       [],
       "alertes":     [],
   }
   code, stdout, _ = run_cmd(["fail2ban-client", "status"])
   if code == -1:
       err("fail2ban non installé ou non démarré")
       resultat["alertes"].append("fail2ban absent ou inactif")
       return resultat
   resultat["installe"] = True
   resultat["actif"]    = True
   ok("fail2ban est actif")
   # Extraction des jails
   match = re.search(r"Jail list:\s*(.+)", stdout)
   if match:
       jails = [j.strip() for j in match.group(1).split(",") if j.strip()]
       resultat["jails"] = jails
       if "sshd" in jails:
           ok(f"Jail SSH active : sshd")
       else:
           warn("Jail SSH (sshd) non détectée — pensez à l'activer")
           resultat["alertes"].append("jail sshd manquante")
       for jail in jails:
           info(f"Jail active : {jail}")
   else:
       warn("Aucune jail active détectée")
       resultat["alertes"].append("aucune jail active")
   return resultat

# ──────────────────────────────────────────────────────────────────────────────
#  6. Utilisateurs et comptes
# ──────────────────────────────────────────────────────────────────────────────
def audit_utilisateurs() -> list[dict]:
   """Analyse les comptes utilisateurs du système."""
   titre_section("6. Analyse des utilisateurs")
   utilisateurs = []
   try:
       entries = pwd.getpwall()
   except Exception as e:
       warn(f"Impossible de lire /etc/passwd : {e}")
       return utilisateurs
   for entry in entries:
       uid  = entry.pw_uid
       nom  = entry.pw_name
       home = entry.pw_dir
       shell= entry.pw_shell
       # Filtre : comptes système vs comptes réels
       est_systeme = uid < 1000 or shell in ("/usr/sbin/nologin", "/bin/false", "/sbin/nologin")
       peut_login  = shell not in ("/usr/sbin/nologin", "/bin/false", "/sbin/nologin")
       alertes     = []
       if peut_login and uid >= 1000:
           # Vérification si le home directory existe
           if not os.path.isdir(home):
               alertes.append(f"Répertoire home absent : {home}")
           # Vérification sudo
           code, out, _ = run_cmd(["groups", nom])
           in_sudo = "sudo" in out or "wheel" in out
           if in_sudo:
               alertes.append("membre du groupe sudo")
       u = {
           "nom":         nom,
           "uid":         uid,
           "shell":       shell,
           "home":        home,
           "peut_login":  peut_login,
           "est_systeme": est_systeme,
           "alertes":     alertes,
       }
       utilisateurs.append(u)
       if peut_login and uid >= 1000:
           if alertes:
               warn(f"Compte : {nom} (UID {uid}) — {', '.join(alertes)}")
           else:
               ok(f"Compte : {nom} (UID {uid}) — shell : {shell}")
   # Comptes spéciaux à surveiller
   comptes_sensibles = ["deploy", "www-data", "nobody"]
   for entry in entries:
       if entry.pw_name in comptes_sensibles:
           shell = entry.pw_shell
           peut_login = shell not in ("/usr/sbin/nologin", "/bin/false", "/sbin/nologin")
           if peut_login:
               err(f"Compte sensible avec shell actif : {entry.pw_name} → {shell}")
   return utilisateurs

# ──────────────────────────────────────────────────────────────────────────────
#  7. Fichiers suspects et artefacts d'incident
# ──────────────────────────────────────────────────────────────────────────────
def audit_fichiers_suspects() -> list[dict]:
   """Recherche les fichiers et artefacts liés à l'incident TechSud."""
   titre_section("7. Recherche de fichiers suspects (IoC TechSud)")
   trouvailles = []
   # Vérification des fichiers connus de l'incident
   for chemin in FICHIERS_SUSPECTS:
       existe = os.path.exists(chemin)
       entree = {
           "type":       "fichier_ioc",
           "chemin":     chemin,
           "present":    existe,
           "criticite":  "CRITIQUE" if existe else "OK",
       }
       trouvailles.append(entree)
       if existe:
           err(f"IoC détecté : {chemin}")
       else:
           ok(f"Absent (OK) : {chemin}")
   # Analyse des crons suspects
   titre_section("7b. Analyse des tâches cron")
   cron_dirs = ["/etc/cron.d", "/etc/cron.daily", "/var/spool/cron/crontabs"]
   for cron_dir in cron_dirs:
       if not os.path.isdir(cron_dir):
           continue
       try:
           for fichier in os.listdir(cron_dir):
               chemin_cron = os.path.join(cron_dir, fichier)
               try:
                   with open(chemin_cron, "r", errors="ignore") as f:
                       contenu = f.read()
                   for pattern in CRON_SUSPECTS_PATTERNS:
                       for ligne in contenu.splitlines():
                           if re.search(pattern, ligne, re.IGNORECASE):
                               entree = {
                                   "type":      "cron_suspect",
                                   "fichier":   chemin_cron,
                                   "ligne":     ligne.strip(),
                                   "pattern":   pattern,
                                   "criticite": "CRITIQUE",
                               }
                               trouvailles.append(entree)
                               err(f"Cron suspect dans {chemin_cron} : {ligne.strip()}")
               except PermissionError:
                   pass
       except PermissionError:
           pass
   return trouvailles

# ──────────────────────────────────────────────────────────────────────────────
#  8. Mises à jour système
# ──────────────────────────────────────────────────────────────────────────────
def audit_mises_a_jour() -> dict:
   """Vérifie si des mises à jour de sécurité sont disponibles."""
   titre_section("8. Mises à jour de sécurité")
   resultat = {
       "gestionnaire": "inconnu",
       "mises_a_jour":  0,
       "securite":      0,
       "alertes":       [],
   }
   # Détection du gestionnaire de paquets
   if Path("/usr/bin/apt").exists() or Path("/usr/bin/apt-get").exists():
       resultat["gestionnaire"] = "apt"
       run_cmd(["apt-get", "update", "-qq"], timeout=30)
       code, stdout, _ = run_cmd(
           ["apt-get", "--simulate", "upgrade"], timeout=30
       )
       if code == 0:
           lignes = [l for l in stdout.splitlines() if "upgraded" in l.lower()]
           if lignes:
               info(lignes[-1])
           # Paquets de sécurité
           code2, out2, _ = run_cmd(
               ["apt-get", "--simulate", "-t", "stable/updates", "upgrade"],
               timeout=30,
           )
           if code2 == 0:
               matches = re.findall(r"(\d+) upgraded", out2)
               resultat["securite"] = int(matches[0]) if matches else 0
       matches_total = re.findall(r"(\d+) upgraded", stdout)
       resultat["mises_a_jour"] = int(matches_total[0]) if matches_total else 0
   elif Path("/usr/bin/dnf").exists():
       resultat["gestionnaire"] = "dnf"
       code, stdout, _ = run_cmd(["dnf", "check-update", "--quiet"], timeout=30)
       lignes = [l for l in stdout.splitlines() if l.strip() and not l.startswith("Last")]
       resultat["mises_a_jour"] = len(lignes)
   if resultat["mises_a_jour"] > 0:
       warn(f"{resultat['mises_a_jour']} mise(s) à jour disponible(s)")
       resultat["alertes"].append(f"{resultat['mises_a_jour']} mises à jour en attente")
   else:
       ok("Système à jour")
   if resultat["securite"] > 0:
       err(f"{resultat['securite']} mise(s) à jour de SÉCURITÉ critique(s)")
   return resultat

# ──────────────────────────────────────────────────────────────────────────────
#  9. Services réseau actifs (ss / netstat)
# ──────────────────────────────────────────────────────────────────────────────
def audit_services_actifs() -> list[dict]:
   """Liste les services réseau en écoute sur la machine locale."""
   titre_section("9. Services réseau en écoute")
   services = []
   code, stdout, _ = run_cmd(["ss", "-tlnp"])
   if code != 0:
       code, stdout, _ = run_cmd(["netstat", "-tlnp"])
   for ligne in stdout.splitlines():
       if "LISTEN" not in ligne and "ESTAB" not in ligne:
           continue
       parts = ligne.split()
       if len(parts) < 4:
           continue
       adresse = parts[3] if "ss" in str(run_cmd(["which", "ss"])[1]) else parts[3]
       port_match = re.search(r":(\d+)$", adresse)
       port = int(port_match.group(1)) if port_match else 0
       service_nom = PORTS_TO_SCAN.get(port, "inconnu")
       alerte = port in PORTS_DANGEREUX
       entree = {
           "port":     port,
           "adresse":  adresse,
           "service":  service_nom,
           "alerte":   alerte,
           "ligne":    ligne.strip(),
       }
       services.append(entree)
       if alerte:
           err(f"Port dangereux en écoute : {port} ({service_nom}) — {adresse}")
       elif port > 0:
           info(f"Port {port} ({service_nom}) en écoute sur {adresse}")
   return services

# ──────────────────────────────────────────────────────────────────────────────
#  10. Synthèse et score de conformité
# ──────────────────────────────────────────────────────────────────────────────
def calcul_score(resultats: dict) -> dict:
   """Calcule un score de conformité SSI global."""
   titre_section("10. Score de conformité SSI")
   points = 0
   total  = 0
   alertes_globales = []
   def ajoute(condition: bool, poids: int, libelle: str):
       nonlocal points, total
       total  += poids
       if condition:
           points += poids
           ok(f"[{poids}pts] {libelle}")
       else:
           err(f"[0/{poids}pts] {libelle}")
           alertes_globales.append(libelle)
   # SSH
   ssh_checks = resultats.get("ssh", [])
   ssh_conformes = sum(1 for c in ssh_checks if c.get("conforme"))
   ssh_total     = len(ssh_checks) if ssh_checks else 1
   ajoute(ssh_conformes == ssh_total,    20, f"SSH entièrement durci ({ssh_conformes}/{ssh_total} règles OK)")
   # Pare-feu
   fw = resultats.get("firewall", {})
   ajoute(fw.get("actif", False),         15, "Pare-feu ufw actif")
   ajoute(len(fw.get("alertes", [])) == 0, 10, "Aucune règle de pare-feu permissive détectée")
   # fail2ban
   f2b = resultats.get("fail2ban", {})
   ajoute(f2b.get("actif", False),        15, "fail2ban actif")
   ajoute("sshd" in f2b.get("jails", []), 10, "Jail fail2ban SSH active")
   # Fichiers suspects
   iocs = [f for f in resultats.get("fichiers", []) if f.get("present")]
   ajoute(len(iocs) == 0,                 20, "Aucun IoC connu détecté")
   # Mises à jour
   maj = resultats.get("maj", {})
   ajoute(maj.get("mises_a_jour", 1) == 0, 10, "Système à jour")
   score_pct = round((points / total) * 100) if total > 0 else 0
   print()
   if score_pct >= 80:
       niveau = colored(f"✓ BON ({score_pct}%)", C.GREEN)
   elif score_pct >= 50:
       niveau = colored(f"! MOYEN ({score_pct}%)", C.YELLOW)
   else:
       niveau = colored(f"✗ INSUFFISANT ({score_pct}%)", C.RED)
   print(f"\n  Score de conformité SSI : {niveau}  ({points}/{total} points)\n")
   return {
       "points":          points,
       "total":           total,
       "pourcentage":     score_pct,
       "niveau":          "BON" if score_pct >= 80 else ("MOYEN" if score_pct >= 50 else "INSUFFISANT"),
       "alertes":         alertes_globales,
   }

# ──────────────────────────────────────────────────────────────────────────────
#  Export JSON & CSV
# ──────────────────────────────────────────────────────────────────────────────
def exporter_json(rapport: dict, dossier: str) -> str:
   """Exporte le rapport complet en JSON."""
   os.makedirs(dossier, exist_ok=True)
   horodatage = datetime.now().strftime("%Y%m%d_%H%M%S")
   chemin = os.path.join(dossier, f"audit_aegis_{horodatage}.json")
   with open(chemin, "w", encoding="utf-8") as f:
       json.dump(rapport, f, indent=2, ensure_ascii=False, default=str)
   return chemin

def exporter_csv(ports: list[dict], dossier: str) -> str:
   """Exporte les résultats de scan de ports en CSV."""
   os.makedirs(dossier, exist_ok=True)
   horodatage = datetime.now().strftime("%Y%m%d_%H%M%S")
   chemin = os.path.join(dossier, f"ports_aegis_{horodatage}.csv")
   if not ports:
       return chemin
   with open(chemin, "w", newline="", encoding="utf-8") as f:
       writer = csv.DictWriter(f, fieldnames=ports[0].keys())
       writer.writeheader()
       writer.writerows(ports)
   return chemin

# ──────────────────────────────────────────────────────────────────────────────
#  Main
# ──────────────────────────────────────────────────────────────────────────────
def parse_args():
   parser = argparse.ArgumentParser(
       description="AEGIS — Script d'audit SSI · Projet BTC1 IPSSI",
       formatter_class=argparse.RawDescriptionHelpFormatter,
       epilog=__doc__,
   )
   parser.add_argument(
       "--target", "-t",
       default=None,
       help="IP ou plage CIDR à scanner (ex: 192.168.1.0/24). "
            "Par défaut : infrastructure TechSud prédéfinie."
   )
   parser.add_argument(
       "--output", "-o",
       default="./rapports_audit",
       help="Dossier de sortie pour les rapports (défaut : ./rapports_audit)"
   )
   parser.add_argument(
       "--local-only", "-l",
       action="store_true",
       help="Effectue uniquement les vérifications locales (SSH, pare-feu, etc.)"
   )
   parser.add_argument(
       "--version", "-v",
       action="version",
       version=f"audit_aegis.py v{VERSION} — {PROJET}"
   )
   return parser.parse_args()

def main():
   args = parse_args()
   banner()
   print(colored(f"  Version : {VERSION}  |  {PROJET}  |  Réf. {REFERENCE}", C.GREY))
   print(colored(f"  Date    : {datetime.now().strftime('%d/%m/%Y %H:%M:%S')}", C.GREY))
   print(colored(f"  Dossier : {args.output}", C.GREY))
   rapport = {
       "meta": {
           "version":   VERSION,
           "projet":    PROJET,
           "reference": REFERENCE,
           "date":      datetime.now().isoformat(),
           "operateur": os.getenv("USER", "inconnu"),
       }
   }
   # 1. Système
   rapport["systeme"] = audit_systeme()
   # 2. Scan de ports
   if not args.local_only:
       cibles = HOSTS_TECHSUD
       if args.target:
           # Support d'une IP unique ou plage simple
           cibles = {args.target: args.target}
       rapport["ports"] = audit_ports(cibles)
   else:
       rapport["ports"] = []
       info("Scan de ports ignoré (--local-only)")
   # 3. SSH
   rapport["ssh"] = audit_ssh()
   # 4. Pare-feu
   rapport["firewall"] = audit_firewall()
   # 5. fail2ban
   rapport["fail2ban"] = audit_fail2ban()
   # 6. Utilisateurs
   rapport["utilisateurs"] = audit_utilisateurs()
   # 7. Fichiers suspects
   rapport["fichiers"] = audit_fichiers_suspects()
   # 8. Mises à jour
   rapport["maj"] = audit_mises_a_jour()
   # 9. Services actifs
   rapport["services"] = audit_services_actifs()
   # 10. Score
   rapport["score"] = calcul_score(rapport)
   # Export
   titre_section("Export des résultats")
   chemin_json = exporter_json(rapport, args.output)
   chemin_csv  = exporter_csv(rapport["ports"], args.output)
   ok(f"Rapport JSON : {chemin_json}")
   ok(f"Ports CSV    : {chemin_csv}")
   # Récapitulatif final
   titre_section("Récapitulatif des alertes")
   toutes_alertes = rapport["score"].get("alertes", [])
   if toutes_alertes:
       for alerte in toutes_alertes:
           err(alerte)
   else:
       ok("Aucune alerte critique détectée — bonne configuration !")
   print()
   print(colored("  Audit terminé. Consultez le rapport JSON pour le détail complet.", C.CYAN))
   print(colored(f"  Score final : {rapport['score']['pourcentage']}% "
                 f"({rapport['score']['niveau']})\n", C.BOLD))
   return 0 if rapport["score"]["pourcentage"] >= 80 else 1

if __name__ == "__main__":
   sys.exit(main())
