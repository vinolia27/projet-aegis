# Projet AEGIS – Sécurité des systèmes d’information

## Membres du groupe
- Elyas Ouaness
- Bocar Mamadou Ba
- Vinolia Ouedraguo
- Malick Sasha Picot

## Contexte
Dans le cadre du projet AEGIS, nous avons travaillé sur un scénario de compromission du système d’information de l’entreprise fictive **TechSud**.  
L’objectif était d’identifier les failles, sécuriser une infrastructure Linux, mettre en place des mesures de protection, puis produire un rapport d’audit et une soutenance.

## Objectifs du projet
- Identifier les failles de sécurité
- Sécuriser l’accès distant à la machine
- Réduire la surface d’attaque
- Mettre en place une surveillance des tentatives d’accès
- Produire un audit automatisé avec export des résultats

## Environnement technique
- VM Ubuntu
- Réseau virtualisé privé
- OpenSSH
- UFW
- Fail2ban
- Python 3
- GitHub

## Mesures de sécurité mises en place
- Activation et configuration du service SSH
- Authentification par clé SSH
- Désactivation de l’authentification par mot de passe
- Interdiction de connexion root en SSH
- Changement du port SSH vers `2222`
- Configuration du pare-feu UFW
- Installation et configuration de Fail2ban sur `sshd`
- Vérification des permissions critiques sur `.ssh` et `authorized_keys`
- Vérification des utilisateurs et des privilèges

## Audit et automatisation
Un script Python `audit.py` a été développé afin de :
- récupérer des informations système
- vérifier l’état de services critiques
- contrôler certains éléments de conformité
- générer un rapport d’audit exploitable

## Exécution du script
Depuis le dossier du projet :

```bash
python3 audit.py
