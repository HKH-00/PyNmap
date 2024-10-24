import nmap
import pyfiglet  # Pour convertir le pseudo en ASCII art
from tqdm import tqdm  # Pour la barre de progression
import time
import schedule  # Pour le scan planifié
import requests  # Pour l'API CVE
import json  # Pour analyser la réponse JSON de l'API CVE
import socket  # Pour obtenir l'IP locale
import netifaces  # Pour obtenir les informations sur le réseau

# Initialiser le scanner nmap
scanner = nmap.PortScanner()

# Variable où tu entres ton pseudo
pseudo = "PyNmap"  # Remplace "TonPseudo" par ton pseudo
info_dev = "PyNmap developed by HKH-00 "
info_dev1 = "https://github.com/HKH-00/"
CVE_API_KEY = "TA_CLE_API_NVD"  # Remplace par ta clé API NVD si besoin

# Fonction pour afficher le pseudo en ASCII Art
def afficher_pseudo_ascii(pseudo):
    ascii_art = pyfiglet.figlet_format(pseudo)
    print(ascii_art)
    print(info_dev)
    print(info_dev1)

# Fonction pour afficher le menu des choix
def afficher_menu():
    print("\nMenu :")
    print("1. Scanner Rapide")
    print("2. Scanner Approfondi")
    print("3. Détection de Vulnérabilités")
    print("4. Planification d'un Scan")
    print("5. Détection Automatique du Réseau")
    print("6. Quitter")
    choix = input("Sélectionnez une option (1, 2, 3, 4, 5, 6) : ")
    return choix

# Fonction pour demander à l'utilisateur la plage d'adresses IP à scanner
def demander_plage_ip():
    reseau = input("Entrez la plage d'adresses IP à scanner (exemple : 192.168.1.0/24) : ")
    return reseau

# Fonction pour afficher une barre de progression
def barre_progression(duree):
    for _ in tqdm(range(100), desc="Scanning en cours", ascii=True, ncols=100):
        time.sleep(duree / 100)  # Simulation de la progression

# Fonction pour un scan rapide : détecter les hôtes actifs
def scanner_rapide(reseau):
    print(f"Scanning rapide du réseau {reseau}...")
    barre_progression(3)  # Barre de progression pour simuler un scan rapide
    resultats = scanner.scan(hosts=reseau, arguments='-sP')  # Scan rapide (ping)
    hôtes_actifs = resultats['scan']
    print(f"{len(hôtes_actifs)} hôtes actifs détectés")
    return hôtes_actifs

# Fonction pour un scan approfondi : avec détection des services et OS
def scanner_approfondi(hote):
    print(f"Scanning détaillé de {hote}...")
    barre_progression(5)  # Barre de progression pour simuler un scan approfondi
    resultats = scanner.scan(hote, arguments='-sV -O')  # Scan détaillé avec détection de l'OS et des versions
    return resultats

# Fonction pour analyser et afficher les détails d'un hôte
def afficher_details_hote(hote, details_scan):
    print(f"--- Détails pour {hote} ---")
    if 'tcp' in details_scan['scan'][hote]:
        for port in details_scan['scan'][hote]['tcp']:
            service = details_scan['scan'][hote]['tcp'][port]['name']
            version = details_scan['scan'][hote]['tcp'][port]['version']
            etat = details_scan['scan'][hote]['tcp'][port]['state']
            print(f"Port {port}: {service} (Version: {version}, État: {etat})")
    if 'osclass' in details_scan['scan'][hote]:
        for osclass in details_scan['scan'][hote]['osclass']:
            print(f"OS détecté : {osclass['osfamily']} - {osclass['osgen']}")

# Fonction pour détecter les vulnérabilités basées sur les versions de services détectées
def detecter_vulnerabilites(details_scan):
    vulnerabilites = []
    
    for hote in details_scan['scan']:
        if 'tcp' in details_scan['scan'][hote]:
            for port in details_scan['scan'][hote]['tcp']:
                service = details_scan['scan'][hote]['tcp'][port]['name']
                version = details_scan['scan'][hote]['tcp'][port]['version']
                if version:  # Si la version est disponible, suggérer de vérifier
                    vulnerabilites.append(f"Service: {service}, Version: {version} à vérifier pour vulnérabilités CVE")
    
    if vulnerabilites:
        print("\n--- Vulnérabilités potentielles détectées ---")
        for vuln in vulnerabilites:
            print(vuln)
    else:
        print("Aucune vulnérabilité détectée à première vue.")

# Fonction pour planifier un scan à intervalles réguliers
def planifier_scan(reseau, intervalle):
    def scan_intervalle():
        print(f"Lancement d'un scan planifié sur {reseau}")
        scanner_rapide(reseau)
    
    # Planification avec le module schedule
    schedule.every(intervalle).minutes.do(scan_intervalle)
    print(f"Scan planifié toutes les {intervalle} minutes.")
    
    while True:
        schedule.run_pending()
        time.sleep(1)

# Fonction pour détecter automatiquement la plage d'IP
def detecter_reseau_local():
    try:
        # Obtenir l'adresse IP locale en se connectant à un serveur externe
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        # On se connecte à une adresse IP externe (Google DNS par exemple)
        sock.connect(("8.8.8.8", 80))
        ip_locale = sock.getsockname()[0]
        sock.close()

        # Obtenir les interfaces réseaux et leur configuration
        interfaces = netifaces.interfaces()

        for interface in interfaces:
            adresse = netifaces.ifaddresses(interface)
            if netifaces.AF_INET in adresse:
                ip_info = adresse[netifaces.AF_INET][0]
                if ip_info['addr'] == ip_locale:
                    # On récupère l'IP et le masque de sous-réseau
                    ip = ip_info['addr']
                    masque = ip_info['netmask']
                    
                    # Calcul de la plage réseau
                    masque_bits = sum([bin(int(x)).count('1') for x in masque.split('.')])
                    plage_ip = f"{ip}/{masque_bits}"
                    print(f"Réseau détecté automatiquement : {plage_ip}")
                    return plage_ip

        print("Erreur : Impossible de détecter automatiquement le réseau.")
        return None
    except Exception as e:
        print(f"Erreur lors de la détection du réseau : {str(e)}")
        return None

# Fonction principale pour gérer les différentes options
def main():
    afficher_pseudo_ascii(pseudo)  # Afficher le pseudo en ASCII art au lancement
    choix = afficher_menu()

    if choix == '1':
        # Scanner rapide
        reseau = demander_plage_ip()
        hotes = scanner_rapide(reseau)
        print("\nHôtes actifs détectés :")
        for hote in hotes:
            print(f"- {hote}")
    
    elif choix == '2':
        # Scanner approfondi
        reseau = demander_plage_ip()
        hotes = scanner_rapide(reseau)  # D'abord détecter les hôtes actifs
        for hote in hotes:
            details = scanner_approfondi(hote)
            afficher_details_hote(hote, details)
    
    elif choix == '3':
        # Détection de vulnérabilités
        reseau = demander_plage_ip()
        hotes = scanner_rapide(reseau)  # D'abord détecter les hôtes actifs
        for hote in hotes:
            details = scanner_approfondi(hote)
            detecter_vulnerabilites(details)
    
    elif choix == '4':
        # Planification d'un scan
        reseau = demander_plage_ip()
        intervalle = int(input("Entrez l'intervalle de scan (en minutes) : "))
        planifier_scan(reseau, intervalle)

    elif choix == '5':
        # Détection automatique du réseau
        reseau_auto = detecter_reseau_local()
        if reseau_auto:
            hotes = scanner_rapide(reseau_auto)  # Scanner le réseau détecté
            print("\nHôtes actifs détectés :")
            for hote in hotes:
                print(f"- {hote}")
    
    elif choix == '6':
        # Quitter
        print("Fermeture du programme. À bientôt !")
    
    else:
        print("Option invalide. Veuillez réessayer.")

# Lancer le programme
if __name__ == "__main__":
    main()
