# École Abou El Kacem Chebbi — Gestion scolaire (serveur + base de données)

Une seule application pour tous les visiteurs : les données sont dans une base PostgreSQL
partagée, et chaque personne ne voit que ce que son rôle autorise.

## Contenu
- `server.js` : serveur (Node.js / Express) — connexion, droits par rôle, fichiers PDF
- `public/index.html` : l'application (interface)
- `render.yaml` : configuration Render (serveur + base PostgreSQL)
- `test.js` : 50 vérifications automatiques (`npm test`)

## Mise en ligne (Render + GitHub)
1. Créez un dépôt GitHub (privé conseillé) et envoyez-y tout le contenu de ce dossier.
2. Sur https://dashboard.render.com : **New + → Blueprint**, choisissez le dépôt, puis **Apply**.
   Render crée le serveur **et** la base PostgreSQL, et génère `SESSION_SECRET` et `SETUP_CODE`.
3. Ouvrez le service web → **Environment** → copiez la valeur de **SETUP_CODE**.
4. Ouvrez l'adresse du site (`https://….onrender.com`) : l'écran **Première installation**
   demande ce code, puis le nom, l'identifiant et le mot de passe de l'administrateur.
5. Ensuite, l'administrateur crée tous les autres comptes (menu « Comptes utilisateurs »).

Aucun mot de passe par défaut n'existe : tant que personne n'a fait l'installation, seul le
détenteur du code d'installation peut créer l'administrateur.

## Plans Render (important)
| Élément | Gratuit | Pour un usage réel |
|---|---|---|
| Serveur web | se met en veille après 15 min (1er chargement ≈ 1 min) | `starter` (toujours actif) |
| Base PostgreSQL | **supprimée au bout de 30 jours** | `basic-256mb` ou plus (sauvegardes) |
Pour l'objectif de 99,5 % de disponibilité et la conservation des données, prévoyez les plans payants.

## Sécurité mise en place
Mots de passe hachés (scrypt) côté serveur ; session par cookie signé (HttpOnly, Secure) ;
blocage après 5 échecs ; mot de passe provisoire à changer à la première connexion ;
droits vérifiés **côté serveur** pour chaque modification ; chaque rôle ne reçoit que ses données ;
fichiers PDF contrôlés (type, taille 800 Ko) et accessibles seulement aux personnes concernées ;
en-têtes de sécurité (CSP, HSTS, anti-framing).

## Limites connues
- Les contrôles de saisie détaillés (formats, plages) sont faits dans l'interface ; le serveur
  vérifie surtout **qui a le droit de modifier quoi**.
- Pas encore : envoi d'e-mails/SMS réels, application installable (PWA), export RGPD automatisé,
  sauvegardes hors Render, plusieurs instances du serveur.
- Mise à jour des écrans des autres utilisateurs : toutes les 20 secondes (ou au changement de page).

## Essai en local
```
npm install
npm start        # http://localhost:3000 — code d'installation local : dev-setup
npm test
```
