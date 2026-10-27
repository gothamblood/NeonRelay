# Politique de sécurité / Security Policy

## Versions supportées / Supported versions

Seule la dernière version de la branche `main` reçoit des correctifs de sécurité.
Only the latest `main` branch receives security fixes.

| Version | Supportée / Supported |
|---------|:---------------------:|
| `main` (dernière / latest) | ✅ |
| versions antérieures / older | ❌ |

## Signaler une vulnérabilité / Reporting a vulnerability

**FR —** Merci de **ne pas** ouvrir d'issue publique pour une faille de sécurité.
Signale-la en privé par courriel à **gothambloodtech@gmail.com**, avec :

- une description de la vulnérabilité et de son impact ;
- les étapes pour la reproduire (proof of concept si possible) ;
- la version / le commit concerné.

Nous accusons réception sous **72 heures** et visons un premier retour sur la
recevabilité et les prochaines étapes sous **7 jours**. Merci de nous laisser un
délai raisonnable pour corriger avant toute divulgation publique (divulgation
coordonnée).

**EN —** Please **do not** open a public issue for a security flaw.
Report it privately by email to **gothambloodtech@gmail.com**, including:

- a description of the vulnerability and its impact;
- steps to reproduce (a proof of concept if possible);
- the affected version / commit.

We acknowledge reports within **72 hours** and aim to give a first assessment of
validity and next steps within **7 days**. Please allow us reasonable time to fix
before any public disclosure (coordinated disclosure).

## Portée / Scope

NeonRelay est conçu pour ne rien conserver du trafic (fire-and-forget), avec TLS
obligatoire et chiffrement de bout en bout optionnel. Sont particulièrement
d'intérêt : contournement de l'authentification (admin ou token), fuite de
trafic/secrets, contournement du TLS/épinglage, ou toute persistance non prévue
de données.

NeonRelay is built to retain no traffic (fire-and-forget), with mandatory TLS and
optional end-to-end encryption. Of particular interest: authentication bypass
(admin or token), traffic/secret leakage, TLS/pinning bypass, or any unintended
data persistence.
