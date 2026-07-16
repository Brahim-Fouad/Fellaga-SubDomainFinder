# Fellaga SubDomainFinder

Fellaga est un énumérateur de sous-domaines écrit en Rust pour Kali Linux. Il combine plusieurs sources passives, un bruteforce DNS asynchrone et récursif, des tentatives AXFR automatiques, un inventaire SQLite et une base de connaissance strictement locale.

> Utilisez Fellaga uniquement sur des domaines que vous êtes autorisé à tester. Un transfert de zone et une énumération DNS restent des actions actives visibles par l'opérateur de la cible.

Documentation du projet : [contribution](CONTRIBUTING.md), [sécurité](SECURITY.md), [changements](CHANGELOG.md), [provenance du corpus](data/CORPUS_LICENSE.md) et [notices tierces](THIRD_PARTY_NOTICES.md).

## Ce qui fonctionne dans la version 0.8.0

- moteur UDP natif corrélé, EDNS0, repli TCP, équilibrage, limite de débit et récursion jusqu'à cinq niveaux ;
- graphe DNS `MX`, `NS`, `SOA`, `TXT`, `CAA`, `SRV`, `HTTPS` et `SVCB`, avec extraction des cibles, services et zones filles ;
- 27 connecteurs passifs enregistrés, dont WhoisXML et Netlas, et un collecteur Certificate Transparency global : chaque entrée CT est indexée une seule fois puis redistribuée localement à tous les domaines concernés ;
- tentative AXFR automatique en TCP sur les serveurs NS autoritaires, réussie uniquement avec les deux SOA qui encadrent un transfert complet ;
- détection wildcard automatique avec cinq sondes par zone, cache durable, contrôle du numéro de série SOA et reconnaissance des réponses tournantes ;
- détection DNSSEC NSEC, parcours borné des zones énumérables, identification de NSEC3 et des réponses NSEC minimales non parcourables ;
- extraction HTTP à faible bruit depuis les en-têtes, HTML, JavaScript, JSON, manifests et source maps ;
- inspection TLS multiport guidée par le DNS, avec négociation STARTTLS minimale pour SMTP, IMAP et POP3 ;
- pivot PTR borné uniquement sur les IP déjà confirmées, sans balayage de plage ;
- mutations contextuelles : environnements voisins, numéros adjacents, permutation de tokens et combinaisons service/environnement ;
- pipeline événementiel borné : chaque découverte Web, TLS, CT, NSEC ou graphe est dédupliquée, priorisée, validée puis peut déclencher les enrichissements suivants ;
- apprentissage probabiliste du rendement de chaque générateur selon le TLD, la profondeur et le fournisseur DNS, avec exploration contrôlée ;
- pool de résolveurs adaptatif qui mémorise latence et erreurs, préfère les serveurs sains et en explore périodiquement d'autres ;
- SQLite normalisé en mode WAL, lectures DNS groupées et writer dédié pour écrire les preuves par lots ;
- score de confiance expliqué pour chaque résultat, fondé sur les preuves indépendantes et la détection wildcard ;
- réponses DNS positives et toutes les observations acquises conservées sans expiration, avec état explicite `live`, `historical` ou `unverified` ;
- cache négatif temporaire afin qu'un nom absent puisse apparaître plus tard ;
- aucune fonction de partage, télémétrie ou synchronisation de la base locale ;
- sélection des sources selon les clés, leur rendement et leur historique d'échec ;
- couche HTTP commune aux sources externes : connexions réutilisées, limitation par fournisseur, réponses bornées à 16 Mio, erreurs détaillées, backoff avec jitter et prise en compte de `Retry-After` ;
- cache Web dédupliqué par URL canonique, avec revalidation ETag/Last-Modified et empreinte du contenu ;
- sorties texte, JSON, JSONL et progression en temps réel par phase ;
- corpus embarqué compressé d'exactement un million de candidats, traité par vagues persistées dans SQLite ;
- reprise `--resume latest`, checkpoints périodiques, consensus de résolveurs fiables et validation autoritaire ;
- familles de preuves indépendantes afin que plusieurs fournisseurs CT ne soient jamais comptés comme plusieurs techniques ;
- paquet Cargo `fellaga-subdomainfinder`, avec le binaire `fellaga` et la cible de bibliothèque Rust `fellaga_core`.

## Publications et vérification

Le code source du dépôt est la référence. Un artefact binaire est considéré publié uniquement lorsqu'il apparaît sur la page GitHub Releases avec un workflow de release réussi ; la présence d'un numéro dans le changelog ou d'un tag ne suffit pas. Le workflow est configuré pour joindre les archives Linux/Kali, le paquet Debian, le SBOM, `SHA256SUMS`, sa signature Sigstore et des attestations GitHub.

Après avoir téléchargé tous les fichiers d'une même release dans un dossier :

```bash
sha256sum -c SHA256SUMS
gh attestation verify fellaga-v0.8.0-x86_64-unknown-linux-gnu.tar.gz \
  --repo Brahim-Fouad/Fellaga-SubDomainFinder
```

La signature sans clé de la liste des empreintes peut aussi être contrôlée avec `cosign` :

```bash
cosign verify-blob \
  --bundle SHA256SUMS.sigstore.json \
  --certificate-identity "https://github.com/Brahim-Fouad/Fellaga-SubDomainFinder/.github/workflows/release.yml@refs/tags/v0.8.0" \
  --certificate-oidc-issuer "https://token.actions.githubusercontent.com" \
  SHA256SUMS
```

## Installation sous Kali

Depuis ce dossier :

```bash
chmod +x install.sh
./install.sh
```

Le script compile la version optimisée et installe `fellaga` dans `~/.local/bin`. Les dépendances et compilations sont conservées dans `target`, ce qui accélère les mises à jour suivantes. Si ce dossier n'est pas dans votre `PATH` :

```bash
export PATH="$HOME/.local/bin:$PATH"
```

Installation manuelle :

```bash
cargo build --release --locked --features vendored-openssl
install -Dm755 target/release/fellaga ~/.local/bin/fellaga
```

La base se trouve par défaut dans `~/.local/share/fellaga/fellaga.db`. Vous pouvez utiliser `--db CHEMIN` ou la variable `FELLAGA_DB`. Le fichier de clés est créé automatiquement dans `~/.config/fellaga/config.json` ; son emplacement peut être changé avec `--config` ou `FELLAGA_CONFIG`.

Le fichier de configuration contient les clés API en clair : il n'est pas chiffré. Sous Unix, Fellaga protège ses dossiers dédiés de configuration et de données en mode `0700`, puis le fichier de configuration, la base SQLite, ses journaux WAL/SHM et ses sauvegardes en `0600`. Un dossier parent partagé fourni explicitement n'est pas reconfiguré. Ces permissions ne remplacent ni le chiffrement du disque ni la protection du compte utilisateur. Ne publiez, ne sauvegardez dans le dépôt et ne joignez jamais ce fichier, la base SQLite ou des résultats de cible confidentiels.

Le moteur natif utilise par défaut une concurrence de 128, une limite globale de 100 requêtes DNS par seconde et un seul domaine actif à la fois. `fellaga resolvers test` permet d'écarter au préalable les résolveurs qui détournent NXDOMAIN, perdent DNSSEC ou répondent de façon incohérente.

> Les garde-fous sont actifs par défaut. `--dns-rate-limit 0` désactive volontairement la limite DNS et `--no-adaptive` force l'épuisement des vagues de candidats. Ces options sont réservées aux utilisateurs expérimentés, sur un laboratoire ou un périmètre explicitement autorisé : elles peuvent saturer la connexion, les résolveurs et la cible.

## Démarrage rapide

Scan complet avec CT, bruteforce rapide et AXFR automatique :

```bash
fellaga scan example.com
```

Cette commande lance le profil `deep` adaptatif par défaut : passif, CT, corpus 1M, récursion jusqu'à cinq niveaux, wildcard, AXFR, graphe DNS, NSEC, Web/JavaScript, archives, TLS/STARTTLS et PTR borné. Un domaine est traité à la fois, à 100 requêtes DNS par seconde, avec une durée maximale de 1 800 secondes par domaine. Les sources qui exigent une clé absente sont ignorées. Le bruteforce commence par les candidats les plus prometteurs, arrête les vagues dont le rendement devient insuffisant et traite les lots dans SQLite afin de garder une mémoire bornée. Utilisez `--resume latest` si la limite de temps est atteinte.

```bash
fellaga scan example.com --profile balanced
fellaga scan example.com --profile turbo --dns-rate-limit 100
fellaga scan example.com --resume latest
fellaga scan example.com --only-live --verification-max-age 6
fellaga scan example.com --stream-jsonl
```

Mode exhaustif expert, uniquement sur un laboratoire ou un périmètre explicitement autorisé. La limite DNS et la durée maximale restent volontairement actives, car `--no-adaptive` peut générer une charge très importante :

```bash
fellaga scan example.com \
  --all-sources \
  --wordlist /usr/share/seclists/Discovery/DNS/subdomains-top1million-110000.txt \
  --max-words 110000 \
  --dns-rate-limit 100 \
  --max-runtime 1800 \
  --no-adaptive
```

Pendant le scan, Fellaga affiche immédiatement :

```text
[>] passif: sources locales et distantes disponibles, cache 24 h
[P] certspotter: 42 nom(s) (cache frais)
[>] wildcard: racine normale, 0 sous-zone(s) wildcard
[>] DNS niveau 1: 250 candidat(s) à valider
[~] DNS niveau 1  [██████████░░░░░░░░░░] 50% 125/250 | +18 | cache 40 | 24/s | 5.2s
[DNS+] 38 requête(s), 16 relation(s), 2 service(s), 1 zone(s) fille(s)
[NSEC] 1 zone(s), 0 parcourue(s), 1 protégée(s), 1 requête(s), 0 nom(s)
[CT] 2 journaux, 128 entrées, 0 échec, 4 noms cumulés, 1.2s
[WEB] 12 hôtes, 18 requêtes, 5 cache, 1 échec, 3 noms, 2.1s
[TLS] 22 endpoint(s), 20 réseau, 16 succès, 4 échec(s), 2 cache, 7 nom(s), 3.1s
[+] api.example.com A=192.0.2.10 [fort 75] (passive:certspotter:cache cache)
```

Les phases et la barre de progression sont écrites sur `stderr`. Les sous-domaines validés sont diffusés sur `stdout` dès leur découverte. Avec `--json`, toute la progression passe sur `stderr` et le document JSON final reste seul sur `stdout`. `--quiet` désactive l'affichage en temps réel.

Plusieurs domaines, fichier ou stdin :

```bash
fellaga scan example.com example.org --jsonl
fellaga scan --targets-file domains.txt --output-dir results
printf 'example.com\nexample.org\n' | fellaga scan --no-axfr
```

Ces commandes traitent un seul domaine à la fois. Augmenter `--domain-concurrency` multiplie la charge réseau et doit rester un choix explicite adapté au périmètre.

Grande wordlist et résolveurs précis :

```bash
fellaga scan example.com \
  --wordlist /usr/share/seclists/Discovery/DNS/subdomains-top1million-110000.txt \
  --max-words 110000 \
  --resolvers 1.1.1.1,8.8.8.8 \
  --concurrency 128 \
  --dns-rate-limit 100 \
  --output example.com.json \
  --json
```

Passive seulement, tout en conservant la tentative AXFR :

```bash
fellaga scan example.com --passive-only
```

Désactiver un composant :

```bash
fellaga scan example.com --no-passive --no-axfr --no-tls --no-web --no-nsec --no-ct-monitor
```

Forcer la revalidation même si le cache est frais :

```bash
fellaga scan example.com --refresh-cache
```

Chercher sous les sous-domaines découverts :

```bash
fellaga scan example.com --depth 2 --recursive-words 150 --recursive-hosts 50
```

Le profil `deep` utilise `--depth 5`, mais reste adaptatif : il commence par 500 candidats, passe à une vague de 1 500, puis ne poursuit que si le rendement reste utile. La durée maximale par défaut est de 1 800 secondes par domaine. La récursion automatique limite d'abord le nombre de parents et de mots, puis s'arrête si un niveau produit moins de deux nouveaux noms. Seul `--no-adaptive`, réservé au mode expert, demande d'épuiser le corpus configuré.

Choisir les sources passives ou forcer leur mise à jour :

```bash
fellaga scan example.com --passive-sources crtsh,certspotter
fellaga scan example.com --exclude-sources wayback,otx
fellaga scan example.com --all-sources
fellaga scan example.com --passive-refresh-hours 0
fellaga scan example.com --passive-only --max-passive 1000
fellaga sources
fellaga sources --check --target example.com --timeout 10
```

Tester le pool de résolveurs avant une campagne, expliquer une preuve et échanger des inventaires :

```bash
fellaga resolvers test 1.1.1.1 8.8.8.8 9.9.9.9 --json
fellaga resolvers benchmark --queries 100000 --concurrency 128 --json
fellaga explain api.example.com --json
fellaga import example.com subfinder.txt --format subfinder
fellaga import example.com amass.json --format amass
fellaga export --domain example.com --format jsonl --output example.com.jsonl
```

Les imports Subfinder, Amass, BBOT et massdns entrent d'abord dans l'état `unverified`. Ils ne deviennent `live` qu'après validation DNS. Aucun inventaire, secret, apprentissage ou statistique n'est envoyé par Fellaga.

## Gestion de l'inventaire

```bash
# Tous les noms conservés, avec leur état
fellaga list --domain example.com

# Uniquement les validations encore live
fellaga list --domain example.com --only-live

# Revalider tous les noms connus, puis rafraîchir SQLite avec les garde-fous par défaut
fellaga refresh example.com --concurrency 128 --dns-rate-limit 100

# Historique et statistiques d'apprentissage
fellaga history --limit 20
fellaga stats
fellaga knowledge --limit 100

# Retirer uniquement les réponses négatives expirées du cache
fellaga cache prune
```

Lors d'un scan normal, Fellaga consulte SQLite avant le réseau :

1. une réponse positive est conservée sans date d'expiration, mais devient `historical` si sa validation est trop ancienne ;
2. une réponse négative encore fraîche empêche une requête inutile ;
3. une entrée absente ou une réponse négative expirée est résolue de nouveau ;
4. `--refresh-cache` force une nouvelle résolution malgré la copie permanente ;
5. `refresh` revalide l'inventaire sans lancer un nouveau bruteforce.

`--ttl-cap` reste accepté pour la compatibilité avec les anciennes commandes, mais n'expire plus les réponses positives.

## Découverte intelligente 0.8

Après la première résolution, Fellaga construit un graphe DNS. Les cibles trouvées dans `MX`, `NS`, `SOA`, `SRV`, `HTTPS`, `SVCB`, `TXT` et `CAA` sont réinjectées comme candidats si elles restent dans le périmètre. Les délégations `NS` et `SOA` signalent les zones filles ; les ports et protocoles `SRV`, `HTTPS` et `SVCB` guident ensuite l'inspection TLS. Les pivots PTR sont limités aux IP déjà associées à un nom confirmé.

Le planificateur n'interroge plus chaque type sur chaque hôte : `NS` et `SOA` ciblent les frontières de zone, les métadonnées de messagerie restent sur la racine et `HTTPS`/`SVCB` sont réservés aux hôtes prioritaires. Les noms produits entrent dans une file événementielle globale qui supprime les doublons avant le réseau et effectue au maximum `--pipeline-rounds` tours dans le budget `--pipeline-budget`.

```bash
# Graphe et services actifs par défaut ; exemple de limites prudentes
fellaga scan example.com --graph-hosts 100 --ptr-ips 32

# Réduire ou désactiver les boucles événementielles
fellaga scan example.com --pipeline-rounds 1 --pipeline-budget 1000
fellaga scan example.com --no-pipeline

# Désactiver ces deux pivots
fellaga scan example.com --no-dns-graph --no-ptr
```

Le moteur de candidats fabrique aussi des variantes à partir des noms déjà observés : `api-dev` peut produire `api-stage`, `api-prod` et `dev-api`; `node03` peut produire ses voisins numériques. Chaque proposition porte le nom de son générateur. Un modèle Beta-Bernoulli local apprend par contexte (`global`, suffixe public, domaine enregistrable, profondeur et fournisseur DNS) et combine rendement attendu, incertitude et exploration pour classer les générateurs des campagnes suivantes.

Le DSL `--mutations` accepte une règle par ligne sous la forme `score:nom:pattern`. Les variables disponibles sont `{{word}}`, `{{parent}}`, `{{env}}`, `{{region}}`, `{{cloud}}` et `{{n}}` :

```text
950:service-environnement:{{word}}-{{env}}
900:region-parent:{{region}}.{{parent}}
850:cloud-service:{{word}}-{{cloud}}-{{n}}
```

La phase Web ne visite que des hôtes déjà confirmés et lit au maximum `--web-max-bytes` par ressource. Elle inspecte la racine, les redirections dans le périmètre, les en-têtes utiles et un nombre borné d'assets JS/JSON/maps. Une URL canonique n'est réclamée qu'une fois par scan. Son cache fusionne les noms historiques, conserve ETag/Last-Modified et utilise les requêtes conditionnelles lors du rafraîchissement.

```bash
fellaga scan example.com --web-hosts 20 --web-assets 3 --web-max-bytes 262144
fellaga scan example.com --no-web
```

La phase DNSSEC envoie directement ses requêtes aux serveurs autoritaires. Une zone NSEC classique est parcourue jusqu'à `--nsec-max-names`; NSEC3 et les réponses NSEC minimales/« black lies » sont reconnues comme protégées et ne sont pas confondues avec un parcours vide. Seuls les résultats terminaux sont mis en cache.

```bash
fellaga scan example.com --nsec-max-names 1000 --nsec-timeout 3
fellaga scan example.com --no-nsec
```

La surveillance CT directe lit la liste publique des journaux, reprend un petit historique au premier passage, puis seulement les nouvelles entrées grâce à `ct_global_state`. Les certificats X.509 et pré-certificats sont décodés localement. Tous leurs noms valides entrent dans un index suffixé global `ct_names`, puis les noms du domaine courant sont fusionnés dans son cache `ct-direct`. Le curseur n'est donc plus répété pour chaque cible.

```bash
fellaga scan example.com --ct-logs 2 --ct-entries 256 --ct-backfill 256
fellaga scan example.com --no-ct-monitor
```

## AXFR

AXFR est activé par défaut. Fellaga :

1. demande les enregistrements `NS` du domaine ;
2. résout toutes les IPv4 et IPv6 de chaque serveur ;
3. ouvre les connexions DNS TCP en parallèle ;
4. demande le transfert complet de zone ;
5. conserve chaque tentative, succès, refus ou timeout dans SQLite ;
6. réinjecte dans l'énumération les noms obtenus en cas de succès.

Le délai par opération est réglable avec `--axfr-timeout`. Utilisez `--no-axfr` lorsque les règles du programme interdisent explicitement ce test.

## Certificats TLS et wildcard

Après la découverte DNS, Fellaga ouvre une connexion TLS courte vers la racine et les endpoints actifs les plus pertinents. Les enregistrements MX/SRV/HTTPS/SVCB peuvent ajouter des ports. Sur SMTP, IMAP et POP3 en clair, Fellaga lit la bannière et demande uniquement la montée STARTTLS avant le handshake. Il extrait ensuite SAN/CN ; seuls les vrais sous-domaines de la cible sont acceptés et revalidés en DNS.

```bash
# Forcer une nouvelle inspection, limiter à 40 endpoints et utiliser un timeout court
fellaga scan example.com --tls-refresh-hours 0 --tls-hosts 40 --tls-timeout 2.5

# Port TLS personnalisé ou désactivation complète
fellaga scan example.com --tls-port 8443
fellaga scan example.com --no-tls
```

Le certificat est inventorié même s'il est expiré, auto-signé ou mal configuré : il s'agit d'une observation, pas d'une décision de confiance. Aucune authentification ni commande applicative métier n'est tentée. L'inspection TLS reste une action réseau visible par la cible.

La détection wildcard utilise cinq noms aléatoires par zone et exige une majorité de trois. Elle compare les valeurs majoritaires, mais aussi la présence majoritaire d'un type (`A`, `AAAA` ou `CNAME`) pour détecter les pools wildcard qui font tourner leurs IP. Fellaga sonde la racine et jusqu'à 20 sous-zones observées par vague. Un nom correspondant est filtré s'il ne repose que sur une observation faible ; il est conservé et marqué `wildcard` s'il possède une preuve forte : consensus passif, CT direct, certificat TLS, AXFR, graphe DNS ou NSEC. `--include-wildcard` conserve aussi les observations faibles.

Le profil de chaque zone est conservé dans `wildcard_cache`. Pendant `--wildcard-refresh-hours` (6 h par défaut), aucun nouveau nom aléatoire n'est envoyé. Ensuite Fellaga vérifie d'abord le numéro de série SOA : s'il est inchangé, le profil est prolongé sans refaire les cinq sondes ; `--wildcard-refresh-hours 0` force le contrôle.

## Les mémoires locales

### 1. Cache DNS dynamique

`dns_cache` contient les réponses positives et négatives. Les réponses positives et les lignes correspondantes de `dns_records` sont permanentes. Seules les réponses négatives expirent, afin qu'un nom absent aujourd'hui puisse être découvert plus tard. Utilisez `refresh` ou `--refresh-cache` pour actualiser volontairement les données positives.

### 2. Cache passif persistant

`passive_cache` conserve la compatibilité et l'état de rafraîchissement, tandis que les nouvelles preuves sont écrites sous forme de lignes dans `observed_names` et `observation_evidence`. Un rafraîchissement fusionne les nouveaux noms avec les anciens : une réponse vide, partielle ou une source devenue indisponible ne peut donc pas effacer la connaissance acquise. Une source n'est normalement réinterrogée qu'après 24 h. Réglez cette fréquence avec `--passive-refresh-hours`.

`source_stats` mesure localement les succès, échecs, volumes et temps de réponse. Trois échecs consécutifs placent une source automatique en pause pendant 24 h ; son cache permanent continue d'être utilisé. Un succès ultérieur remet son compteur à zéro. Une source demandée explicitement avec `--passive-sources` ou `--all-sources` ignore cette pause. Les erreurs 408, 425, 429, 500, 502, 503 et 504 sont retentées avec backoff exponentiel et jitter. Un `Retry-After` inférieur ou égal à 30 secondes est attendu ; une attente plus longue est mémorisée exactement dans SQLite et la source reprend à l'heure demandée sans bloquer le scan.

Cert Spotter accepte facultativement `CERTSPOTTER_API_TOKEN`. OTX accepte `OTX_API_KEY` ou `X_OTX_API_KEY` et envoie la clé dans `X-OTX-API-KEY`; sans clé, un 429 anonyme explique clairement la configuration requise. HackerTarget limite son accès gratuit ; le cache évite de consommer cette limite à chaque scan.

### 3. Cache permanent des certificats TLS

`tls_certificate_cache` conserve par domaine, endpoint et port l'empreinte SHA-256 du dernier certificat ainsi que l'union de tous les SAN/CN déjà observés. Un certificat renouvelé ne supprime donc pas les anciens noms. Par défaut, une nouvelle connexion est tentée après 24 h ; `--tls-refresh-hours` règle ce délai et `0` force la mise à jour.

### 4. Base de connaissance permanente

Chaque libellé testé alimente `word_stats`. Les succès, le nombre de cibles distinctes et le ratio succès/essais déterminent le rang au scan suivant. `relative_patterns` conserve aussi les chemins complets qui réussissent, par exemple `api.dev`, `admin.internal` ou `status.eu`.

Ces deux tables n'ont aucune expiration : elles constituent le cache « en dur » des structures les plus fréquentes. La table `candidate_priors` contient en plus, dès la création de la base, le catalogue intégré de mots et de chemins imbriqués fréquents. Au scan suivant, Fellaga essaie d'abord la wordlist fournie, puis les chemins appris, les mots appris et enfin ce catalogue permanent. Les observations passives, AXFR et DNS validées alimentent toutes cette connaissance.

`generator_stats`, `generator_domains` et `generator_context_stats` gardent l'historique compatible. `generator_bandits` contient les postérieurs probabilistes par TLD, profondeur et fournisseur DNS. Un générateur rentable remonte ; un générateur peu essayé conserve une petite chance d'exploration. Aucun domaine observé n'est transmis.

### 5. Graphe DNS permanent

`discovery_edges`, `service_endpoints` et `child_zones` conservent chaque relation DNS, endpoint guidé et délégation avec dates de première/dernière observation et compteur de répétition. Une disparition ultérieure ne supprime pas la preuve historique.

### 6. Caches Web et DNSSEC

`web_discovery_cache` et `dnssec_walk_cache` fusionnent tous les noms déjà observés. Le cache Web ajoute ETag, Last-Modified et SHA-256 du contenu afin de revalider une ressource sans la retélécharger inutilement. Le statut récent et la date de rafraîchissement changent, mais l'ensemble historique reste conservé. Les échecs DNSSEC transitoires ne sont pas mémorisés comme résultat terminal.

### 7. Index Certificate Transparency global

`ct_global_state` mémorise un seul prochain index par journal. `ct_names` indexe les noms à l'envers pour retrouver rapidement tous ceux qui terminent par le domaine demandé. `passive_cache` conserve parallèlement l'union distribuée sous la source `ct-direct`. Le suivi reste incrémental et strictement local ; `ct_log_state` n'est conservée que pour lire les anciennes bases.

### 8. Résolveurs, pipeline et confiance

`resolver_stats` conserve requêtes, succès, erreurs, latence cumulée et échecs consécutifs. Lorsqu'on fournit plusieurs `--resolvers`, le pool favorise le meilleur profil tout en testant périodiquement les autres ; UDP et TCP sont disponibles par résolveur. `scan_pipeline_metrics` permet de vérifier le nombre d'événements, doublons supprimés, validations et éventuel épuisement du budget.

Chaque ligne de résultat et chaque entrée `scan_findings` reçoit enfin un score de 0 à 100, un niveau (`faible`, `probable`, `fort`, `confirmé`) et les raisons qui l'expliquent. Les preuves autoritaires ou indépendantes augmentent le score ; une correspondance wildcard le réduit fortement.

Les domaines sont représentés par un hash dans les tables de fréquence. L'inventaire complet reste nécessairement dans votre SQLite locale pour `list` et `refresh`. Rien n'est transmis à un serveur Fellaga, car aucun client de partage n'existe dans le binaire.

Cette absence de télémétrie ne rend pas un scan anonyme : les fournisseurs passifs interrogés reçoivent nécessairement le domaine demandé, tandis que les résolveurs et les services de la cible peuvent observer les requêtes DNS, HTTP ou TLS actives. Choisissez les sources et résolveurs selon les règles du périmètre.

Pour consulter cette mémoire :

```bash
fellaga knowledge --limit 100
```

## Sources et techniques d'alimentation

- `crt.sh` : journaux de transparence des certificats, souvent riches en anciens noms ;
- Cert Spotter : certificats et SAN, avec sous-domaines de profondeur quelconque ;
- HackerTarget Host Search : index DNS agrégé, limité en accès gratuit ;
- Common Crawl : noms d'hôtes extraits de cinq index et plusieurs pages de crawl public ;
- Wayback CDX : hôtes historiques archivés par Internet Archive ;
- urlscan : domaines de pages issus des scans publics (`URLSCAN_API_KEY` facultative) ;
- Anubis DB : base ouverte dédiée aux sous-domaines ;
- subdomain.app : API publique de noms observés ;
- AlienVault OTX : historique DNS passif public ;
- CIRCL Passive DNS : connecteur authentifié avec `CIRCL_PDNS_CREDENTIALS=user:password` ;
- CertificateDetails, Driftnet et Subdomain Center : connecteurs expérimentaux, isolés et bornés, activés dans le profil `deep` lorsqu'ils restent accessibles ;
- WhoisXML Subdomains Lookup et Netlas Domains Search : API officielles paginées, activées lorsque leur clé est configurée ;
- BeVigil, BuiltWith, Censys, Chaos, FullHunt, GitHub Code Search, GitLab global Code Search, Intelligence X, LeakIX, SecurityTrails, Shodan et VirusTotal : activés automatiquement dès que leur clé est configurée ;
- CT direct : liste publique des journaux Chrome, lecture incrémentale `get-sth`/`get-entries` et parsing local des certificats ;
- AXFR natif : zone complète lorsque le serveur autoritaire l'autorise ;
- graphe DNS : relations MX/NS/SOA/TXT/CAA/SRV/HTTPS/SVCB, zones filles, services et PTR borné ;
- bruteforce priorisé : wordlist externe, mutations contextuelles, connaissance permanente, puis corpus 1M ;
- récursion : les mots les plus efficaces sont testés sous les parents validés ;
- validation DNS : chaque nom passif est confirmé avant de passer à l'état `live` ;
- Web : redirections, en-têtes, HTML, JavaScript, JSON, manifests et source maps ;
- TLS direct et STARTTLS guidé : SAN/CN des certificats présentés, avec historique permanent ;
- DNSSEC : parcours NSEC borné et identification de NSEC3/NSEC minimal ;
- sondes wildcard hiérarchiques : racine et sous-zones fréquentes observées ;
- historique local : les chemins validés sur une cible améliorent les suivantes.

Le catalogue et l'état des clés sont visibles sans lancer de scan :

```bash
fellaga sources
fellaga sources --json
```

`fellaga sources` affiche aussi le ratio de succès, la latence moyenne, la dernière erreur et le temps restant avant la fin d'une pause adaptative. Le JSON ajoute ces données sous `health`, avec `next_retry` au format Unix.

Les clés peuvent être placées dans les variables affichées par cette commande ou dans `~/.config/fellaga/config.json`. Une chaîne ou une liste est acceptée ; plusieurs clés sont utilisées à tour de rôle :

```json
{
  "api_keys": {
    "github": ["token-1", "token-2"],
    "censys": "api-id:api-secret",
    "virustotal": "api-key"
  }
}
```

Les valeurs ci-dessus sont des exemples factices. Le fichier JSON et les variables d'environnement ne constituent pas un coffre-fort : évitez les journaux de diagnostic contenant l'environnement, ne commitez jamais ces secrets et révoquez immédiatement toute clé exposée.

Common Crawl est sérialisé globalement afin que plusieurs domaines ne frappent pas simultanément l'index public. L'URL du dernier index est conservée 30 jours dans `source_metadata_cache`; une réponse 404/410 force sa redécouverte. Wayback tente d'abord une requête bornée à 2 000 lignes, puis, en cas de timeout, quatre fenêtres temporelles parallèles de 1 000 lignes dont les résultats sont fusionnés au cache permanent.

Cert Spotter parcourt désormais jusqu'à 25 pages avec détection de curseur bloqué. urlscan utilise `search_after` sur cinq pages et extrait les hôtes depuis les domaines comme depuis les URL. Shodan active l'historique et suit le champ `more` sur dix pages. VirusTotal suit ses curseurs uniquement lorsqu'ils restent en HTTPS sur le domaine officiel, afin qu'une réponse compromise ne puisse pas détourner la clé API. Pour les sources paginées, une page tardive indisponible ne fait plus perdre les noms déjà récupérés.

Variables reconnues : `BEVIGIL_API_KEY`, `BUILTWITH_API_KEY`, `CENSYS_API_KEY`, `CERTSPOTTER_API_TOKEN`, `CHAOS_API_KEY`, `CIRCL_PDNS_CREDENTIALS`, `FULLHUNT_API_KEY`, `GITHUB_TOKEN`, `GITHUB_TOKENS`, `GITLAB_TOKEN`, `INTELX_API_KEY`, `LEAKIX_API_KEY`, `NETLAS_API_KEY`, `OTX_API_KEY`, `X_OTX_API_KEY`, `SECURITYTRAILS_API_KEY`, `SHODAN_API_KEY`, `URLSCAN_API_KEY`, `VIRUSTOTAL_API_KEY` et `WHOISXML_API_KEY`.

## Évolution naturelle de l'énumération

Un scan suit désormais cette boucle locale :

1. réutiliser les noms passifs et DNS déjà connus, sans expiration positive ;
2. reprendre les journaux CT globaux et distribuer leur index suffixé au domaine ;
3. classer wordlist et mutations avec les postérieurs contextuels locaux ;
4. réutiliser ou contrôler par SOA les profils wildcard ;
5. valider les vagues DNS via le pool de résolveurs adaptatif ;
6. construire le graphe avec un plan de requêtes réduit, puis détecter zones et services ;
7. injecter CT, graphe, PTR, NSEC, Web et TLS dans la même file événementielle dédupliquée ;
8. poursuivre les enrichissements tant que le nombre de tours et le budget le permettent ;
9. expliquer la confiance, écrire les preuves normalisées par lots et mettre à jour l'apprentissage.

Le profil `deep` est lui aussi adaptatif par défaut : comme `balanced` et `turbo`, il arrête les vagues à faible rendement, tout en utilisant des limites de profondeur et de couverture plus larges. Seul `--no-adaptive` lui demande d'épuiser les candidats configurés. À mesure que SQLite accumule des succès sur plusieurs domaines, les mots et chemins récurrents remontent dans l'ordre de test, tandis que les sources lentes ou durablement défaillantes cessent temporairement de pénaliser le temps total. Toutes ces décisions restent sur la machine.

L'architecture des connecteurs et plusieurs conventions d'interface ont été inspirées de [xsubfind3r](https://github.com/hueristiq/xsubfind3r), distribué sous licence MIT. L'attribution et la licence complète figurent dans [THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md). Fellaga conserve son propre moteur Rust, la validation DNS, SQLite permanent, l'AXFR, l'apprentissage et l'orchestration adaptative.

## Développement

```bash
cargo fmt --all -- --check
cargo test --all-targets --locked
cargo clippy --all-targets --locked -- -D warnings
tests/dns-lab/verify.sh
```

Le banc `benchmarks/run.sh` est prévu pour comparer Fellaga, Subfinder, Amass, BBOT, puredns et dnsx en modes sans clé et clés identiques. Il refuse de démarrer sans confirmation explicite du périmètre autorisé. Le workflow CI est configuré pour vérifier le corpus, le MSRV, les tests, le fuzzing et le laboratoire DNS. Le workflow des tags `v*` est configuré pour construire les binaires Linux/Kali x86-64 et ARM64, un `.deb`, un SBOM, des checksums, une signature Sigstore et des attestations GitHub ; son résultat doit être vérifié sur GitHub avant d'annoncer une release.

Structure principale :

- `src/lib.rs` : cible de bibliothèque `fellaga_core` du paquet `fellaga-subdomainfinder` ;
- `src/dns.rs` : moteur UDP natif, consensus, validation autoritaire, résolveurs et wildcard ;
- `src/pipeline.rs` : file d'événements priorisée, déduplication et budgets ;
- `src/confidence.rs` : score de confiance et raisons associées ;
- `src/discovery.rs` : graphe DNS, zones filles et services ;
- `src/dnssec.rs` : détection NSEC/NSEC3 et parcours borné ;
- `src/axfr.rs` : transfert de zone DNS TCP ;
- `src/ct_monitor.rs` : suivi direct et incrémental des journaux CT ;
- `src/web_discovery.rs` : extraction HTTP/HTML/JS/maps à faible bruit ;
- `src/tls.rs` : TLS/STARTTLS, extraction SAN/CN et cache permanent ;
- `src/candidate.rs` : mutations contextuelles et scoring ;
- `src/db.rs` : schéma SQLite, cache, inventaire et apprentissage ;
- `src/scanner.rs` : orchestration d'un scan et rafraîchissement ;
- `src/passive.rs` et `src/passive/extra.rs` : catalogue, configuration, sources passives et parsing ;
- `data/candidates-1m.txt.zst` : corpus SecLists dérivé d'un million de candidats, avec provenance et empreintes dans `data/CORPUS_LICENSE.md` ;
- `benchmarks/` : banc comparatif et seuil de publication ;
- `tests/dns-lab/` : serveur DNS contrôlé reproductible.
