# Contribuer à Fellaga

Merci de contribuer. Les changements doivent préserver trois propriétés : des
résultats traçables, une charge réseau bornée par défaut et aucune transmission
automatique de la base locale.

## Avant de commencer

- utilisez uniquement une zone DNS que vous contrôlez ou êtes autorisé à
  tester ;
- recherchez une issue existante avant d'en ouvrir une nouvelle ;
- ne joignez jamais de clé API, de base SQLite réelle ou de résultat de cible
  confidentiel ;
- gardez les connecteurs non documentés isolés, bornés et marqués
  `experimental` ; aucun contournement d'authentification ou de CAPTCHA n'est
  accepté.

Les échanges doivent rester respectueux et centrés sur des faits
reproductibles.

## Environnement de développement

Le paquet Cargo s'appelle `fellaga-subdomainfinder`. Il construit le binaire
`fellaga` et la cible de bibliothèque Rust `fellaga_core`. Le MSRV déclaré est
Rust 1.95.

Sous Kali ou Debian, installez au minimum Rust/Cargo, `pkg-config`, les en-têtes
OpenSSL et `zstd`, puis exécutez :

```bash
cargo fmt --all -- --check
cargo clippy --all-targets --all-features --locked -- -D warnings
cargo test --all-targets --all-features --locked
cargo build --release --locked
tests/dns-lab/verify.sh
```

Le laboratoire DNS est la préférence pour tester les wildcards, AXFR, NSEC,
troncatures et réponses incohérentes. Un test contre un domaine public ne
remplace pas un test reproductible et ne doit jamais devenir une fixture.

## Préparer un changement

1. Limitez chaque proposition à un problème cohérent.
2. Ajoutez un test qui échoue avant la correction lorsqu'il s'agit d'un bug.
3. Préservez la compatibilité des champs JSON publics ou documentez clairement
   la rupture envisagée.
4. Bornez toute nouvelle boucle réseau par un timeout, une limite de réponses,
   un budget et une annulation.
5. Expliquez la provenance de chaque nouvelle preuve et sa famille afin de ne
   pas compter deux fois une même source sous-jacente.
6. Mettez à jour `README.md` et `CHANGELOG.md` lorsque le comportement visible
   change.

Une pull request doit décrire le risque, la méthode de vérification et les
commandes de test exécutées. N'affirmez pas un gain de couverture ou de débit
sans corpus, paramètres et mesures reproductibles.

## Corpus embarqué

Le corpus distribué dérive d'une révision épinglée de SecLists. Consultez
`data/CORPUS_LICENSE.md` avant toute modification. Pour le reconstruire :

```bash
git clone https://github.com/danielmiessler/SecLists.git
git -C SecLists checkout 8a7c5daa498962e240a52c9b29164174478ffe78
SECLISTS_ROOT="$PWD/SecLists" ./scripts/build-corpus.sh
```

Le script vérifie les empreintes des deux sources, le contenu canonique et
l'archive produite. Une mise à jour de SecLists doit modifier ensemble le
script, le manifeste, les notices de licence et l'artefact compressé, avec une
explication du changement de couverture.

## Dépendances et licences

Conservez `Cargo.lock` avec les changements de dépendances. Vérifiez la licence
et la provenance de tout contenu redistribué, puis complétez
`THIRD_PARTY_NOTICES.md` si nécessaire. Le SBOM d'une release est un inventaire
complémentaire ; il ne remplace pas cette vérification.

## Vulnérabilités de Fellaga

N'ouvrez pas d'issue publique contenant une faille exploitable. Suivez plutôt
la procédure de `SECURITY.md`.
