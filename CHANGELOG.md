# Journal des changements

Ce projet suit les principes de [Keep a Changelog](https://keepachangelog.com/fr/1.1.0/).
La disponibilité d'une version et de ses artefacts se vérifie sur la page
GitHub Releases ; un numéro présent dans ce fichier ne prouve pas à lui seul
qu'une publication a réussi.

## [0.8.0] - 2026-07-16

Première version publique préparée de Fellaga.

### Ajouté

- moteur DNS Rust asynchrone avec UDP corrélé, EDNS0, repli TCP, limites de
  débit et validation par résolveurs de confiance ;
- inventaire SQLite permanent distinguant les états `live`, `historical` et
  `unverified`, avec journal de validation, checkpoints et reprise ;
- sources passives, Certificate Transparency incrémentale, AXFR strict, NSEC,
  graphe DNS, Web/JavaScript, TLS/STARTTLS et mutations contextuelles ;
- détection wildcard hiérarchique, familles de preuves et explication du score
  de confiance ;
- corpus SecLists dérivé, épinglé et compressé d'un million de candidats ;
- sorties texte, JSON, JSONL/stream JSONL et commandes d'import, d'export,
  d'explication et de contrôle des sources/résolveurs ;
- banc concurrentiel, laboratoire DNS, tests de propriétés, cible de fuzzing et
  workflows CI/release.

### Sécurité et fiabilité

- limites prudentes par défaut pour la concurrence, le débit DNS, le nombre de
  domaines actifs et la durée maximale ;
- profil `deep` adaptatif par défaut, avec arrêt des vagues à faible rendement ;
- timeouts absolus et budgets pour AXFR, TLS, NSEC, Web et sources externes ;
- filtrage des destinations Web privées ou locales et validation des
  redirections ;
- permissions privées sous Unix pour la configuration, SQLite, WAL/SHM et les
  sauvegardes de migration ;
- purge des observations faibles correspondant à un wildcard, y compris les
  réponses positives orphelines du cache, sans supprimer les preuves
  indépendantes ;
- conservation locale de l'apprentissage, sans télémétrie ni partage
  automatique de la base.

### Documentation et distribution

- politique de sécurité, guide de contribution, notices tierces et provenance
  vérifiable du corpus ;
- workflow de release configuré pour produire archives Linux/Kali x86-64 et
  ARM64, paquet Debian, SBOM, checksums, signature sans clé et attestations. Ces
  artefacts ne sont considérés publiés qu'après réussite visible du workflow.
