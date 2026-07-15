# Laboratoire DNS contrôlé

`verify.sh` construit un serveur BIND jetable et vérifie les cas réels suivants : wildcard tournant, wildcard multiniveau, détournement de nom absent, CNAME pendant, délégation avec glue, NSEC, NSEC3, réponse UDP tronquée avec reprise TCP observable, AXFR complet et AXFR refusé. Le cas AXFR vide/incomplet est couvert par le test Rust de classification, car un serveur autoritaire conforme encadre même une zone sans hôte par deux SOA.

```bash
tests/dns-lab/verify.sh
```

Le laboratoire écoute seulement sur `127.0.0.1:53535`, ne contacte aucune cible et est détruit automatiquement.
