# Benchmark reproductible Fellaga

Le banc produit deux campagnes séparées : `no-key` et `equal-keys`. Chaque ligne de `summary.jsonl` contient le domaine, l'outil, le code retour, la durée, la mémoire maximale, les noms bruts, les noms validés par `dnsx`, les requêtes DNS et les erreurs. Si le banc tourne en root avec `tshark`, les requêtes sont comptées sur le réseau; sinon Fellaga expose son compteur interne et les valeurs concurrentes restent `null`. Les sorties originales sont conservées pour audit et le rapport note les versions exactes des exécutables.

Prérequis : `fellaga`, `subfinder`, `amass`, `bbot`, `puredns`, `dnsx`, `jq`, `python3`, `zstd`. Le fichier de domaines doit contenir uniquement des cibles autorisées. Le garde-fou `FELLAGA_BENCH_AUTHORIZED=YES` est obligatoire.

```bash
cp benchmarks/authorized-domains.example.txt benchmarks/authorized-domains.txt
FELLAGA_BENCH_AUTHORIZED=YES benchmarks/run.sh no-key benchmarks/authorized-domains.txt
FELLAGA_BENCH_AUTHORIZED=YES KEYS_MANIFEST=benchmarks/keys-manifest.json \
  benchmarks/run.sh equal-keys benchmarks/authorized-domains.txt
```

Le mode `equal-keys` refuse de démarrer tant que chaque fournisseur du manifeste n'est pas marqué `competitors_configured: true` et que la variable Fellaga correspondante n'est pas définie. Les secrets eux-mêmes ne sont jamais copiés dans les résultats.

Pour les faux positifs, ajoutez un fichier `ground-truth/<domain>.txt` de noms live attendus. `report.py` calcule alors rappel, faux positifs, exclusifs validés et victoires par domaine. Sans vérité terrain, ces métriques restent explicitement `null`.
