# Fixtures contractuelles

Ces réponses sont volontairement minimales, sans secret ni donnée personnelle. Les tests vérifient le schéma, la pagination et le filtrage strict du périmètre. Les scénarios HTTP génériques `429`, `Retry-After`, corps partiel, erreur structurée et taille excessive sont couverts dans `passive.rs`; chaque nouveau connecteur doit ajouter ici une page normale, une page terminale et une réponse de schéma dégradé avant activation par défaut.
