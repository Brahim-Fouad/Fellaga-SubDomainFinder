# Politique de sécurité

Fellaga effectue des requêtes DNS, HTTP et TLS actives. Utilisez-le uniquement
sur des domaines pour lesquels vous disposez d'une autorisation explicite.

## Versions prises en charge

Les correctifs de sécurité visent la dernière version publiée dans GitHub
Releases. La branche `main` reçoit les correctifs destinés à la prochaine
version, mais peut changer avant sa publication. Les versions plus anciennes ne
bénéficient pas d'un support garanti.

## Signaler une vulnérabilité

1. Utilisez **Security > Report a vulnerability** dans le dépôt GitHub si le
   formulaire de signalement privé est disponible.
2. S'il ne l'est pas, ouvrez une issue ne contenant que la demande d'un canal
   privé. N'y publiez ni preuve d'exploitation, ni secret, ni donnée de cible.
3. Indiquez dans le rapport privé la version ou le commit, le système, les
   options concernées, l'impact attendu et une reproduction minimale.

Les rapports sont traités au mieux des disponibilités du projet, sans délai de
réponse contractuel. Une correction peut être préparée sous embargo avant la
publication coordonnée d'un avis.

## Données à ne jamais joindre

Ne transmettez pas de clé API, jeton, mot de passe, base SQLite réelle, fichier
de configuration, résultat de scan non expurgé ou nom de cible confidentiel.
Remplacez ces éléments par des valeurs factices et utilisez, si possible, une
zone DNS de laboratoire que vous contrôlez.

## Périmètre de cette politique

Cette politique couvre le code et les artefacts de Fellaga. Elle ne couvre pas
les vulnérabilités découvertes sur les domaines analysés, les indisponibilités
des services tiers ni un scan lancé sans autorisation. Signalez une faille d'un
tiers à son propriétaire selon son propre processus de divulgation.
