### <u>Question1 </u>: Quelle est le nom de l'algorithme de chiffrement ? est-il robuste et pourquoi ? 

--> L'algorithme de chiffrement utilisé ici est celui du chiffrement par ou exclusif (XOR). Il est mathématiquement parfait, cependant ce qui sera difficile ici c'est de garantir le caractère aléatoire des clefs. La clef doit être aussi grande que le message orignal pour que le chiffrement soit robuste.

### <u>Question2 </u>: Pourquoi ne pas hacher le sel et la clef directement? Et avec un hmac?

--> On ne hache pas directement le sel et la clef ensemble car cela rendrai la clef vulnérable à des attaques de types brut-force. On veut que nos fonctions de hachages soient le plus rapide possible pour éviter cela.

En utilisant un HMAC, on peut combiner les deux, mais de manière sécurisée. On utilise PBKDF2 pour cela, il améliore la sécurité en ajoutant un sel et un grand nombre d'itérations.



### <u>Question3 </u>: Pourquoi il est préférable de vérifier qu'un fichier token.bin n'est pas déjà présent ?

--> Tout d'abord, on risque de perdre des données qui seraient nécessaire pour déchiffrer, donc il faut bien vérifier. On économise des ressources si on ne renvoie pas un fichier token au CNC.


### <u>Question4 </u>: Comment vérifier que la clef la bonne ?

--> Pour vérifier que la clef est bonne, on peut vérifier que la clef dérivée avec le sel correspond au token.