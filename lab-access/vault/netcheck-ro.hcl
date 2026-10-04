# Politique du rôle AppRole « netcheck-ro » (phase C3) : LECTURE SEULE sur le seul secret des identifiants du lab.
# Rien d'autre : pas de liste, pas d'écriture, pas de suppression, pas d'autre chemin, pas de sys/.
# (L'ouverture de session AppRole, POST auth/approle/login, n'exige aucune politique : elle précède le jeton.)
path "secret/data/netcheck/lab" {
  capabilities = ["read"]
}
