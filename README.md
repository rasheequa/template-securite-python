# Template code Sécurité Python

## Description

Projet contenant les modèles de TP pour le cours de sécurité Python de 4e année de l'ESGI.

## Installation

Faire un fork puis un clone du projet :

```bash
git clone git@github.com:<VotreNom>/template-securite-python.git
```

Installer les dépendances :

```bash
cd template-securite-python
poetry lock
poetry install
```

## Utilisation

Lancer le projet :

```bash
poetry run tp1
```

## Tests

# Tous les tests du TP1
poetry run pytest tests/tp1

# Plus détaillé
poetry run pytest tests/tp1 -v

# Un seul fichier
poetry run pytest tests/tp1/utils/test_capture.py -v

# Un seul test précis
poetry run pytest tests/tp1/utils/test_capture.py::test_get_all_protocols -v
