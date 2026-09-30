# Devcontainer

L'image est construite **une fois** (réseau nécessaire), puis VS Code l'utilise hors ligne :

```bash
docker build -t secupython-dev .devcontainer
```

À refaire uniquement si le `Dockerfile` change.
