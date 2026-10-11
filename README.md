# Equipo Ramos

App web instalable (iPhone y Android) para que el equipo sepa a qué teatro ir, a qué hora y cómo llegar.

- La agenda está en `agenda.enc.json`, **cifrada** (PBKDF2-SHA256 + AES-GCM). Sin el código del equipo no se puede leer, aunque el repositorio sea público.
- Pablo edita la agenda desde la misma app ("Soy Pablo: armar la agenda") con una clave de GitHub de permisos mínimos (solo *Contents: read and write* en este repositorio).
- `tools/cifrar.mjs` cifra una agenda desde la terminal: `CODIGO="..." node tools/cifrar.mjs agenda.json > agenda.enc.json`.
- Se publica con GitHub Pages desde la rama `main`, carpeta raíz.
