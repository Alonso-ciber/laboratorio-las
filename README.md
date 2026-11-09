# Práctica de Seguridad: MTTD y MTTR — ESIT

Laboratorio de ciberseguridad: aplicación web Flask con registro/login de usuarios,
detección de intentos de fuerza bruta y cálculo de métricas **MTTD** y **MTTR**.

## Estructura del proyecto

```
laboratorio-las/
├── app.py              # Aplicación principal Flask (seguridad: validación, hash, SQL parametrizado)
├── crearDB.py          # Script que genera la base de datos usuarios.db
├── detector.py         # Detector de incidentes + cálculo de MTTD/MTTR
├── templates/
│   ├── registro.html   # Formulario de registro
│   └── login.html      # Formulario de inicio de sesión
├── usuarios.db         # Base de datos SQLite (generada por crearDB.py)
├── eventos.log         # Log de eventos de seguridad (generado por app.py)
└── respuesta.log       # Log de respuesta a incidentes (generado por detector.py)
```

## Requisitos

- Python 3.x
- Flask (`pip install flask`)

## Ejecución

```bash
# 1. Crear y activar el entorno virtual
python -m venv venv
venv\Scripts\activate        # Windows
source venv/bin/activate     # Linux/Mac

# 2. Instalar dependencias
pip install flask

# 3. Crear la base de datos
python crearDB.py

# 4. Ejecutar la aplicación
python app.py
# Abrir http://127.0.0.1:5000/registro y /login en el navegador

# 5. Ejecutar el detector de incidentes (después de generar intentos fallidos)
python detector.py
```

## Medidas de seguridad implementadas

| Medida | Implementación |
|---|---|
| Validación de usuario | `re.fullmatch(r"[A-Za-z0-9_]{4,20}", usuario)` |
| Validación de correo | Expresión regular estándar de correo |
| Validación de contraseña | Mínimo 8 caracteres |
| Saneamiento de entradas | `.strip()` en usuario y correo |
| Duplicados | Consulta previa `SELECT ... WHERE usuario = ? OR correo = ?` |
| Contraseñas | `generate_password_hash()` / `check_password_hash()` |
| SQL Injection | Consultas parametrizadas (`?`) en todas las consultas |
| Registro de eventos | `eventos.log` → `LOGIN_CORRECTO` / `LOGIN_FALLIDO` |

## Métricas

- **MTTD (Mean Time to Detect):** tiempo entre el primer intento fallido y la detección (3er intento).
- **MTTR (Mean Time to Respond):** tiempo entre la detección y la respuesta (bloqueo registrado en `respuesta.log`).
