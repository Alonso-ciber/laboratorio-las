# -*- coding: utf-8 -*-
"""
crearDB.py — Práctica de Seguridad MTTD y MTTR (ESIT)
Parte 1, Paso 4: Creación de la base de datos SQLite.

Ejecutar:  python crearDB.py
Resultado: archivo "usuarios.db" con la tabla "usuarios".
"""

import sqlite3

# Conexión: si el archivo no existe, SQLite lo crea automáticamente
conexion = sqlite3.connect("usuarios.db")
cursor = conexion.cursor()

# Creación de la tabla con los campos exactos de la guía
cursor.execute("""
    CREATE TABLE IF NOT EXISTS usuarios (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        usuario TEXT,
        correo TEXT,
        password TEXT
    );
""")

conexion.commit()
conexion.close()

print("Base de datos 'usuarios.db' y tabla 'usuarios' creadas correctamente.")
