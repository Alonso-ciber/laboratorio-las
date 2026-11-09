# -*- coding: utf-8 -*-
"""
app.py — Práctica de Seguridad MTTD y MTTR (ESIT)
Aplicación web Flask con registro/login de usuarios.

Medidas de seguridad implementadas:
  * Validación de entradas con expresiones regulares (re.fullmatch).
  * Normalización y saneamiento de entradas (.strip()).
  * Prevención de duplicados en el registro.
  * Almacenamiento seguro de contraseñas (hash con werkzeug).
  * Prevención de SQL Injection (consultas parametrizadas).
  * Registro de eventos de seguridad en "eventos.log".

Ejecutar:  python app.py   ->   http://127.0.0.1:5000/registro  y  /login
"""

import re
import sqlite3
from datetime import datetime

from flask import Flask, render_template, request
from werkzeug.security import check_password_hash, generate_password_hash

app = Flask(__name__)


# ------------------------------------------------------------------------------
# VALIDACIONES CON EXPRESIONES REGULARES
# ------------------------------------------------------------------------------
def validar_usuario(usuario):
    """Entre 4 y 20 caracteres: solo letras, números y guion bajo."""
    return re.fullmatch(r"[A-Za-z0-9_]{4,20}", usuario) is not None


def validar_correo(correo):
    """Formato de correo electrónico válido estándar."""
    return re.fullmatch(
        r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}", correo
    ) is not None


def validar_password(password):
    """Mínimo 8 caracteres."""
    return len(password) >= 8


# ------------------------------------------------------------------------------
# REGISTRO DE EVENTOS DE SEGURIDAD (Parte 3)
# Formato exacto: "YYYY-MM-DD HH:MM:SS, TIPO_EVENTO, usuario"
# ------------------------------------------------------------------------------
def registrar_evento(tipo, usuario):
    fecha = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    with open("eventos.log", "a", encoding="utf-8") as archivo:
        archivo.write(f"{fecha}, {tipo}, {usuario}\n")


# ------------------------------------------------------------------------------
# RUTA DE INICIO
# ------------------------------------------------------------------------------
@app.route("/")
def inicio():
    return "Laboratorio de Seguridad MTTD y MTTR — ESIT"


# ------------------------------------------------------------------------------
# REGISTRO DE USUARIOS (Parte 1, Paso 5)
# ------------------------------------------------------------------------------
@app.route("/registro", methods=["GET", "POST"])
def registro():
    if request.method == "POST":
        # Normalización y saneamiento de entradas: .strip()
        usuario = request.form.get("usuario", "").strip()
        correo = request.form.get("correo", "").strip()
        password = request.form.get("password", "")

        # Validaciones con expresiones regulares
        if not validar_usuario(usuario):
            return ("Usuario inválido: debe tener entre 4 y 20 caracteres "
                    "(solo letras, números y guion bajo).")

        if not validar_correo(correo):
            return "Correo electrónico inválido."

        if not validar_password(password):
            return "La contraseña debe tener al menos 8 caracteres."

        conexion = sqlite3.connect("usuarios.db")
        cursor = conexion.cursor()

        # Prevención de duplicados: consultar antes de insertar
        cursor.execute(
            "SELECT id FROM usuarios WHERE usuario = ? OR correo = ?",
            (usuario, correo),
        )
        if cursor.fetchone():
            conexion.close()
            registrar_evento("REGISTRO_DUPLICADO", usuario)
            return "El usuario o el correo ya están registrados."

        # Almacenamiento seguro: hash de la contraseña (nunca texto plano)
        password_hash = generate_password_hash(password)

        # Prevención de SQL Injection: consulta parametrizada con ?
        cursor.execute(
            "INSERT INTO usuarios (usuario, correo, password) VALUES (?, ?, ?)",
            (usuario, correo, password_hash),
        )
        conexion.commit()
        conexion.close()

        return "Usuario registrado correctamente."

    return render_template("registro.html")


# ------------------------------------------------------------------------------
# INICIO DE SESIÓN (Parte 1, Paso 7)
# ------------------------------------------------------------------------------
@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        usuario = request.form.get("usuario", "").strip()
        password = request.form.get("password", "")

        # Consulta parametrizada: prevención de SQL Injection
        conexion = sqlite3.connect("usuarios.db")
        cursor = conexion.cursor()
        cursor.execute(
            "SELECT id, usuario, correo, password FROM usuarios WHERE usuario = ?",
            (usuario,),
        )
        resultado = cursor.fetchone()
        conexion.close()

        if resultado and check_password_hash(resultado[3], password):
            registrar_evento("LOGIN_CORRECTO", usuario)
            return "Inicio de sesión correcto."

        # Intento fallido: se registra el evento para el detector de incidentes
        registrar_evento("LOGIN_FALLIDO", usuario)
        return "Credenciales incorrectas."

    return render_template("login.html")


if __name__ == "__main__":
    app.run(debug=True)
