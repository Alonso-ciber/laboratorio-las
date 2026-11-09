# -*- coding: utf-8 -*-
"""
detector.py — Práctica de Seguridad MTTD y MTTR (ESIT)
Partes 3 y 4: Detector de incidentes y cálculo de métricas.

Funcionalidad:
  1. Lee "eventos.log" línea por línea y agrupa los LOGIN_FALLIDO por usuario.
  2. Genera una ALERTA DE SEGURIDAD cuando un usuario acumula >= 3 intentos fallidos.
  3. Simula la respuesta al incidente escribiendo en "respuesta.log"
     con el formato: "YYYY-MM-DD HH:MM:SS, USUARIO_BLOQUEADO, usuario".
  4. Calcula:
       MTTD = detección - primer intento fallido
       MTTR = respuesta   - detección
     usando datetime.strptime y .total_seconds().

Ejecutar:  python detector.py
"""

from datetime import datetime

FORMATO_FECHA = "%Y-%m-%d %H:%M:%S"
UMBRAL_INTENTOS = 3  # Umbral de la guía: 3 o más intentos fallidos


def registrar_respuesta(usuario):
    """Simula la respuesta al incidente: registra el bloqueo del usuario."""
    fecha_respuesta = datetime.now().strftime(FORMATO_FECHA)
    with open("respuesta.log", "a", encoding="utf-8") as archivo:
        archivo.write(f"{fecha_respuesta}, USUARIO_BLOQUEADO, {usuario}\n")
    return fecha_respuesta


# ------------------------------------------------------------------------------
# 1. LECTURA Y AGRUPACIÓN DE INTENTOS FALLIDOS
# ------------------------------------------------------------------------------
intentos = {}  # {usuario: [fecha1, fecha2, fecha3, ...]}

try:
    with open("eventos.log", "r", encoding="utf-8") as archivo:
        for linea in archivo:
            partes = linea.strip().split(",")
            if len(partes) < 3:
                continue  # Línea malformada: se ignora

            fecha = partes[0].strip()
            tipo_evento = partes[1].strip()
            usuario = partes[2].strip()

            if tipo_evento == "LOGIN_FALLIDO":
                intentos.setdefault(usuario, []).append(fecha)
except FileNotFoundError:
    print("El archivo 'eventos.log' todavía no existe.")
    print("Ejecuta la aplicación (python app.py) y genera intentos fallidos.")
    raise SystemExit

if not intentos:
    print("No se encontraron intentos fallidos en 'eventos.log'.")
    raise SystemExit

# ------------------------------------------------------------------------------
# 2. DETECCIÓN DE INCIDENTES, ALERTAS Y MÉTRICAS
# ------------------------------------------------------------------------------
incidentes = []  # [(usuario, mttd, mttr, ...)] para calcular promedios al final

for usuario, registros in intentos.items():
    if len(registros) < UMBRAL_INTENTOS:
        continue  # No alcanza el umbral: no hay incidente

    # Momento de detección = momento del intento que alcanza el umbral
    primer_intento = registros[0]
    momento_deteccion = registros[UMBRAL_INTENTOS - 1]

    print("=" * 50)
    print("ALERTA DE SEGURIDAD")
    print("=" * 50)
    print(f"Usuario:            {usuario}")
    print(f"Intentos fallidos:  {len(registros)}")
    print(f"Primer intento:     {primer_intento}")
    print(f"Detección:          {momento_deteccion}")

    # 3. Respuesta simulada al incidente (bloqueo del usuario)
    fecha_respuesta = registrar_respuesta(usuario)
    print(f"Acción aplicada:    Usuario bloqueado")
    print(f"Respuesta:          {fecha_respuesta}")

    # 4. Cálculo de métricas con datetime.strptime y .total_seconds()
    inicio = datetime.strptime(primer_intento, FORMATO_FECHA)
    deteccion = datetime.strptime(momento_deteccion, FORMATO_FECHA)
    respuesta = datetime.strptime(fecha_respuesta, FORMATO_FECHA)

    mttd = (deteccion - inicio).total_seconds()   # Mean Time to Detect
    mttr = (respuesta - deteccion).total_seconds()  # Mean Time to Respond

    print(f"MTTD:               {mttd:.0f} segundos")
    print(f"MTTR:               {mttr:.0f} segundos")
    print("=" * 50)

    incidentes.append(
        {"usuario": usuario, "intentos": len(registros),
         "primer_intento": primer_intento, "deteccion": momento_deteccion,
         "respuesta": fecha_respuesta, "mttd": mttd, "mttr": mttr}
    )

# ------------------------------------------------------------------------------
# RESUMEN PARA LA TABLA DE PRUEBAS (Parte 4: Pruebas 1, 2 y 3)
# ------------------------------------------------------------------------------
if incidentes:
    print("\nRESUMEN PARA LA TABLA DE PRUEBAS")
    print("-" * 78)
    print(f"{'Prueba':<8}{'Usuario':<16}{'Intentos':<10}{'MTTD (s)':<12}{'MTTR (s)':<10}")
    print("-" * 78)

    for numero, inc in enumerate(incidentes, start=1):
        print(f"{numero:<8}{inc['usuario']:<16}{inc['intentos']:<10}"
              f"{inc['mttd']:<12.0f}{inc['mttr']:<10.0f}")

    promedio_mttd = sum(i["mttd"] for i in incidentes) / len(incidentes)
    promedio_mttr = sum(i["mttr"] for i in incidentes) / len(incidentes)

    print("-" * 78)
    print(f"{'PROMEDIO':<34}{promedio_mttd:<12.2f}{promedio_mttr:<10.2f}")
    print("-" * 78)
    print(f"MTTD promedio: {promedio_mttd:.2f} segundos | "
          f"MTTR promedio: {promedio_mttr:.2f} segundos")
else:
    print("Ningún usuario alcanzó el umbral de 3 intentos fallidos.")
