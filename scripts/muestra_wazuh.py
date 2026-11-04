#!/usr/bin/env python3
"""
muestra_wazuh.py - Extrae de cowrie.json una muestra acotada para Wazuh.

Wazuh se ahoga con 1,3 millones de eventos en una VM pequena, asi que se
carga un solo dia y solo los tipos de evento relevantes (conexion, login,
comandos y ficheros). Uso:
    python scripts/muestra_wazuh.py logs/real/2026-11-01/cowrie.json salida.json --dia 2026-10-29 --max 30000
"""
import argparse
import json

TIPOS = {
    "cowrie.session.connect", "cowrie.login.failed", "cowrie.login.success",
    "cowrie.command.input", "cowrie.session.file_download",
    "cowrie.session.file_upload", "cowrie.direct-tcpip.request",
}

p = argparse.ArgumentParser()
p.add_argument("entrada")
p.add_argument("salida")
p.add_argument("--dia", required=True, help="AAAA-MM-DD")
p.add_argument("--max", type=int, default=30000)
a = p.parse_args()

n = 0
con = 0
with open(a.entrada, encoding="utf-8", errors="replace") as f, \
        open(a.salida, "w", encoding="utf-8", newline="\n") as o:
    for linea in f:
        try:
            d = json.loads(linea)
        except ValueError:
            continue
        if not d.get("timestamp", "").startswith(a.dia):
            continue
        if d.get("eventid") not in TIPOS:
            continue
        o.write(json.dumps(d, ensure_ascii=False) + "\n")
        n += 1
        if n >= a.max:
            break
print(f"{n} eventos del {a.dia} escritos en {a.salida}")
