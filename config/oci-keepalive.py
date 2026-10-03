#!/usr/bin/env python3
"""
oci-keepalive.py - Evita que Oracle recupere la instancia por "ociosa"
Proyecto Intermodular ASIR - Diego Perez Fonterosa

Oracle puede recuperar una instancia Always Free si durante 7 dias tiene
a la vez CPU < 20 % (p95), red < 20 % y, en las A1, memoria < 20 %.
Un honeypot cumple las tres. Basta con romper una: este proceso reserva
un porcentaje fijo de la RAM y la mantiene ocupada, sin gastar CPU.

Porcentaje configurable con la variable KEEPALIVE_PERCENT (defecto 25).
"""
import os
import signal
import sys
import time


def meminfo(campo):
    with open("/proc/meminfo", encoding="ascii") as f:
        for linea in f:
            if linea.startswith(campo + ":"):
                return int(linea.split()[1]) * 1024  # kB -> bytes
    raise KeyError(campo)


def main():
    pct = float(os.environ.get("KEEPALIVE_PERCENT", "25"))
    if not 0 < pct <= 50:
        sys.exit("KEEPALIVE_PERCENT debe estar entre 0 y 50")

    total = meminfo("MemTotal")
    tam = int(total * pct / 100)

    # bytearray() pide paginas a cero que el kernel no asigna hasta que se
    # escriben: hay que tocar cada pagina para que cuenten como RAM usada.
    buf = bytearray(tam)
    pagina = os.sysconf("SC_PAGE_SIZE")
    for i in range(0, tam, pagina):
        buf[i] = 1

    print(f"Reservados {tam / 2**20:.0f} MiB ({pct:g} % de {total / 2**30:.1f} GiB)", flush=True)

    signal.signal(signal.SIGTERM, lambda *_: sys.exit(0))
    while True:
        time.sleep(3600)


if __name__ == "__main__":
    main()
