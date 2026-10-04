#!/usr/bin/env python3
"""
cowrie_analyzer.py — Análisis de logs JSON de Cowrie
Proyecto Intermodular ASIR · Diego Pérez Fonterosa

Procesa los ficheros cowrie.json y genera:
  1. Ranking de IPs atacantes con geolocalización
  2. Credenciales más probadas (usuario y contraseña)
  3. Comandos más ejecutados tras el acceso
  4. Ficheros/malware descargados
  5. Clasificación de la actividad en MITRE ATT&CK (mitre_mapping.py)
  6. Resumen general de la actividad
  7. Gráficas en PNG (matplotlib) y tabla MITRE en CSV

Uso:
  python3 cowrie_analyzer.py cowrie.json
  python3 cowrie_analyzer.py /ruta/a/logs/cowrie.json.* --output resultados/
"""

import argparse
import csv
import glob
import json
import os
import re
import sys
from collections import Counter
from datetime import datetime

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from mitre_mapping import mapear  # noqa: E402

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
import matplotlib.dates as mdates


# ─── Colores para las gráficas ────────────────────────────────────────
COLOR_PRIMARY = "#2E3B4E"
COLOR_BARS = "#3B7DD8"
COLOR_ACCENT = "#E74C3C"
COLOR_BG = "#FAFAFA"
COLORS_PALETTE = [
    "#3B7DD8", "#E74C3C", "#2ECC71", "#F39C12", "#9B59B6",
    "#1ABC9C", "#E67E22", "#34495E", "#16A085", "#C0392B",
]


# ─── Lectura de logs ──────────────────────────────────────────────────
def load_logs(paths):
    """Lee uno o varios ficheros de log JSON (un evento por línea)."""
    events = []
    files_read = 0
    for pattern in paths:
        for filepath in sorted(glob.glob(pattern)):
            files_read += 1
            with open(filepath, "r", encoding="utf-8", errors="replace") as f:
                for line_num, line in enumerate(f, 1):
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        events.append(json.loads(line))
                    except json.JSONDecodeError:
                        print(f"  [aviso] Línea {line_num} de {filepath} no es JSON válido, saltando.")
    print(f"Ficheros leídos: {files_read}")
    print(f"Eventos cargados: {len(events)}")
    return events


# ─── Filtrado por tipo de evento ──────────────────────────────────────
def filter_events(events, eventid):
    return [e for e in events if e.get("eventid") == eventid]


# ─── Análisis ─────────────────────────────────────────────────────────
def analyze_connections(events):
    """Sesiones y IPs únicas."""
    connects = filter_events(events, "cowrie.session.connect")
    ips = Counter(e["src_ip"] for e in connects)
    sessions = set(e.get("session") for e in connects)
    return ips, len(sessions)


def analyze_logins(events):
    """Intentos de login: exitosos y fallidos, credenciales usadas."""
    failed = filter_events(events, "cowrie.login.failed")
    success = filter_events(events, "cowrie.login.success")

    usernames = Counter()
    passwords = Counter()
    credentials = Counter()

    for e in failed + success:
        u = e.get("username", "")
        p = e.get("password", "")
        usernames[u] += 1
        passwords[p] += 1
        credentials[(u, p)] += 1

    return {
        "failed": len(failed),
        "success": len(success),
        "usernames": usernames,
        "passwords": passwords,
        "credentials": credentials,
    }


def analyze_commands(events):
    """Comandos ejecutados tras el acceso."""
    cmds = filter_events(events, "cowrie.command.input")
    return Counter(e.get("input", "") for e in cmds)


def analyze_downloads(events):
    """Ficheros que los atacantes intentaron descargar."""
    downloads = filter_events(events, "cowrie.session.file_download")
    urls = Counter(e.get("url", "") for e in downloads)
    shasums = {}
    for e in downloads:
        url = e.get("url", "")
        sha = e.get("shasum", "N/A")
        if url and url not in shasums:
            shasums[url] = sha
    return urls, shasums


URL_RE = re.compile(r"(?:https?|ftp|tftp)://[^\s'\";|&)<>`]+", re.IGNORECASE)


def analyze_command_urls(events):
    """URLs que aparecen en los comandos (wget, curl, tftp...).

    Cowrie solo genera cowrie.session.file_download si la descarga
    termina bien. Muchos servidores de malware ya están caídos cuando el
    bot ejecuta el comando, así que estas URLs se extraen también de los
    comandos: son indicadores de compromiso (IOC) aunque no haya fichero.
    """
    urls = Counter()
    for e in filter_events(events, "cowrie.command.input"):
        for url in URL_RE.findall(e.get("input", "")):
            urls[url] += 1
    return urls


def analyze_timeline(events):
    """Actividad por día (conexiones)."""
    connects = filter_events(events, "cowrie.session.connect")
    daily = Counter()
    for e in connects:
        ts = e.get("timestamp", "")
        try:
            day = ts[:10]  # YYYY-MM-DD
            daily[day] += 1
        except Exception:
            pass
    return dict(sorted(daily.items()))


# ─── Geolocalización ─────────────────────────────────────────────────
def geolocate_ips(ip_counter, top_n=20):
    """
    Geolocaliza las top N IPs usando ip-api.com (batch, gratis, sin clave).
    Máximo 100 IPs por petición, 45 peticiones por minuto.
    """
    try:
        import urllib.request
    except ImportError:
        print("  [aviso] urllib no disponible, saltando geolocalización.")
        return {}

    top_ips = [ip for ip, _ in ip_counter.most_common(top_n)]
    # ip-api.com acepta batch POST con hasta 100 IPs
    url = "http://ip-api.com/batch?fields=query,country,countryCode,city,isp,org,as"
    payload = json.dumps(top_ips).encode("utf-8")

    try:
        req = urllib.request.Request(
            url, data=payload,
            headers={"Content-Type": "application/json"},
            method="POST"
        )
        with urllib.request.urlopen(req, timeout=15) as resp:
            results = json.loads(resp.read().decode("utf-8"))
    except Exception as ex:
        print(f"  [aviso] Error en geolocalización: {ex}")
        print("  Puedes reintentar más tarde o usar GeoLite2 offline.")
        return {}

    geo = {}
    for r in results:
        ip = r.get("query", "")
        geo[ip] = {
            "country": r.get("country", "N/A"),
            "country_code": r.get("countryCode", "N/A"),
            "city": r.get("city", "N/A"),
            "isp": r.get("isp", "N/A"),
            "org": r.get("org", "N/A"),
            "as": r.get("as", "N/A"),
        }
    return geo


# ─── Generación de gráficas ──────────────────────────────────────────
def plot_top_bar(counter, title, xlabel, filename, top_n=15, horizontal=True):
    """Gráfica de barras para un ranking."""
    items = counter.most_common(top_n)
    if not items:
        return

    labels = [str(item[0]) for item in items]
    values = [item[1] for item in items]

    fig, ax = plt.subplots(figsize=(10, max(4, len(items) * 0.4 + 1)))
    fig.patch.set_facecolor(COLOR_BG)
    ax.set_facecolor(COLOR_BG)

    if horizontal:
        labels.reverse()
        values.reverse()
        bars = ax.barh(labels, values, color=COLOR_BARS, edgecolor="white", linewidth=0.5)
        ax.set_xlabel(xlabel, fontsize=10, color=COLOR_PRIMARY)
        # Valor al lado de cada barra
        for bar, val in zip(bars, values):
            ax.text(bar.get_width() + max(values) * 0.01, bar.get_y() + bar.get_height() / 2,
                    str(val), va="center", fontsize=9, color=COLOR_PRIMARY)
    else:
        bars = ax.bar(labels, values, color=COLOR_BARS, edgecolor="white", linewidth=0.5)
        ax.set_ylabel(xlabel, fontsize=10, color=COLOR_PRIMARY)
        plt.xticks(rotation=45, ha="right")

    ax.set_title(title, fontsize=13, fontweight="bold", color=COLOR_PRIMARY, pad=12)
    ax.spines["top"].set_visible(False)
    ax.spines["right"].set_visible(False)
    ax.spines["left"].set_color("#CCCCCC")
    ax.spines["bottom"].set_color("#CCCCCC")
    ax.tick_params(colors=COLOR_PRIMARY, labelsize=9)

    plt.tight_layout()
    plt.savefig(filename, dpi=150, bbox_inches="tight")
    plt.close()
    print(f"  Gráfica guardada: {filename}")


def plot_timeline(daily, filename):
    """Gráfica de actividad diaria."""
    if not daily:
        return

    dates = [datetime.strptime(d, "%Y-%m-%d") for d in daily.keys()]
    values = list(daily.values())

    fig, ax = plt.subplots(figsize=(12, 4))
    fig.patch.set_facecolor(COLOR_BG)
    ax.set_facecolor(COLOR_BG)

    ax.bar(dates, values, color=COLOR_BARS, edgecolor="white", linewidth=0.5, width=0.8)
    ax.plot(dates, values, color=COLOR_ACCENT, linewidth=1.5, marker="o", markersize=4)

    ax.set_title("Conexiones por día", fontsize=13, fontweight="bold", color=COLOR_PRIMARY, pad=12)
    ax.set_ylabel("Conexiones", fontsize=10, color=COLOR_PRIMARY)
    ax.xaxis.set_major_formatter(mdates.DateFormatter("%d %b"))
    ax.xaxis.set_major_locator(mdates.DayLocator(interval=2))
    plt.xticks(rotation=45, ha="right", fontsize=9)
    ax.spines["top"].set_visible(False)
    ax.spines["right"].set_visible(False)
    ax.spines["left"].set_color("#CCCCCC")
    ax.spines["bottom"].set_color("#CCCCCC")
    ax.tick_params(colors=COLOR_PRIMARY)

    plt.tight_layout()
    plt.savefig(filename, dpi=150, bbox_inches="tight")
    plt.close()
    print(f"  Gráfica guardada: {filename}")


def plot_geo_pie(geo_data, ip_counter, filename):
    """Gráfica de tarta con países de origen."""
    if not geo_data:
        return

    country_counts = Counter()
    for ip, count in ip_counter.items():
        if ip in geo_data:
            country = geo_data[ip]["country"]
            country_counts[country] += count

    top_countries = country_counts.most_common(8)
    if not top_countries:
        return

    labels = [c[0] for c in top_countries]
    sizes = [c[1] for c in top_countries]
    others = sum(country_counts.values()) - sum(sizes)
    if others > 0:
        labels.append("Otros")
        sizes.append(others)

    fig, ax = plt.subplots(figsize=(8, 6))
    fig.patch.set_facecolor(COLOR_BG)
    colors = COLORS_PALETTE[:len(labels)]

    wedges, texts, autotexts = ax.pie(
        sizes, labels=labels, autopct="%1.1f%%",
        colors=colors, startangle=140,
        pctdistance=0.85, textprops={"fontsize": 9, "color": COLOR_PRIMARY}
    )
    for t in autotexts:
        t.set_fontsize(8)
        t.set_color("white")
        t.set_fontweight("bold")

    ax.set_title("Origen de los ataques por país",
                 fontsize=13, fontweight="bold", color=COLOR_PRIMARY, pad=12)
    plt.tight_layout()
    plt.savefig(filename, dpi=150, bbox_inches="tight")
    plt.close()
    print(f"  Gráfica guardada: {filename}")


# ─── Informe en texto ─────────────────────────────────────────────────
def write_report(output_dir, ip_counter, num_sessions, login_data,
                 cmd_counter, download_urls, download_shasums,
                 daily, geo_data, command_urls=None, mitre=None, sin_clasificar=None):
    """Genera un resumen en texto plano."""
    path = os.path.join(output_dir, "informe_resumen.txt")
    with open(path, "w", encoding="utf-8") as f:
        f.write("=" * 70 + "\n")
        f.write("  INFORME DE ANÁLISIS — HONEYPOT SSH COWRIE\n")
        f.write("  Proyecto Intermodular ASIR · Diego Pérez Fonterosa\n")
        f.write("=" * 70 + "\n\n")

        # Resumen general
        total_login = login_data["failed"] + login_data["success"]
        f.write("─── RESUMEN GENERAL ───\n\n")
        f.write(f"  Sesiones totales:          {num_sessions}\n")
        f.write(f"  IPs únicas:                {len(ip_counter)}\n")
        f.write(f"  Intentos de login:         {total_login}\n")
        f.write(f"    - Fallidos:              {login_data['failed']}\n")
        f.write(f"    - Exitosos:              {login_data['success']}\n")
        f.write(f"  Comandos ejecutados:       {sum(cmd_counter.values())}\n")
        f.write(f"  Descargas de malware:      {sum(download_urls.values())}\n")
        if daily:
            f.write(f"  Periodo:                   {min(daily.keys())} a {max(daily.keys())}\n")
            f.write(f"  Media diaria conexiones:   {sum(daily.values()) / len(daily):.1f}\n")
        f.write("\n")

        # Top IPs
        f.write("─── TOP 15 IPs ATACANTES ───\n\n")
        f.write(f"  {'IP':<20} {'Intentos':>10}  {'País':<20} {'ISP'}\n")
        f.write(f"  {'─'*20} {'─'*10}  {'─'*20} {'─'*30}\n")
        for ip, count in ip_counter.most_common(15):
            geo = geo_data.get(ip, {})
            country = geo.get("country", "N/A")
            isp = geo.get("isp", "N/A")
            f.write(f"  {ip:<20} {count:>10}  {country:<20} {isp}\n")
        f.write("\n")

        # Credenciales
        f.write("─── TOP 10 USUARIOS ───\n\n")
        for user, count in login_data["usernames"].most_common(10):
            f.write(f"  {user:<25} {count:>6} intentos\n")
        f.write("\n")

        f.write("─── TOP 10 CONTRASEÑAS ───\n\n")
        for pwd, count in login_data["passwords"].most_common(10):
            f.write(f"  {pwd:<25} {count:>6} intentos\n")
        f.write("\n")

        f.write("─── TOP 10 COMBINACIONES USUARIO:CONTRASEÑA ───\n\n")
        for (user, pwd), count in login_data["credentials"].most_common(10):
            f.write(f"  {user}:{pwd:<30} {count:>6} intentos\n")
        f.write("\n")

        # Comandos
        f.write("─── TOP 15 COMANDOS EJECUTADOS ───\n\n")
        for cmd, count in cmd_counter.most_common(15):
            f.write(f"  {count:>6}x  {cmd}\n")
        f.write("\n")

        # Descargas
        if download_urls:
            f.write("─── DESCARGAS DE MALWARE ───\n\n")
            for url, count in download_urls.most_common():
                sha = download_shasums.get(url, "N/A")
                f.write(f"  {count:>4}x  {url}\n")
                f.write(f"        SHA256: {sha}\n")
            f.write("\n")

        # URLs en comandos (IOC aunque la descarga fallara)
        if command_urls:
            f.write("─── URLs EN COMANDOS (IOC: intentos de descarga) ───\n\n")
            for url, count in command_urls.most_common():
                f.write(f"  {count:>4}x  {url}\n")
            f.write("\n")

        # MITRE ATT&CK
        if mitre:
            f.write("─── MAPEO MITRE ATT&CK ───\n\n")
            tactica = None
            for t in mitre:
                if t["tactica"] != tactica:
                    tactica = t["tactica"]
                    f.write(f"  [{tactica}]\n")
                f.write(f"    {t['id']:<10} {t['nombre']}\n")
                f.write(f"               {t['sesiones']} sesiones · {t['ejecuciones']} eventos · "
                        f"{t['ips']} IPs\n")
                for ej, n in t["ejemplos"][:2]:
                    f.write(f"               ej.: {ej[:70]}  ({n}x)\n")
                f.write(f"               Recomendación: {t['recomendacion']}\n")
            f.write("\n")
        if sin_clasificar:
            f.write("─── COMANDOS SIN TÉCNICA ASIGNADA (revisión manual) ───\n\n")
            for cmd, n in sin_clasificar.most_common(15):
                f.write(f"  {n:>6}x  {cmd}\n")
            f.write("\n")

        f.write("=" * 70 + "\n")
        f.write("Generado por cowrie_analyzer.py\n")

    print(f"  Informe guardado: {path}")


def write_mitre_csv(mitre, path):
    """Tabla MITRE en CSV (UTF-8 con BOM para que Excel respete las tildes)."""
    with open(path, "w", newline="", encoding="utf-8-sig") as f:
        w = csv.writer(f, delimiter=";")
        w.writerow(["Táctica", "ID", "Técnica", "Sesiones", "Eventos", "IPs",
                    "Ejemplo", "Recomendación"])
        for t in mitre:
            ejemplo = t["ejemplos"][0][0] if t["ejemplos"] else ""
            w.writerow([t["tactica"], t["id"], t["nombre"], t["sesiones"], t["ejecuciones"],
                        t["ips"], ejemplo, t["recomendacion"]])
    print(f"  Tabla MITRE guardada: {path}")


# ─── Main ─────────────────────────────────────────────────────────────
def main():
    parser = argparse.ArgumentParser(
        description="Análisis de logs JSON de Cowrie (honeypot SSH)"
    )
    parser.add_argument(
        "logs", nargs="+",
        help="Fichero(s) de log de Cowrie (cowrie.json, cowrie.json.*, etc.)"
    )
    parser.add_argument(
        "--output", "-o", default="output",
        help="Directorio de salida para gráficas e informe (por defecto: output/)"
    )
    parser.add_argument(
        "--no-geo", action="store_true",
        help="Omitir geolocalización (sin acceso a Internet)"
    )
    parser.add_argument(
        "--top", type=int, default=15,
        help="Número de elementos en los rankings (por defecto: 15)"
    )
    parser.add_argument(
        "--exclude-ip", action="append", default=[], metavar="IP",
        help="IP a excluir del análisis (pruebas propias); se puede repetir. "
             "127.0.0.1 se excluye siempre"
    )
    args = parser.parse_args()

    os.makedirs(args.output, exist_ok=True)

    print("\n╔══════════════════════════════════════════╗")
    print("║   Cowrie Analyzer · Honeypot SSH          ║")
    print("║   Diego Pérez Fonterosa · ASIR 2025-2026  ║")
    print("╚══════════════════════════════════════════╝\n")

    # 1. Cargar logs
    print("[1/6] Cargando logs...")
    events = load_logs(args.logs)
    if not events:
        print("ERROR: No se encontraron eventos. Comprueba la ruta.")
        sys.exit(1)

    # Fuera las sesiones de prueba propias (localhost y las IPs indicadas)
    excluidas = {"127.0.0.1", "::1", *args.exclude_ip}
    antes = len(events)
    events = [e for e in events if e.get("src_ip") not in excluidas]
    if antes != len(events):
        print(f"  Excluidos {antes - len(events)} eventos de pruebas propias "
              f"({', '.join(sorted(excluidas))})")

    # 2. Análisis
    print("\n[2/6] Analizando conexiones e IPs...")
    ip_counter, num_sessions = analyze_connections(events)
    print(f"  {num_sessions} sesiones, {len(ip_counter)} IPs únicas")

    print("\n[3/6] Analizando intentos de login...")
    login_data = analyze_logins(events)
    total = login_data["failed"] + login_data["success"]
    rate = (login_data["success"] / total * 100) if total else 0
    print(f"  {total} intentos ({login_data['success']} exitosos, {rate:.1f}%)")

    print("\n[4/6] Analizando comandos y descargas...")
    cmd_counter = analyze_commands(events)
    download_urls, download_shasums = analyze_downloads(events)
    command_urls = analyze_command_urls(events)
    print(f"  {sum(cmd_counter.values())} comandos, {sum(download_urls.values())} descargas, "
          f"{len(command_urls)} URLs distintas en comandos")

    mitre, sin_clasificar = mapear(events)
    tacticas = sorted({t["tactica"] for t in mitre})
    print(f"  MITRE ATT&CK: {len(mitre)} técnicas en {len(tacticas)} tácticas; "
          f"{sum(sin_clasificar.values())} comandos sin técnica propia")

    daily = analyze_timeline(events)

    # 3. Geolocalización
    geo_data = {}
    if not args.no_geo:
        print("\n[5/6] Geolocalizando IPs (ip-api.com)...")
        geo_data = geolocate_ips(ip_counter, top_n=20)
        if geo_data:
            print(f"  {len(geo_data)} IPs geolocalizadas")
    else:
        print("\n[5/6] Geolocalización omitida (--no-geo)")

    # 4. Gráficas
    print("\n[6/6] Generando gráficas...")
    plot_top_bar(
        ip_counter, "Top IPs atacantes", "Conexiones",
        os.path.join(args.output, "top_ips.png"), top_n=args.top
    )
    plot_top_bar(
        login_data["usernames"], "Usuarios más probados", "Intentos",
        os.path.join(args.output, "top_usuarios.png"), top_n=args.top
    )
    plot_top_bar(
        login_data["passwords"], "Contraseñas más probadas", "Intentos",
        os.path.join(args.output, "top_passwords.png"), top_n=args.top
    )
    plot_top_bar(
        cmd_counter, "Comandos más ejecutados", "Ejecuciones",
        os.path.join(args.output, "top_comandos.png"), top_n=args.top
    )
    plot_timeline(daily, os.path.join(args.output, "timeline.png"))
    if mitre:
        sesiones_por_tecnica = Counter({f"{t['id']}  {t['nombre']}": t["sesiones"] for t in mitre})
        plot_top_bar(
            sesiones_por_tecnica, "Técnicas MITRE ATT&CK observadas", "Sesiones",
            os.path.join(args.output, "mitre_tecnicas.png"), top_n=len(mitre)
        )
        write_mitre_csv(mitre, os.path.join(args.output, "mitre_mapping.csv"))

    if geo_data:
        plot_geo_pie(geo_data, ip_counter, os.path.join(args.output, "paises_origen.png"))

    # 5. Informe
    print("\nGenerando informe de resumen...")
    write_report(
        args.output, ip_counter, num_sessions, login_data,
        cmd_counter, download_urls, download_shasums,
        daily, geo_data, command_urls, mitre, sin_clasificar
    )

    print(f"\n✓ Análisis completo. Resultados en: {args.output}/\n")


if __name__ == "__main__":
    main()
