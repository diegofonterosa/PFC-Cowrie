#!/usr/bin/env bash
# =====================================================================
#  02_instalar_cowrie.sh - Instalacion del honeypot (PFC-Cowrie)
#  Proyecto Intermodular ASIR - Diego Perez Fonterosa
#
#  - Crea el usuario sin privilegios "cowrie"
#  - Instala Cowrie 3.1.0 en un entorno virtual de Python
#  - Aplica cowrie.cfg y userdb.txt del proyecto
#  - Lo deja como servicio de systemd escuchando en el puerto 2222
#  - En instancias A1, activa oci-keepalive (reserva de memoria para que
#    Oracle no recupere la instancia por considerarla ociosa)
#
#  Uso:  sudo bash 02_instalar_cowrie.sh   (despues de 01_hardening.sh)
# =====================================================================
set -euo pipefail

COWRIE_VERSION=3.1.0
HP_DIR=/home/cowrie/honeypot
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"

info() { echo -e "\n\033[1;34m[+]\033[0m $*"; }
die()  { echo -e "\033[1;31m[x]\033[0m $*" >&2; exit 1; }

[[ $EUID -eq 0 ]] || die "Ejecuta el script con sudo."
for f in cowrie.cfg userdb.txt cowrie.service; do
  [[ -f "$SCRIPT_DIR/$f" ]] || die "Falta $f junto al script."
done

# userdb.txt con un solo caracter no ASCII hace que Cowrie rechace todos
# los logins sin avisar (comprobado en pruebas): se valida antes.
if LC_ALL=C grep -qP '[^\x00-\x7F]' "$SCRIPT_DIR/userdb.txt"; then
  die "userdb.txt contiene caracteres no ASCII (tildes, enies...). Quitalos."
fi

info "Instalando dependencias..."
export DEBIAN_FRONTEND=noninteractive
apt-get install -yq python3-venv python3-pip python3-dev libssl-dev libffi-dev build-essential

info "Creando el usuario cowrie..."
id cowrie &>/dev/null || adduser --disabled-password --gecos "" cowrie

info "Instalando Cowrie $COWRIE_VERSION..."
sudo -u cowrie -H bash -s <<EOF
set -euo pipefail
mkdir -p "$HP_DIR" && cd "$HP_DIR"
[[ -d cowrie-env ]] || python3 -m venv cowrie-env
source cowrie-env/bin/activate
python -m pip install -q --upgrade pip
python -m pip install -q "cowrie==$COWRIE_VERSION"
[[ -f etc/cowrie.cfg ]] || cowrie init
# Cache de plugins de Twisted: bajo systemd el venv es de solo lectura y,
# sin generarla aqui, twistd avisaria en cada arranque de que no puede escribirla.
python -c "from twisted.plugin import IPlugin, getPlugins; list(getPlugins(IPlugin))"
EOF

info "Aplicando la configuracion del proyecto..."
install -o cowrie -g cowrie -m 640 "$SCRIPT_DIR/cowrie.cfg" "$HP_DIR/etc/cowrie.cfg"
install -o cowrie -g cowrie -m 640 "$SCRIPT_DIR/userdb.txt" "$HP_DIR/etc/userdb.txt"

info "Creando el servicio de systemd..."
install -m 644 "$SCRIPT_DIR/cowrie.service" /etc/systemd/system/cowrie.service
systemctl daemon-reload
systemctl enable --now cowrie.service

sleep 8
systemctl is-active --quiet cowrie || die "Cowrie no arranca. Revisa: journalctl -u cowrie -n 50"
ss -ltn "sport = :2222" | grep -q LISTEN || die "Cowrie no escucha en 2222. Revisa: journalctl -u cowrie"

info "Cowrie instalado y escuchando en el puerto 2222."

# --- Reserva de memoria (solo instancias A1 de Oracle) ------------------
# Oracle recupera instancias Always Free con CPU, red y memoria (en A1)
# por debajo del 20 % durante 7 dias. Un honeypot cumple las tres; con
# mantener la memoria por encima del 20 % deja de considerarse ociosa.
mem_mb=$(awk '/MemTotal/ {print int($2/1024)}' /proc/meminfo)
es_oci=$(cat /sys/class/dmi/id/chassis_asset_tag 2>/dev/null || true)
if [[ "$es_oci" == "OracleCloud.com" && "$(uname -m)" == "aarch64" ]] && (( mem_mb >= 2048 )); then
  [[ -f "$SCRIPT_DIR/oci-keepalive.py" && -f "$SCRIPT_DIR/oci-keepalive.service" ]] \
    || die "Faltan oci-keepalive.py u oci-keepalive.service junto al script."
  info "Instancia A1 con ${mem_mb} MB: activando la reserva de memoria (25 %)..."
  install -D -m 644 "$SCRIPT_DIR/oci-keepalive.py" /usr/local/lib/pfc-cowrie/oci-keepalive.py
  install -m 644 "$SCRIPT_DIR/oci-keepalive.service" /etc/systemd/system/oci-keepalive.service
  systemctl daemon-reload
  systemctl enable --now oci-keepalive.service
  sleep 5
  systemctl is-active --quiet oci-keepalive || die "oci-keepalive no arranca: journalctl -u oci-keepalive"
  free -h | awk 'NR<=2'
else
  info "No es una instancia A1 de Oracle: la reserva de memoria no hace falta."
fi
cat <<EOF

  PRUEBA (desde tu equipo o Kali, todavia por el puerto 2222):
    1. En el firewall del proveedor abre TEMPORALMENTE el 2222/TCP
    2. ssh -p 2222 root@<IP_PUBLICA>     (password "root"   -> rechazada)
       ssh -p 2222 root@<IP_PUBLICA>     (password "prueba" -> entra)
    3. Ejecuta "uname -a" y sal. En el servidor:
       sudo tail -n 5 $HP_DIR/var/log/cowrie/cowrie.json
    4. Cierra el 2222 en el firewall del proveedor y continua con:
       sudo bash 03_redireccion_22.sh

EOF
