#!/usr/bin/env bash
# =====================================================================
#  01_hardening.sh - Bastionado del servidor (PFC-Cowrie)
#  Proyecto Intermodular ASIR - Diego Perez Fonterosa
#
#  - Actualiza el sistema y activa las actualizaciones automaticas
#  - Mueve el SSH real al puerto 2022, solo con clave y sin root
#  - Firewall con iptables (persistente): denegar todo salvo lo necesario
#  - Crea swap si la maquina tiene menos de 2 GB de RAM
#
#  Uso:  sudo bash 01_hardening.sh   (o como root: bash 01_hardening.sh)
#  Probado para Ubuntu Server 24.04 LTS. Valido para proveedores que
#  entregan un usuario "ubuntu" (Oracle, AWS) o solo root (Hetzner).
# =====================================================================
set -euo pipefail

SSH_PORT=2022
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
DROPIN=/etc/ssh/sshd_config.d/00-pfc-hardening.conf

info() { echo -e "\n\033[1;34m[+]\033[0m $*"; }
warn() { echo -e "\033[1;33m[!]\033[0m $*"; }
die()  { echo -e "\033[1;31m[x]\033[0m $*" >&2; exit 1; }

# --- Comprobaciones previas -------------------------------------------
[[ $EUID -eq 0 ]] || die "Ejecuta el script con sudo (o como root)."
[[ -f "$SCRIPT_DIR/sshd_hardening.conf" ]] || die "Falta sshd_hardening.conf junto al script."

# --- Usuario administrador ---------------------------------------------
# Este script prohibe el acceso SSH como root, asi que antes debe existir
# un usuario administrador con tu clave. Si la maquina solo trae root
# (Hetzner), se crea uno copiando la clave autorizada de root.
if [[ -n "${SUDO_USER:-}" && "${SUDO_USER}" != "root" ]]; then
  ADMIN_USER="$SUDO_USER"
elif id ubuntu &>/dev/null && [[ -s /home/ubuntu/.ssh/authorized_keys ]]; then
  ADMIN_USER=ubuntu
else
  [[ -s /root/.ssh/authorized_keys ]] || die "root no tiene claves en /root/.ssh/authorized_keys."
  read -rp "  Nombre del usuario administrador a crear [diego]: " ADMIN_USER
  ADMIN_USER="${ADMIN_USER:-diego}"
  [[ "$ADMIN_USER" =~ ^[a-z_][a-z0-9_-]*$ ]] || die "Nombre de usuario no valido."
  if ! id "$ADMIN_USER" &>/dev/null; then
    info "Creando el usuario administrador $ADMIN_USER..."
    adduser --disabled-password --gecos "" "$ADMIN_USER"
  fi
  usermod -aG sudo "$ADMIN_USER"
  install -d -m 700 -o "$ADMIN_USER" -g "$ADMIN_USER" "/home/$ADMIN_USER/.ssh"
  install -m 600 -o "$ADMIN_USER" -g "$ADMIN_USER" /root/.ssh/authorized_keys \
    "/home/$ADMIN_USER/.ssh/authorized_keys"
  # Solo se pide contrasena si el usuario aun no tiene una (estado "P"),
  # para poder volver a ejecutar el script sin repetir este paso.
  if [[ "$(passwd -S "$ADMIN_USER" | awk '{print $2}')" != "P" ]]; then
    echo "  Elige la contrasena de $ADMIN_USER. Solo la pedira sudo: el SSH seguira siendo solo con clave."
    passwd "$ADMIN_USER"
  fi
fi
[[ -s "/home/$ADMIN_USER/.ssh/authorized_keys" ]] \
  || die "El usuario $ADMIN_USER no tiene claves en ~/.ssh/authorized_keys: te quedarias fuera."
info "Usuario administrador: $ADMIN_USER"

cat <<EOF

  ANTES DE CONTINUAR, en el firewall de tu proveedor cloud abre la
  entrada TCP $SSH_PORT desde cualquier origen (0.0.0.0/0):
    - Hetzner: Firewalls > (tu firewall) > Reglas de entrada
    - Oracle:  Networking > VCN > Subnet > Security List > Ingress Rule
    - AWS:     EC2 > Security Groups > Inbound rules

  Si el puerto $SSH_PORT no esta abierto ahi, perderas el acceso.
EOF
read -rp "  El puerto $SSH_PORT ya esta abierto en el firewall del proveedor? (si/no): " ok
[[ "$ok" == "si" ]] || die "Abrelo primero y vuelve a ejecutar el script."

# --- 1. Sistema --------------------------------------------------------
info "Actualizando el sistema..."
export DEBIAN_FRONTEND=noninteractive
apt-get update -q
apt-get upgrade -yq
apt-get install -yq iptables-persistent unattended-upgrades
dpkg-reconfigure -f noninteractive unattended-upgrades

# --- 2. Swap (instancias pequenas, p. ej. E2.1.Micro con 1 GB) ---------
mem_mb=$(awk '/MemTotal/ {print int($2/1024)}' /proc/meminfo)
if (( mem_mb < 2048 )) && ! swapon --show | grep -q .; then
  info "RAM de ${mem_mb} MB: creando 2 GB de swap..."
  fallocate -l 2G /swapfile && chmod 600 /swapfile
  mkswap /swapfile && swapon /swapfile
  grep -q '^/swapfile' /etc/fstab || echo '/swapfile none swap sw 0 0' >> /etc/fstab
fi

# --- 3. Firewall (iptables) --------------------------------------------
# Se usa iptables y no UFW: las imagenes Ubuntu de Oracle ya traen reglas
# en /etc/iptables/rules.v4 (incluidas las de los servicios internos de
# OCI en 169.254.0.0/16) y UFW gestionaria las mismas tablas en paralelo.
info "Configurando el firewall..."
if ufw status 2>/dev/null | grep -q "Status: active"; then
  warn "UFW estaba activo: se desactiva para no duplicar reglas."
  ufw disable
fi

ensure() {  # inserta la regla al principio solo si no existe ya
  local chain=$1; shift
  iptables -C "$chain" "$@" 2>/dev/null || iptables -I "$chain" 1 "$@"
}

# Si la cadena INPUT no tiene ya un "denegar todo" (p. ej. Hetzner o AWS),
# se crea la base: trafico establecido, loopback, ICMP, 22 y rechazo final.
if ! iptables -S INPUT | grep -qE -- '-j (REJECT|DROP)$|-j REJECT --reject-with'; then
  iptables -A INPUT -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT
  iptables -A INPUT -i lo -j ACCEPT
  iptables -A INPUT -p icmp -j ACCEPT
  iptables -A INPUT -p tcp --dport 22 -m conntrack --ctstate NEW -j ACCEPT
  iptables -A INPUT -j REJECT --reject-with icmp-host-prohibited
fi
ensure INPUT -p tcp --dport "$SSH_PORT" -m conntrack --ctstate NEW -j ACCEPT
netfilter-persistent save

# --- 4. SSH ------------------------------------------------------------
info "Configurando SSH en el puerto $SSH_PORT..."
# "Port" se acumula entre ficheros: si sshd_config fija el 22, se comenta.
sed -i -E 's/^\s*Port\s+/#&/' /etc/ssh/sshd_config
sed "s/__ADMIN_USER__/$ADMIN_USER/" "$SCRIPT_DIR/sshd_hardening.conf" > "$DROPIN"
chmod 644 "$DROPIN"

# Ubuntu 24.04 arranca sshd por socket y /run/sshd solo existe mientras el
# servicio corre; "sshd -t" falla sin ella aunque la configuracion este bien.
install -d -m 0755 /run/sshd
if ! sshd -t; then
  rm -f "$DROPIN"
  die "La configuracion de sshd no es valida; se deshace el cambio."
fi

# Ubuntu 24.04 arranca SSH por socket: el puerto lo fija ssh.socket.
systemctl daemon-reload
if systemctl is-enabled ssh.socket &>/dev/null; then
  systemctl restart ssh.socket
fi
systemctl restart ssh.service

sleep 2
ss -ltn "sport = :$SSH_PORT" | grep -q LISTEN \
  || die "sshd no escucha en $SSH_PORT. NO cierres esta sesion y revisa: journalctl -u ssh"

info "Hecho. SSH escuchando en el puerto $SSH_PORT."
cat <<EOF

  SIGUIENTE PASO (sin cerrar esta sesion):
    abre OTRA terminal y conecta con
      ssh -p $SSH_PORT -i <tu_clave> $ADMIN_USER@<IP_PUBLICA>
    Si entra, continua con:  sudo bash 02_instalar_cowrie.sh

EOF
