#!/usr/bin/env bash
# =====================================================================
#  03_redireccion_22.sh - Exponer el honeypot en el puerto 22
#  Proyecto Intermodular ASIR - Diego Perez Fonterosa
#
#  Redirige (NAT) las conexiones entrantes al 22 hacia el 2222 de
#  Cowrie. Es el ultimo paso: a partir de aqui el honeypot es publico.
#
#  Uso:  sudo bash 03_redireccion_22.sh
# =====================================================================
set -euo pipefail

info() { echo -e "\n\033[1;34m[+]\033[0m $*"; }
die()  { echo -e "\033[1;31m[x]\033[0m $*" >&2; exit 1; }

[[ $EUID -eq 0 ]] || die "Ejecuta el script con sudo."

# Seguridad: no redirigir el 22 si el SSH real no esta ya en el 2022
# o si Cowrie no esta escuchando.
ss -ltn "sport = :2022" | grep -q LISTEN || die "El SSH real no escucha en 2022. Ejecuta antes 01_hardening.sh."
systemctl is-active --quiet cowrie       || die "Cowrie no esta activo. Ejecuta antes 02_instalar_cowrie.sh."

ensure() {  # inserta la regla solo si no existe ya
  local table=$1 chain=$2; shift 2
  iptables -t "$table" -C "$chain" "$@" 2>/dev/null || iptables -t "$table" -I "$chain" 1 "$@"
}

info "Aplicando la redireccion 22 -> 2222..."
# Tras PREROUTING el paquete llega a INPUT con destino 2222, por eso el
# firewall del host debe aceptar el 2222 aunque el proveedor solo exponga el 22.
ensure filter INPUT -p tcp --dport 2222 -m conntrack --ctstate NEW -j ACCEPT
ensure nat PREROUTING -p tcp --dport 22 -j REDIRECT --to-port 2222
netfilter-persistent save

info "Reglas activas:"
iptables -t nat -S PREROUTING | grep 2222
iptables -S INPUT | grep -E -- '--dport (2022|2222)'

cat <<EOF

  El honeypot ya es publico en el puerto 22.
  Comprobacion desde fuera:  ssh root@<IP_PUBLICA>   -> debe verse web-prod-02
  Administracion:            ssh -p 2022 ubuntu@<IP_PUBLICA>
  Ver ataques en directo:    sudo tail -f /home/cowrie/honeypot/var/log/cowrie/cowrie.json

EOF
