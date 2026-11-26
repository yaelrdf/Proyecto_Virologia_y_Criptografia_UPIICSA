#!/usr/bin/env bash
# Abre en el firewall de Linux (ufw) los puertos del nodo (§5.1 del estándar v2.0):
#   HTTP 5000+n (TCP), HTTPS 5100+n (TCP) y anuncio de descubrimiento 5099 (UDP).
# Uso:  sudo scripts/firewall-linux.sh [teamNumber] [--subred 192.168.1.0/24] [--quitar]
set -euo pipefail

TEAM=8
SUBNET="any"
REMOVE=0
while [[ $# -gt 0 ]]; do
  case "$1" in
    --subred) SUBNET="$2"; shift 2 ;;
    --quitar) REMOVE=1; shift ;;
    *) TEAM="$1"; shift ;;
  esac
done

HTTP=$((5000 + TEAM)); HTTPS=$((5100 + TEAM)); UDP=5099
command -v ufw >/dev/null || { echo "ufw no está instalado (sudo apt install ufw)"; exit 1; }
[[ $EUID -eq 0 ]] || { echo "Ejecuta con sudo"; exit 1; }

rule() { # proto puerto comentario
  if [[ $REMOVE -eq 1 ]]; then
    ufw delete allow from "$SUBNET" to any port "$2" proto "$1" >/dev/null || true
    echo "Quitada: $1/$2 ($3)"
  else
    ufw allow from "$SUBNET" to any port "$2" proto "$1" comment "CentroCiber $3"
  fi
}

rule tcp "$HTTP"  "API HTTP EQ$(printf %02d "$TEAM")"
rule tcp "$HTTPS" "API HTTPS EQ$(printf %02d "$TEAM")"
rule udp "$UDP"   "Descubrimiento CC-BEACON"
ufw status | grep -E "$HTTP|$HTTPS|$UDP" || true
echo "Listo. Si ufw está inactivo, actívalo con: sudo ufw enable (permite SSH antes si lo usas)."
