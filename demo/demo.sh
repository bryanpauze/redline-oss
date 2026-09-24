#!/usr/bin/env bash
set -uo pipefail
export REDLINE_ENABLE_MCP_EXEC=1 TERM=xterm-256color
R=$'\033[38;5;203m'; D=$'\033[38;5;245m'; C=$'\033[38;5;51m'; B=$'\033[1m'; X=$'\033[0m'
sec(){ printf "\n${C}${B}▸ %s${X}\n" "$1"; sleep .6; }
run(){ printf "${D}\$ ${X}${B}%s${X}\n" "$1"; sleep .4; eval "$1" || true; sleep 1.2; }
clear
printf "${R}${B}  Redline (Open Source)${X}  ${D}LLM & agent security scanner${X}\n"; sleep 1
sec "Scan a deliberately vulnerable model (offline, deterministic)"
run "redline scan --target mock --quiet 2>/dev/null"
sec "Prove whether an agent's tool graph can leak"
run "redline exfil-cert --mcp-command 'python3 -m redline.fixtures.vuln_mcp_server' | head -4"
sec "Map coverage to the NIST adversarial-ML taxonomy"
run "redline coverage 2>/dev/null | sed -n '2,3p'"
printf "\n${R}${B}  Redline OSS${X}${D}  ·  github.com/bryanpauze/redline-oss${X}\n\n"; sleep 1.5
