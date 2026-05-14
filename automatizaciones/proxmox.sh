#!/bin/bash

# ==========================================
# ToolKit Proxmox Automate
# ==========================================

# Función para pausar antes de volver al menú
pause() {
    echo ""
    read -p "Presiona [Enter] para volver al menú..."
}

# --- FUNCIONES DE LOS SCRIPTS ---

f_post_install() {
    echo "Ejecutando Proxmox Post-Install..."
    bash -c "$(wget -qLO - https://github.com/community-scripts/ProxmoxVE/raw/main/tools/pve/post-pve-install.sh)"
    pause
}

f_dependency_check() {
    echo "Ejecutando PVE Startup Dependency Check..."
    bash -c "$(curl -fsSL https://raw.githubusercontent.com/community-scripts/ProxmoxVED/main/tools/pve/dependency-check.sh)"
    pause
}

f_all_templates() {
    echo "Descargando All Templates..."
    bash -c "$(curl -fsSL https://raw.githubusercontent.com/community-scripts/ProxmoxVE/main/tools/addon/all-templates.sh)"
    pause
}

f_lxc_execute() {
    echo "Ejecutando PVE LXC Execute..."
    bash -c "$(wget -qLO - https://github.com/community-scripts/ProxmoxVE/raw/main/tools/pve/pve-lxc-execute.sh)"
    pause
}

f_backup_total() {
    echo "=== Configuración de Backup Total ==="
    echo "1. FTP"
    echo "2. Disco USB"
    echo "3. NAS (NFS/SMB)"
    read -p "Elige el destino del backup: " destino
    
    read -p "Introduce la ruta o IP del servidor: " ruta
    echo "Iniciando copia de seguridad de todo el disco hacia $ruta..."
    # Aquí irá tu lógica de dd, rsync o vzdump
    sleep 2
    echo "Backup completado (Simulación)."
    pause
}

f_kernel_clean() {
    echo "Ejecutando PVE Kernel Clean..."
    bash -c "$(wget -qLO - https://github.com/community-scripts/ProxmoxVE/raw/main/tools/pve/pve-kernel-clean.sh)"
    pause
}

f_update_repos() {
    echo "Actualizando Repositorios PVE..."
    bash -c "$(wget -qLO - https://github.com/community-scripts/ProxmoxVE/raw/main/tools/pve/pve-repo-update.sh)"
    pause
}

f_raid_lvm() {
    echo "=== Configuración de RAID 5 y LVM ==="
    echo "Detectando discos disponibles..."
    lsblk -d -o NAME,SIZE,MODEL | grep -v "boot"
    echo "Aquí irá el script para configurar mdadm y lvcreate..."
    pause
}

# --- COLORES ---
NARANJA="\e[38;5;208m" # Naranja Proxmox
BLANCO="\e[97m"
VERDE="\e[32m"
ROJO="\e[31m"
RESET="\e[0m"

# --- TRAMPA PARA SALIDA LIMPIA (Ctrl+C) ---
trap "echo -e '\n${VERDE}Saliendo de ToolKit Proxmox Automate...${RESET}'; exit 0" SIGINT

# --- MENÚ PRINCIPAL ---
while true; do
    clear
    # Imprimiendo el logo ASCII en naranja y el menú con colores combinados
    echo -e "${NARANJA}"
    cat << EOF
  _____                                             ${BLANCO}|  ToolKit Proxmox Automate
 |  __ \                                            ${BLANCO}|  ======================================
 | |__) | __ _____  ___ __ ___   _____  __          ${BLANCO}|  [${NARANJA}1${BLANCO}] Post-Install
 |  ___/ '__/ _ \ \/ / '_ \` _ \ / _ \ \/ /          ${BLANCO}|  [${NARANJA}2${BLANCO}] PVE Startup Dependency Check
 | |   | | | (_) >  <| | | | | | (_) >  <           ${BLANCO}|  [${NARANJA}3${BLANCO}] All Templates
 |_|   |_|  \___/_/\_\_| |_| |_|\___/_/\_\          ${BLANCO}|  [${NARANJA}4${BLANCO}] PVE LXC Execute
                                                    ${BLANCO}|  [${NARANJA}5${BLANCO}] Backup Total (FTP / USB / NAS)
                                                    ${BLANCO}|  [${NARANJA}6${BLANCO}] PVE Kernel Clean
                                                    ${BLANCO}|  [${NARANJA}7${BLANCO}] PVE Update Repositories
                                                    ${BLANCO}|  [${NARANJA}8${BLANCO}] Configurar RAID 5 + LVM
                                                    ${BLANCO}|  [${ROJO}9${BLANCO}] Salir
EOF
    echo -e "${RESET}"
    
    # read -n 1 capta la tecla (silenciosamente con -s) sin necesidad de pulsar Enter
    echo -en " Elige una opción [${NARANJA}1-9${RESET}]: "
    read -n 1 -s opcion
    echo "" # Salto de línea visual
    
    case $opcion in
        1) f_post_install ;;
        2) f_dependency_check ;;
        3) f_all_templates ;;
        4) f_lxc_execute ;;
        5) f_backup_total ;;
        6) f_kernel_clean ;;
        7) f_update_repos ;;
        8) f_raid_lvm ;;
        9) echo -e "${VERDE}Saliendo de ToolKit Proxmox Automate...${RESET}"; exit 0 ;;
        *) echo -e "${ROJO}Opción no válida. Inténtalo de nuevo.${RESET}"; sleep 1 ;;
    esac
done
