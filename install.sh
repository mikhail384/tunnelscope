#!/usr/bin/env bash
# Generated with the standalone installer by scripts/package_installer.py.
set -Eeuo pipefail
umask 077
DOWNLOAD_DIR=''
cleanup() { [[ -z "$DOWNLOAD_DIR" ]] || rm -rf -- "$DOWNLOAD_DIR"; }
trap cleanup EXIT

main() {
    local installer_url='https://raw.githubusercontent.com/mikhail384/tunnelscope/csqtt-compatible/install-csqtt.sh'
    local installer_sha256='1474b86e931f5c336a84899c39b80ebdbf3551bdf329fc3d1a0ba2864536e708'
    DOWNLOAD_DIR="$(mktemp -d -t csqtt-download.XXXXXXXX)"
    # The bundled installer reads its own payload, so it must be a real file.
    echo 'Загрузка совместимого CSQTT...'
    curl --fail --silent --show-error --location --proto '=https' --tlsv1.2 \
        --connect-timeout 15 --retry 3 "$installer_url" -o "$DOWNLOAD_DIR/install-csqtt.sh"
    if ! printf '%s  %s\n' "$installer_sha256" "$DOWNLOAD_DIR/install-csqtt.sh" |
            sha256sum --check --status; then
        echo 'Контрольная сумма установщика не совпала. Повторите команду позже.' >&2
        return 1
    fi
    case "${1:-}" in
        --help|-h|--extract|--prepare-only)
            bash "$DOWNLOAD_DIR/install-csqtt.sh" "$@" ;;
        *)
            if [[ $EUID == 0 ]]; then
                bash "$DOWNLOAD_DIR/install-csqtt.sh" "$@"
            elif command -v sudo >/dev/null; then
                sudo bash "$DOWNLOAD_DIR/install-csqtt.sh" "$@"
            else
                echo 'Войдите на VPS как root и повторите команду установки.' >&2
                return 1
            fi ;;
    esac
}

main "$@"
