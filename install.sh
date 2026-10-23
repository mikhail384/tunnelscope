#!/usr/bin/env bash
# Generated with the standalone installer by scripts/package_installer.py.
set -Eeuo pipefail
umask 077
DOWNLOAD_DIR=''
cleanup() { [[ -z "$DOWNLOAD_DIR" ]] || rm -rf -- "$DOWNLOAD_DIR"; }
trap cleanup EXIT

main() {
    local installer_url='https://raw.githubusercontent.com/mikhail384/tunnelscope/b65763375e96bf2b53fb7cdb465b732ad84e1906/install-csqtt.sh'
    local installer_sha256='7063dc0bf813ac51a34ca112a190166857df94bc3023e44a40cd5dbfbdac701e'
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
