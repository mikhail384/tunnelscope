#!/usr/bin/env bash
# CSQTT compatible server: standalone installer template, bundled by package_installer.py.
set -Eeuo pipefail
umask 077
readonly CSQTT_INSTALLER_VERSION='2.5.0-compatible.3'
readonly CSQTT_PAYLOAD_SHA256='@PAYLOAD_SHA256@'
readonly CSQTT_RUST_VERSION='1.97.1'
WORK_DIR=''
cleanup() { [[ -z "$WORK_DIR" ]] || rm -rf -- "$WORK_DIR"; }
trap cleanup EXIT
trap 'printf "Ошибка установки, строка %s.\n" "$LINENO" >&2' ERR

usage() {
    cat <<'HELP'
CSQTT 2.5 с поддержкой Android 2.1.9, focsq и VK TURN Proxy iOS.

Установка / обновление на Ubuntu или Debian с systemd:
  sudo bash install-csqtt.sh

Параметры:
  --help                 Эта справка; без изменений системы.
  --extract КАТАЛОГ      Извлечь встроенные исходники; без root и установки.
  --prepare-only КАТАЛОГ Собрать бинарник в каталоге; без установки службы.
  --backup               Сохранить текущий CSQTT локально; краткий перезапуск.
  --list-backups         Показать копии и версии; без изменения службы.
  --rollback ВЕРСИЯ      Вернуть последнюю исправную копию версии, например 2.1.9.
  --rollback ИМЯ_КОПИИ   Вернуть конкретную копию из --list-backups.

Копии хранятся в /var/backups/csqtt-compatible на вашем VPS. При откате сначала
сохраняется текущее состояние. Восстанавливаются прежние панель, база и пароли;
доступы, созданные после выбранной копии, останутся только в копии перед откатом.
Эти команды не устанавливают зависимости и не пересобирают сервер.

Настройки через окружение (необязательны):
  CSQTT_PEER_PORT=46000 CSQTT_WEB_PORT=46002 CSQTT_PUBLIC_IP=IPv4
  CSQTT_WEB_USER=admin CSQTT_WEB_PASS=... CSQTT_MAIN_PASSWORD=...
  CSQTT_BUILD_JOBS=2

При обновлении настройки и база сохраняются. Пароли генерируются автоматически
при первой установке. Сборка из встроенного исходного кода требует интернета,
нескольких ГБ свободного места и времени на загрузку Rust и компиляцию.
HELP
}

extract_source() {
    local destination="$1" archive="$WORK_DIR/source.tar.gz" self
    self="${BASH_SOURCE[0]}"
    if [[ "$CSQTT_PAYLOAD_SHA256" != '@PAYLOAD_SHA256@' ]]; then
        awk 'payload { print } $0 == "# __CSQTT_SOURCE_PAYLOAD_V1__" { payload = 1 }' "$self" |
            base64 --decode > "$archive"
        printf '%s  %s\n' "$CSQTT_PAYLOAD_SHA256" "$archive" | sha256sum --check --status || {
            echo 'Контрольная сумма встроенных исходников не совпала.' >&2; return 1;
        }
        tar -xzf "$archive" --no-same-owner -C "$destination"
    else
        local project
        project="$(cd -- "$(dirname -- "$self")/.." && pwd)"
        [[ -f "$project/rust-server/main.rs" ]] || {
            echo 'Нужен автономный install-csqtt.sh или полный каталог исходников.' >&2; return 1;
        }
        mkdir "$destination/csqtt-compatible"
        tar -C "$project" --exclude=target --exclude=build --exclude=dist -cf - \
            rust-server shared LICENSE app/src/main/assets/domains.txt scripts/install_server.py scripts/csqtt-network-up.sh |
            tar -xf - -C "$destination/csqtt-compatible"
    fi
}

check_platform() {
    [[ "$(uname -s)" == Linux ]] || { echo 'Требуется Linux.' >&2; return 1; }
    case "$(uname -m)" in
        x86_64|aarch64|arm64) ;;
        *) echo 'Поддерживаются серверы amd64 и arm64.' >&2; return 1 ;;
    esac
    [[ -r /etc/os-release ]] || return 1
    # This is an OS-owned configuration, never an uploaded environment file.
    . /etc/os-release
    case "${ID:-}" in
        ubuntu|debian) ;;
        *) echo 'Этот установщик рассчитан на Ubuntu и Debian.' >&2; return 1 ;;
    esac
}

install_build_dependencies() {
    echo 'Установка зависимостей сборки...'
    export DEBIAN_FRONTEND=noninteractive
    apt-get update -q
    apt-get install -y --no-install-recommends \
        build-essential cmake pkg-config ca-certificates curl python3 \
        iproute2 iptables kmod util-linux openssl procps
}

build_server() {
    local source="$1" output="$2" cargo_bin host jobs
    jobs="${CSQTT_BUILD_JOBS:-2}"
    [[ "$jobs" =~ ^[1-9][0-9]?$ ]] || { echo 'CSQTT_BUILD_JOBS: от 1 до 99.' >&2; return 1; }
    if [[ "${ACTION}" == prepare ]]; then
        cargo_bin="$(command -v cargo || true)"
        [[ -n "$cargo_bin" ]] || { echo 'Для --prepare-only установите Rust 1.97.1.' >&2; return 1; }
    else
        export CARGO_HOME=/opt/csqtt-build/cargo RUSTUP_HOME=/opt/csqtt-build/rustup
        mkdir -p "$CARGO_HOME" "$RUSTUP_HOME"
        cargo_bin="$CARGO_HOME/bin/cargo"
        if [[ ! -x "$cargo_bin" ]]; then
            curl --fail --silent --show-error --location --proto '=https' --tlsv1.2 \
                --retry 3 https://sh.rustup.rs -o "$WORK_DIR/rustup-init.sh"
            sh "$WORK_DIR/rustup-init.sh" -y --no-modify-path --profile minimal \
                --default-toolchain "$CSQTT_RUST_VERSION"
        fi
        "$CARGO_HOME/bin/rustup" toolchain install "$CSQTT_RUST_VERSION" --profile minimal
        export PATH="$CARGO_HOME/bin:$PATH"
        export CARGO_TARGET_DIR=/var/cache/csqtt-compatible/target
    fi
    host="$("$cargo_bin" +"$CSQTT_RUST_VERSION" -vV | sed -n 's/^host: //p')"
    [[ -n "$host" ]] || { echo 'Не удалось определить Rust target.' >&2; return 1; }
    # Explicit host target overrides upstream's musl-only .cargo/config.toml.
    mkdir -p "$output"
    export CARGO_TARGET_DIR="${CARGO_TARGET_DIR:-$output/target}"
    # Bundled files have reproducible epoch mtimes. Cargo checks mtimes, so an
    # existing target cache could otherwise silently reuse the previous server,
    # even when Rust code or include_str! HTML/CSS changed in this installer.
    find "$source" -type f -exec touch -- {} +
    echo 'Сборка совместимого сервера из встроенных исходников...'
    "$cargo_bin" +"$CSQTT_RUST_VERSION" build --manifest-path "$source/rust-server/Cargo.toml" \
        --release --locked --target "$host" --jobs "$jobs"
    install -m 0755 "$CARGO_TARGET_DIR/$host/release/csqtt" "$output/csqtt"
    [[ "$("$output/csqtt" --protocol-revision)" == CSQTT-WIRE-3 ]]
    "$output/csqtt" --version
}

main() {
    ACTION=install
    local output=''
    case "${1:-}" in
        --help|-h) usage; return ;;
        --extract|--prepare-only)
            [[ $# == 2 ]] || { usage >&2; return 2; }
            output="$2"
            [[ ! -e "$output" ]] || { echo 'Каталог назначения уже существует.' >&2; return 2; }
            if [[ "$1" == --extract ]]; then ACTION=extract; else ACTION=prepare; fi ;;
        --backup|--list-backups)
            [[ $# == 1 ]] || { usage >&2; return 2; }
            ACTION=maintenance ;;
        --rollback)
            [[ $# == 2 && -n "$2" ]] || { usage >&2; return 2; }
            ACTION=maintenance ;;
        '') [[ $# == 0 ]] || return 2 ;;
        *) usage >&2; return 2 ;;
    esac
    if [[ "$ACTION" == install ]]; then
        [[ $EUID == 0 ]] || { echo 'Запустите: sudo bash install-csqtt.sh' >&2; return 1; }
        check_platform
        [[ -d /run/systemd/system ]] && command -v systemctl >/dev/null || {
            echo 'Нужен VPS с работающим systemd.' >&2; return 1;
        }
        # Fail before apt, compilation or touching a running server on panel-managed hosts.
        if systemctl cat csqtt.service 2>/dev/null | grep -Eq -- '--desired|--no-web|swg-noded'; then
            echo 'Этот экземпляр управляется swg-panel; требуется его серверный форк.' >&2; return 1
        fi
        install_build_dependencies
        exec 9>/run/lock/csqtt-compatible-install.lock
        flock -n 9 || { echo 'Другой установщик уже работает.' >&2; return 1; }
    fi
    WORK_DIR="$(mktemp -d -t csqtt-compatible.XXXXXXXX)"
    if [[ "$ACTION" == extract ]]; then
        mkdir -p -- "$output"
        extract_source "$output"
        echo "Исходники: $output/csqtt-compatible"
        return
    fi
    extract_source "$WORK_DIR"
    local source="$WORK_DIR/csqtt-compatible"
    if [[ "$ACTION" == maintenance ]]; then
        [[ $EUID == 0 ]] || { echo 'Для резервных копий запустите команду через sudo.' >&2; return 1; }
        command -v python3 >/dev/null || { echo 'Нужен Python 3: sudo apt-get install -y python3' >&2; return 1; }
        python3 "$source/scripts/install_server.py" "$@"
        return
    fi
    if [[ "$ACTION" == prepare ]]; then
        build_server "$source" "$output"
        return
    fi
    python3 "$source/scripts/install_server.py" --preflight
    build_server "$source" "$WORK_DIR/binary"
    python3 "$source/scripts/install_server.py" --install "$WORK_DIR/binary/csqtt" \
        --network-helper "$source/scripts/csqtt-network-up.sh" --source "$source"
}

main "$@"
exit 0
