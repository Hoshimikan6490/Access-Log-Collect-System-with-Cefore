#!/bin/bash
# cefore_clean.sh
# Ceforeの古いビルドデータとインストール済みバイナリを削除する
#
# 使い方:
#   ./cefore_clean.sh                        # バイナリ削除のみ
#   ./cefore_clean.sh /path/to/cefore-0.12.0 # ソースツリーも合わせてclean
#
# 削除対象:
#   - /usr/local/sbin/ 以下の cefnetd, csmgrd, conpubd
#   - /usr/local/bin/  以下の各種ツール・ユーティリティ
#   - /usr/local/lib/  以下の libcefore*, libcsmgrd*
#   - /tmp/cef_*.* /tmp/csmgr_*.* (残留ソケットファイル)
#   - ソースツリー内のビルド生成物 (make distclean)
#
# 削除しないもの:
#   - /usr/local/cefore/ の設定ファイル (cefnetd.conf など)
#   - ソースコード本体

set -euo pipefail

# ===================== 設定 =====================
CEFORE_INSTALL_DIR="${CEFORE_DIR:-/usr/local}"
SRC_DIR="${1:-}"

if [ -z "${SRC_DIR}" ]; then
    SRC_DIR=$(pwd)
fi

# ===================== 表示 =====================
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
BOLD='\033[1m'
NC='\033[0m'

info()  { echo -e "${BLUE}[INFO]${NC} $*"; }
ok()    { echo -e "${GREEN}[ OK ]${NC} $*"; }
warn()  { echo -e "${YELLOW}[WARN]${NC} $*"; }
error() { echo -e "${RED}[ERR ]${NC} $*" >&2; }
sep()   { echo -e "${BOLD}-----------------------------------------------${NC}"; }

# ===================== sudo確認 =====================
check_sudo() {
    if ! sudo -n true 2>/dev/null; then
        info "sudoパスワードを入力してください"
        sudo true || { error "sudo失敗。終了します"; exit 1; }
    fi
}

# ===================== デーモン停止 =====================
stop_daemons() {
    sep
    info "デーモン停止"

    if pgrep -x cefnetd > /dev/null 2>&1; then
        info "cefnetd を停止します..."
        # cefnetdstop -F は全インスタンス停止+ソケット掃除
        sudo "${CEFORE_INSTALL_DIR}/bin/cefnetdstop" -F 2>/dev/null \
            || sudo pkill -x cefnetd 2>/dev/null \
            || true
        sleep 1
        ok "cefnetd 停止"
    else
        info "cefnetd は動いていません"
    fi

    if pgrep -x csmgrd > /dev/null 2>&1; then
        info "csmgrd を停止します..."
        sudo "${CEFORE_INSTALL_DIR}/bin/csmgrdstop" 2>/dev/null \
            || sudo pkill -x csmgrd 2>/dev/null \
            || true
        sleep 1
        ok "csmgrd 停止"
    else
        info "csmgrd は動いていません"
    fi

    # 残留ソケットファイルを掃除
    local socks
    socks=$(find /tmp -maxdepth 1 -name 'cef_*.*' -o -name 'csmgr_*.*' 2>/dev/null || true)
    if [ -n "${socks}" ]; then
        echo "${socks}" | xargs sudo rm -f
        ok "残留ソケット削除"
    fi
}

# ===================== インストール済みファイル削除 =====================
remove_installed() {
    sep
    info "インストール済みバイナリ・ライブラリ削除 (${CEFORE_INSTALL_DIR})"

    local removed=0

    # --- sbin: デーモン ---
    local daemons=(cefnetd csmgrd conpubd)
    for f in "${daemons[@]}"; do
        local path="${CEFORE_INSTALL_DIR}/sbin/${f}"
        if [ -f "${path}" ]; then
            sudo rm -f "${path}" && ok "削除: ${path}" && ((removed++)) || warn "削除失敗: ${path}"
        fi
    done

    # --- bin: ツール・ユーティリティ ---
    local tools=(
        cefnetdstart cefnetdstop
        cefstatus cefroute cefctrl
        cefputfile cefgetfile
        cefputstream cefgetstream cefgetchunk
        ccninfo cefinfo
        cefsubfile cefpubfile
        csmgrdstart csmgrdstop csmgrstatus
        conpubdstart conpubdstop conpubstatus conpubreload
    )
    for f in "${tools[@]}"; do
        local path="${CEFORE_INSTALL_DIR}/bin/${f}"
        if [ -f "${path}" ]; then
            sudo rm -f "${path}" && ok "削除: ${path}" && ((removed++)) || warn "削除失敗: ${path}"
        fi
    done

    # --- lib: 共有ライブラリ ---
    local lib_dir="${CEFORE_INSTALL_DIR}/lib"
    local libs
    libs=$(find "${lib_dir}" -maxdepth 1 \( -name 'libcefore*' -o -name 'libcsmgrd*' \) 2>/dev/null || true)
    if [ -n "${libs}" ]; then
        echo "${libs}" | xargs sudo rm -f
        ok "共有ライブラリ削除 (libcefore*, libcsmgrd*)"
        ((removed++))
    else
        info "共有ライブラリは見つかりませんでした (${lib_dir})"
    fi

    # ldconfigを更新してキャッシュから消す
    sudo ldconfig 2>/dev/null && ok "ldconfig 更新" || warn "ldconfig 失敗 (影響は軽微)"

    if [ "${removed}" -eq 0 ]; then
        warn "削除対象のファイルが見つかりませんでした"
        warn "CEFORE_DIR が違う可能性があります (現在: ${CEFORE_INSTALL_DIR})"
    else
        ok "合計 ${removed} 件削除"
    fi
}

# ===================== ソースツリークリーン =====================
clean_source() {
    sep
    if [ -z "${SRC_DIR}" ]; then
        info "ソースディレクトリ未指定 → ソースツリークリーンをスキップ"
        info "指定する場合: $0 /path/to/cefore-0.12.0"
        return
    fi

    if [ ! -d "${SRC_DIR}" ]; then
        warn "ディレクトリが存在しません: ${SRC_DIR} → スキップ"
        return
    fi

    info "ソースツリークリーン: ${SRC_DIR}"

    if [ ! -f "${SRC_DIR}/Makefile" ]; then
        warn "Makefileが見つかりません (まだconfigureしていない？) → スキップ"
        return
    fi

    (
        cd "${SRC_DIR}"
        # make distclean: Makefile・config.h・config.logなど configure生成物も含めて全削除
        # make clean:     オブジェクトファイルのみ削除 (Makefileは残る)
        if make distclean 2>/dev/null; then
            ok "make distclean 完了 (configure生成物も削除)"
        else
            warn "make distclean 失敗 → make clean にフォールバック"
            make clean 2>/dev/null && ok "make clean 完了" || warn "make clean も失敗"
        fi
    )
}

# ===================== 設定ファイルの扱い =====================
show_config_note() {
    sep
    local conf_dir="${CEFORE_INSTALL_DIR}/cefore"
    if [ -d "${conf_dir}" ]; then
        warn "設定ファイルは削除しませんでした: ${conf_dir}"
        warn "  CS_MODE などのカスタム設定はそのまま残ります"
        warn "  完全に消したい場合は手動で: sudo rm -rf ${conf_dir}"
    fi
}

# ===================== メイン =====================
main() {
    sep
    echo -e "${BOLD}  Cefore クリーンアップスクリプト${NC}"
    sep
    echo "  インストール先 : ${CEFORE_INSTALL_DIR}"
    echo "  ソースDir      : ${SRC_DIR:-（未指定・スキップ）}"
    echo ""
    echo "  削除対象:"
    echo "    ・cefnetd / csmgrd / conpubd（デーモン停止を含む）"
    echo "    ・各種ツール・ユーティリティ"
    echo "    ・libcefore* / libcsmgrd*（共有ライブラリ）"
    echo "    ・/tmp の残留ソケットファイル"
    if [ -n "${SRC_DIR}" ]; then
    echo "    ・ソースツリーのビルド生成物（make distclean）"
    fi
    echo ""
    echo "  削除しない:"
    echo "    ・${CEFORE_INSTALL_DIR}/cefore/ の設定ファイル"
    sep

    read -r -p "続けますか？ [y/N]: " confirm
    case "${confirm}" in
        [yY]|[yY][eE][sS]) ;;
        *) info "キャンセルしました"; exit 0;;
    esac
    echo ""

    check_sudo
    stop_daemons
    remove_installed
    clean_source
    show_config_note

    sep
    ok "クリーンアップ完了"
    sep
    echo ""
    echo -e "${BOLD}次のステップ:${NC} ソースディレクトリで再ビルドしてください"
    echo ""
    if [ -n "${SRC_DIR}" ]; then
        echo "  cd ${SRC_DIR}"
    else
        echo "  cd /path/to/cefore-0.12.0"
    fi
    echo "  autoconf && automake"
    echo "  ./configure --enable-cache --enable-csmgr"
    echo "  make"
    echo "  sudo make install"
    echo "  sudo ldconfig"
    echo ""
}

main
