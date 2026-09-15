#!/bin/bash
# Local files only. Sourcing this helper does not install anything.
sb_install_local_shortcut(){
local candidate bundle previous= bundle_root=/usr/local/lib/sing-box-yg item
local -a module_files=(chain/core.lock.json lib/sb-config.sh lib/sb-install.sh)
if [[ ! -f "$SB_SCRIPT_SOURCE" || "$SB_SCRIPT_SOURCE" == /proc/* || "$SB_SCRIPT_SOURCE" == /dev/* ]]; then
echo "请先将仓库克隆或脚本下载到普通文件，再运行；快捷命令只安装本地已审阅脚本。" >&2
return 1
fi
[[ "$SB_SCRIPT_SOURCE" == /usr/bin/sb && -f "$bundle_root/chain/generate.py" && -f "$bundle_root/lib/sb-config.sh" && -f "$bundle_root/lib/sb-install.sh" ]] && return 0
for item in chain/generate.py chain/chain.py chain/fetch-core.py chain/core.lock.json lib/sb-config.sh lib/sb-install.sh; do
    [[ -f "$SB_MODULE_ROOT/$item" ]] || { echo "缺少本地模块：$item" >&2; return 1; }
done
for item in "$SB_MODULE_ROOT"/chain/*.py; do
    module_files+=("chain/${item##*/}")
done
candidate=$(mktemp /usr/bin/.sb.XXXXXX) || return 1
if ! cp -- "$SB_SCRIPT_SOURCE" "$candidate" || ! bash -n "$candidate" || ! chmod 700 "$candidate"; then
rm -f -- "$candidate"
return 1
fi
mkdir -p /usr/local/lib || { rm -f -- "$candidate"; return 1; }
bundle=$(mktemp -d /usr/local/lib/.sing-box-yg.XXXXXX) || { rm -f -- "$candidate"; return 1; }
mkdir -- "$bundle/chain" "$bundle/lib" || { rm -rf -- "$bundle"; rm -f -- "$candidate"; return 1; }
for item in "${module_files[@]}"; do
    if ! install -m 600 -- "$SB_MODULE_ROOT/$item" "$bundle/$item"; then
        rm -rf -- "$bundle"; rm -f -- "$candidate"; return 1
    fi
done
if ! bash -n "$bundle/lib/sb-config.sh" || ! bash -n "$bundle/lib/sb-install.sh"; then
    rm -rf -- "$bundle"; rm -f -- "$candidate"; return 1
fi
touch "$bundle/.local-sb-modules"
if [[ -e "$bundle_root" || -L "$bundle_root" ]]; then
    if [[ -L "$bundle_root" || ! -f "$bundle_root/.local-sb-modules" ]]; then
        echo "模块目录已存在且不属于本脚本，未覆盖。" >&2
        rm -rf -- "$bundle"; rm -f -- "$candidate"; return 1
    fi
    previous=$(mktemp -d /usr/local/lib/.sing-box-yg-old.XXXXXX) || {
        rm -rf -- "$bundle"; rm -f -- "$candidate"; return 1;
    }
    rmdir -- "$previous"
    if ! mv -- "$bundle_root" "$previous"; then
        rm -rf -- "$bundle"; rm -f -- "$candidate"; return 1
    fi
fi
if ! mv -- "$bundle" "$bundle_root"; then
    [[ -n "$previous" ]] && mv -- "$previous" "$bundle_root"
    rm -rf -- "$bundle"; rm -f -- "$candidate"; return 1
fi
if ! mv -f -- "$candidate" /usr/bin/sb; then
    rm -rf -- "$bundle_root"
    [[ -n "$previous" ]] && mv -- "$previous" "$bundle_root"
    rm -f -- "$candidate"; return 1
fi
[[ -z "$previous" ]] || rm -rf -- "$previous"
return 0
}
