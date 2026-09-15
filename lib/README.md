# 配置生成与运行分离

## 日常使用：中文向导

在完整仓库运行：

```bash
bash sb.sh --generate-config
```

向导依次收集输出位置、协议、起始端口、监听地址、Reality 域名、VMess 路径，以及 TLS 证书。协议可以全部生成，也可以输入 `1,3` 等编号选择；凭据会自动生成。

TLS 可使用现有 PEM 证书和私钥，也可在输出目录内临时生成带 DNS SAN 的自签证书。证书与私钥内容嵌入最终 JSON，临时 PEM 文件随后删除。自签证书有效期为一年；后续证书更新需要重新生成、导入并部署，工具不会借用原 `sb` 的续期任务。客户端需要信任自签证书；附件完整客户端配置会携带证书固定信息。

可提供本地内核，省去向导中的下载选择：

```bash
bash sb.sh --generate-config --binary /path/to/sing-box-1.14.0 \
  --output ./server.json
```

没有内核时，向导中的 `auto` 或 `--download-core` 会下载 `chain/core.lock.json` 锁定的官方版本，校验归档 SHA256 和内核版本后保存在输出文件旁的 `.sb-generator-core/`。缓存与原服务、附件服务的内核独立，只用于生成和校验。已有输出文件不会覆盖。

生成成功后会显示可直接执行的 `sing-box run -c ...` 命令。配置也可以直接交给附件导入。生成与实际运行之间的交接文件就是这个标准 sing-box JSON。

## 自动化

保留参数文件接口：

```bash
bash sb.sh --generate-config --example > params.json
# 设置 params.json 中需要的协议、端口、域名及 PEM 文件路径。
bash sb.sh --generate-config --params params.json \
  --output ./server.json --binary /path/to/sing-box-1.14.0
```

证书相对路径以 `params.json` 所在目录为基准。省略 UUID、密码、Reality 私钥和 short ID 时自动生成。省略本地内核时可以使用 `--download-core`。

内部接口位于 `chain/generate.py`：

| 接口 | 行为 |
| --- | --- |
| `render(params, base, binary)` | 解析参数并返回标准配置；必要时调用内核生成 Reality 密钥 |
| `generate_values(params, base, output, binary)` | 校验参数与内核版本，检查配置，原子发布权限为 0600 的新文件 |
| `generate(params_path, output, binary)` | 参数文件入口 |
| `wizard(output=None, binary=None, download=False)` | 中文向导，返回 `(output, binary)` 两个 `Path` |
| `main(argv)` | 命令行入口；`main([])` 启动向导 |

这些操作不需要 root，也不会安装系统依赖或配置服务。自动下载需要 `curl`；自签证书需要 `openssl`；缺少程序时会报错。写入范围是用户指定的输出目录及其临时文件、可选内核缓存，不自动读写 `/etc/s-box`、`/etc/sing-box-addon`、systemd、OpenRC 或 crontab。

## 原模板的独立模块

`lib/sb-config.sh` 保留原 `inssbjsonser` 的两套模板。单独 `source` 仅定义函数，不执行生成或安装。

调用方式：

```bash
source lib/sb-config.sh
# 调用方先准备函数开头列出的协议、证书、Reality 和 WARP 参数变量。
mkdir -p ./legacy-output
sb_render_legacy_config ./legacy-output 1.14.0
```

该接口面向原脚本与自动化开发。它接受显式输出目录和内核版本，只在输出目录生成 `sb10.json`、`sb11.json`、`sb.json`。1.10 系列选用四协议模板，其余使用五协议模板。输出目录已有这些文件时拒绝覆盖；字段缺失、非法转义或无效 JSON 不会发布配置。

保留原文件逐行布局是为了兼容原菜单的固定行号修改。没有把这些旧模板交给 JSON 格式化器重写。旧模板中的 WARP、分流和证书路径仍与原版兼容；它们与向导生成的、证书内嵌的标准配置有不同用途。

原默认安装流程拆为三个阶段：

1. `sb_prepare_legacy_install`：原环境准备、证书与端口选择、内核与 WARP 参数准备。
2. `inssbjsonser(output_dir)`：调用纯模板模块生成到暂存目录。
3. `sb_deploy_generated(output_dir)`：先由内核校验，再安装配置与服务、建立快捷命令及定时任务。

**旧环境准备仍保留原脚本的行为。** 例如 `v6` 可能调整解析和临时停启 WARP，ACME 选项会调用原来的证书申请流程。只生成向导不会调用这个阶段。原整套管理菜单仍用于维护原服务。

## 本地安装与更新

`lnsb` 同时安装本地 `sb.sh`、全部 `chain/*.py`、锁文件及模板模块到 `/usr/bin/sb` 与 `/usr/local/lib/sing-box-yg`。快捷命令生成配置时可以脱离克隆目录。

已有原版安装时，可从完整仓库显式更新本地快捷命令，无需重装代理服务：

```bash
bash sb.sh --install-shortcut
sb --generate-config
```

`--install-shortcut` 需要 root，只复制脚本与模块，不启动或停止服务，也不修改原配置、crontab 和链式接管标记。`lib/sb-install.sh` 保存该安装函数；同样可以安全地单独 `source`。旧脚本卸载时，仅当模块目录带有本脚本的所有权标记，才连同快捷命令一起删除。

模块缺失会在进入原脚本系统检测和依赖安装前报错。脚本更新菜单不会联网覆盖代码；需要从自己的 Git 仓库审阅更新后使用本地版本。安装快捷命令不会从上游下载 `sb.sh`。

## 验证

```bash
bash -n sb.sh
bash -n lib/sb-config.sh
bash -n lib/sb-install.sh
python3 -m unittest discover -s chain/tests -p 'test_generate.py' -v
python3 -m unittest discover -s chain/tests -p 'test_legacy_config.py' -v
SB_TEST_CORE=/path/to/sing-box-1.14.0 \
  python3 -m unittest discover -s chain/tests -p 'test_generate.py' -v
```

测试在临时目录验证五协议向导、自签证书内嵌、核心校验失败清理、旧模板与提取前的字节一致性、1.10 模板选择、生成失败不部署服务，以及安装快捷命令后脱离仓库仍可生成。最后一个命令额外使用真实内核检查五协议配置，不启动监听服务。
