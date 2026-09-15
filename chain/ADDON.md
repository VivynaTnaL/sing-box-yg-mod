# 独立链式代理附件

`sb-chain` 在 A、B 上运行自己的 sing-box：客户端 → A 的独立入口 → B 的 SS2022 入口 → 互联网。原有 `sb` 和其他代理服务可以继续运行。

导入只读取标准 sing-box 服务端配置及证书材料；公网访问地址由用户补充。导入后保存独立端口、凭据和配置快照，服务运行不读取原脚本目录。

本页适用于 `sb-chain`。目录中 `chain.py`、`deploy.py` 及旧版文档属于历史接管方案，新安装请从本页开始。

## 开始前

- A、B 都准备完整仓库；后台安装需要 Linux amd64/arm64、systemd 247+、root、Python 3.9+ 和 OpenSSL。
- 内核固定为 sing-box **1.14.0**。初始化时可自动下载并校验，也可用 `--binary /path/to/sing-box` 指定已有内核。
- 准备 A 的 sing-box 服务端配置，以及 A 的公网访问地址、A 连接 B 时的实际出站 IP、B 接收连接的 IP。B 的来源限制使用实际出站 IP，经过 NAT 时应填写 NAT 出口地址。
- 为附件预留独立端口。A 默认从 `21000` 起分配，B 默认 `22000`；按所选协议开放 A 的 TCP/UDP 入口，B 的链路端口只需允许 A 访问。

下文示例中的 `198.51.100.10`、`203.0.113.20` 和示例域名都需要替换。命令在仓库根目录运行。

## 最简单：中文菜单，先 B 后 A

在两台服务器分别运行：

```bash
./sb-chain --state /root/addon-state
```

1. **B：菜单 1**，选择落地 B，填写 B 的 IP、独立端口和 A 的实际出站 IP。得到 `/root/addon-state/handoff.json`。
2. **B：菜单 2**，安装附件运行环境并部署。
3. 通过 SSH/SFTP 把 B 的 `handoff.json` 复制到 A。
4. **A：菜单 1**，选择中转 A，填写源配置路径、客户端访问 A 的 IP/域名及 B 对接文件路径。
5. **A：菜单 2**，安装并部署；首次生成国内直连配置会自动从 GitHub 获取规则。菜单 5 导出客户端文件，菜单 6 设置订阅 URL，菜单 7 设置分流或每日规则更新。

菜单 **5** 包含五项：导出全部或指定组、本机直连节点导入、跨机节点导出、跨机节点导入、应用直连组。已有部署时，通过菜单添加或导入直连节点会自动刷新客户端配置，无需重新部署代理。

尚无服务端配置时，可用菜单 **10** 的中文向导生成，再交给菜单 1 导入。向导支持选择协议、端口、Reality 域名和 TLS 证书，不需要手写 JSON。

安装成功后，脚本会把本次状态目录记录到 `/etc/sing-box-addon/manager.json`。以后系统命令 `sb-chain` 和仓库入口 `./sb-chain` 都会使用这个目录，可以直接运行：

```bash
sb-chain
sb-chain status
sb-chain urls
```

菜单和 `status` 会显示实际读取的状态目录。目录选择顺序为：本次显式 `--state` → 安装时记住的目录 → `/etc/sing-box-addon`。普通命令的显式参数只覆盖本次操作；只有成功执行 `install` 才会记住新的目录。

`--state` 只改变管理数据的位置；当前系统服务仍是单实例，不用于在同一台机器部署多套附件。记录目录不会重新部署代理，也不会把正在运行的代理切换到另一份配置。

已保存的设置损坏，或其指向的目录丢失时，脚本会明确报错。请先确认原状态目录，再用 `./sb-chain --state /实际状态目录 status` 检查，并以同一路径执行 `install` 修复记录；不要通过重新初始化来处理路径问题。
如果 `manager.json` 本身变成了符号链接或目录，需要先检查并处理这个异常路径；安装会拒绝覆盖它。显式 `--state` 仍可用于管理原部署。

### 菜单 4：修改链式服务配置

仅在需要修改 A 的链式入口协议/证书、A 连接 B 的对接信息，或 B 的公网地址/链路端口/允许的 A IP 时使用。导出客户端文件和发布 URL 使用菜单 5、6。

菜单 4 的子项 1、2、3 先收集新的连接参数，然后询问是否立即应用：`n`（默认）只保存，`y` 保存并应用、重启本机附件代理。子项 4 将此前保存的配置应用到服务并重启；若有尚未应用的修改，它们也会生效。已设置的订阅随成功部署同步更新。

各选择子菜单支持 `0` 返回主菜单，无效选项会报错并取消本轮操作。菜单 4 默认 `0`，直接回车也只返回；更新确认处输入 `0` 会连同尚未保存的输入一起取消。只有明确选择部署或确认立即应用才会重启，返回与错误输入不会触发部署。

## 等价 CLI 教程

### 1. 在 B 初始化并部署

```bash
./sb-chain --state /root/addon-state init-exit \
  --address 203.0.113.20 \
  --entry-source 198.51.100.10 \
  --port 22000
./sb-chain --state /root/addon-state install
./sb-chain --state /root/addon-state deploy
```

多个 A 出口可重复传入 `--entry-source`。B 已有服务端配置时，可增加 `--config /path/to/server.json`，用于检查所选端口与该配置是否冲突。A、B 的链路 IP 需使用相同地址族。

`handoff.json` 是含服务器间密钥的私有对接文件。在 **A** 上取回：

```bash
scp root@203.0.113.20:/root/addon-state/handoff.json /root/B-handoff.json
chmod 600 /root/B-handoff.json
```

### 2. 在 A 导入并部署

```bash
./sb-chain --state /root/addon-state init-entry \
  --config /root/A-server.json \
  --address entry.example.com \
  --link /root/B-handoff.json
./sb-chain --state /root/addon-state install
./sb-chain --state /root/addon-state deploy
./sb-chain --state /root/addon-state status
```

`--config` 是标准服务端配置，不是分享链接文件；生成来源不限于 `sb`。支持 VLESS Reality、VMess、Hysteria2、TUIC、AnyTLS，当前传输支持 TCP/WebSocket。可用重复的 `--inbound TAG` 选择入站，用 `--port-start 31000` 指定附件的起始端口。

原 `sb` 默认的 WebSocket early-data（2048、`Sec-WebSocket-Protocol`）会保留到完整 Mihomo/sing-box 配置中；原始 URI 不携带这项可选优化。

`--address` 是客户端实际连接的新入口地址。通配监听地址 `0.0.0.0` 不能提供这个信息；NAT、CDN、Argo 还可能需要额外的端口映射或公网接入设置。本版不自动接管 CDN/Argo 隧道，也不能从 inbound 推导其全部公网参数。

## 客户端分流与 GitHub 自动规则更新

默认 `cn-direct`：国内和局域网从**客户端设备直连**，其他流量走所选代理。这里的 `DIRECT` 不是 `A-direct`；`A-direct` 仍然需要先连接服务器 A。

| 模式 | 客户端路由 |
| --- | --- |
| `cn-direct` | 局域网、CN 域名、CN IP 直连，其余代理 |
| `lan-direct` | 局域网直连，其余代理 |
| `global` | 默认全部代理，仍可设置显式例外 |

默认在服务器自动取得 [MetaCubeX/meta-rules-dat](https://github.com/MetaCubeX/meta-rules-dat) 维护的 `geoip.db` 和 `geosite.db`，提取 `cn` 分类并将规则内嵌进客户端配置。客户端启动不再依赖服务器的 `/root` 路径，也不需要先下载 GitHub 规则。

首次 `build`、`export` 或 `deploy` 自动准备规则；以后使用已经校验的快照。立即检查上游并更新：

```bash
./sb-chain --state /root/addon-state geodata
```

已安装附件后，可启用每日更新：

```bash
./sb-chain --state /root/addon-state rules-auto enable
./sb-chain --state /root/addon-state rules-auto status
# 需要停用时：
./sb-chain --state /root/addon-state rules-auto disable
```

`enable` 先执行一次更新，再安装独立的 systemd timer。后续每天执行，带最多 30 分钟随机延迟，并在错过日程后补执行。手动更新和定时更新都只刷新客户端规则与已发布订阅，**无需重启代理**；原 URL 保持不变。客户端需要按自身订阅刷新周期拉取新内容。

`disable` 取消后续定时任务，正在进行的一次更新会正常完成，避免中断配置与订阅的保存。

下载固定到同一次 release 的两个资产 ID，核对 GitHub 公布的 SHA-256 和文件大小，通过转换及规则校验后才切换快照。同版本复用缓存；`geodata --force` 强制建立新快照。首次无法获取规则时明确报错，更新失败保留有效配置和订阅。校验信任 GitHub HTTPS 及上游维护者，不是额外的独立签名。

成功更新后清理旧数据库缓存，保留最近三个完整版本、当前版本和仍被管理状态引用的快照。手动生成的 `releases/` 目录保留，便于检查和手动运行；确认不再使用后可自行归档。

可以继续使用本机数据库；显式导入会切换为本地规则来源，定时器随后跳过此来源：

```bash
./sb-chain --state /root/addon-state geodata \
  --geoip /root/geoip.db \
  --geosite /root/geosite.db
```

源 `.db` 此后不是运行依赖；更新本地数据库后重新导入即可刷新订阅。再次执行无参数 `geodata` 会恢复 GitHub 来源。缺库、损坏或无法转换时会报错。

设置模式和例外：

```bash
./sb-chain --state /root/addon-state rules \
  --mode cn-direct \
  --direct-domain company.example \
  --proxy-domain overseas.company.example \
  --direct-cidr 192.168.50.0/24 \
  --proxy-cidr 10.20.30.40/32
./sb-chain --state /root/addon-state refresh-clients
```

域名按后缀匹配，各例外参数可重复。优先级为强制代理例外 → 强制直连例外 → 局域网 → CN 域名/IP → 剩余代理。完全相同的直连/代理例外会报错；重叠范围按上述顺序匹配。

`rules` 每次覆盖例外列表，需要保留的例外应一起传入；已导入的内嵌规则会保留。也可通过 `--rules-dir /path/to/snapshot` 选择已有快照。DNS 同步分流：LAN 域名用系统 DNS，CN 域名用国内直连 DNS，其余目标 DNS 经代理；节点自身地址单独使用直连 DNS 解析。

`refresh-clients` 将准备好的分流策略应用到**已部署的节点**。`geodata` 仅替换数据库规则，并分别保留准备配置和已部署配置各自的模式、例外。两种操作都不会把尚未部署的入口端口、凭据或落地连接提前发布。

## 导出文件与固定订阅 URL

先导出到一个尚不存在的目录：

```bash
./sb-chain --state /root/addon-state export --output-dir /root/chain-clients-1
```

| 文件 | 用途 |
| --- | --- |
| `mihomo.yaml` | 完整 Mihomo 配置，含节点组、路由和 DNS |
| `sing-box.json` | sing-box 1.14.0 客户端配置，提供本机 `127.0.0.1:7890` mixed 入口 |
| `nodes.txt` | 逐行节点 URI |
| `nodes.base64.txt` | Base64 节点订阅 |

优先使用完整配置。已验证 Mihomo **1.19.31** 和 sing-box **1.14.0** 的配置加载；旧 Clash 内核及其他客户端不保证支持。URI 中的 TLS 指纹参数并非所有客户端都支持，完整配置保留的证书验证信息更完整。纯节点订阅本身不携带分流规则。sing-box 导出没有自动配置 TUN，手机/TUN 客户端可能需要按其接入方式调整入站。

### A、B、A→B 各自一套配置与订阅

在 **A 上统一发布**三组即可，B 无需额外部署订阅服务：

| 分组 | 客户端使用代理时的路径 | 所需服务 |
| --- | --- | --- |
| `A-direct` | 客户端 → A → 互联网 | A 的原代理服务 |
| `B-direct` | 客户端 → B → 互联网 | B 的原代理服务 |
| `A-to-B` | 客户端 → A 的附件入口 → B 的附件入口 → 互联网 | A、B 的附件服务 |

`A-direct`、`B-direct` 使用对应原服务的监听端口和凭据；原服务必须运行，入口必须对客户端可达。B 的附件 SS2022 链路入口只供 A 连接，不能作为 `B-direct` 节点。每组完整配置仍遵循所选的国内、局域网直连规则。

#### 已部署用户先更新工具

若两端已完成初始化和部署，在 **A、B 各自的仓库目录**运行：

```bash
git pull --ff-only origin feat/standalone-chain
./sb-chain --state /root/addon-state install
```

上例沿用 `/root/addon-state`；请换成初始化时使用的目录，原默认目录为 `/etc/sing-box-addon`。首次升级到能记住目录的版本时，自定义目录用户需要像上面这样显式指定一次。`install` 更新工具与服务定义，并记录选定的状态目录；无需重新初始化或再次选择菜单 2。成功更新不重启代理。

完成后，日常运行 `sb-chain`、`sb-chain status`、`sb-chain urls`，以及之后在仓库执行 `./sb-chain install`，均可省略 `--state`。以下教程继续显式写出目录，便于照着操作时核对；已完成上述安装的用户可以省略。

如果你之前为 `sb-chain` 设置过带 `--state` 的 shell 别名，别名仍会显式覆盖脚本记住的目录。仅在设置过别名的情况下，执行 `unalias sb-chain`，并从 `~/.bashrc` 删除那条旧 `alias sb-chain=...`，再通过 `sb-chain status` 验证新默认目录。没有设置别名则跳过这一步。

#### 1. B 导出客户端交换文件

在 **B** 运行，地址填写客户端访问 B 的公网 IP 或域名：

```bash
./sb-chain --state /root/addon-state export-nodes \
  --config /etc/s-box/sb.json \
  --address original-b.example.com \
  --label B-direct \
  --output /root/B-client-nodes.json
```

输出路径须为新文件；可重复传入 `--inbound TAG` 选择协议入站，也可用 `--binary` 指定内核。这是标准 sing-box 客户端交换配置，只包含客户端所需的地址、认证凭据及公证书信息，不含服务端私钥或本机文件依赖。该文件仍含节点凭据，应通过 SSH/SFTP 传给 A。

在 **A** 取回它：

```bash
scp root@203.0.113.20:/root/B-client-nodes.json /root/B-client-nodes.json
chmod 600 /root/B-client-nodes.json
```

#### 2. A 导入两组直连节点并应用

在 **A** 运行：

```bash
./sb-chain --state /root/addon-state add-direct \
  --config /etc/s-box/sb.json \
  --address original-a.example.com \
  --label A-direct
./sb-chain --state /root/addon-state import-nodes \
  --config /root/B-client-nodes.json \
  --label B-direct
./sb-chain --state /root/addon-state publish-clients
```

`add-direct`、`import-nodes` 在 CLI 中只准备直连组；`publish-clients` 将这两组应用到已部署的客户端配置，同时刷新已设置的订阅。它保留已部署的 `A-to-B` 节点、链路端口、密钥和分流策略，不重启代理，也不提前发布其他待部署的修改。菜单 5 中的添加、导入操作会在已有部署时自动完成这一步。

#### 3. 按组导出或发布

独立导出每组到不同的新目录：

```bash
./sb-chain --state /root/addon-state export --group A-direct --output-dir /root/A-clients-1
./sb-chain --state /root/addon-state export --group B-direct --output-dir /root/B-clients-1
./sb-chain --state /root/addon-state export --group A-to-B --output-dir /root/A-B-clients-1
```

每个目录都有上表中的四种客户端文件。不传 `--group` 时，仍导出可选择全部节点的合并配置。

`export` 读取准备状态，在线订阅读取已应用状态。如果另有尚未 `deploy` 的 A→B 端口或凭据修改，离线导出会包含这些待部署参数；在线订阅继续使用当前链路参数。

接着在 A 按下面任一种方式执行 `publish`。如果升级前已开启订阅，需按原来的地址、监听端口和 TLS 参数重新执行一次完整的 `publish` 命令，让订阅服务加载新版分组路由。原路径口令保持不变。

### 方式一：本机监听，由已有 HTTPS 反向代理发布

先完成 A 的 `deploy`，再运行：

```bash
./sb-chain --state /root/addon-state publish \
  --base-url https://sub.example.com \
  --bind 127.0.0.1 --port 18080
```

在已有 Nginx HTTPS 站点中，将该域名的请求路径原样转发到附件：

```nginx
location / {
    proxy_pass http://127.0.0.1:18080;
    proxy_set_header Host $host;
    access_log off;
}
```

HTTPS 站点和证书由反向代理自行管理。示例使用独立订阅域名；若使用子路径，反向代理需要去掉该前缀，后端接收 `/<口令>/<文件名>` 或 `/<口令>/<分组>/<文件名>`。

### 方式二：附件直接提供 HTTPS

准备匹配订阅域名的证书和私钥：

```bash
./sb-chain --state /root/addon-state publish \
  --base-url https://sub.example.com:18443 \
  --bind 0.0.0.0 --port 18443 \
  --cert /root/sub-fullchain.pem --key /root/sub-key.pem
```

工具会复制 TLS 材料到附件目录；证书续期后需要重新执行该 `publish` 命令加载新证书。发布端口范围为 `1024–65535`。

如使用 `http://服务器IP:18080` 并省略证书参数，服务提供明文 HTTP：路径口令限制访问，但不加密订阅内容。公网使用 HTTPS。

发布后显示已存在分组的固定地址，例如：

| 分组 | Mihomo 订阅示例 |
| --- | --- |
| A 直连 | `https://sub.example.com/<随机口令>/A-direct/mihomo.yaml` |
| B 直连 | `https://sub.example.com/<随机口令>/B-direct/mihomo.yaml` |
| A→B 链式 | `https://sub.example.com/<随机口令>/A-to-B/mihomo.yaml` |
| 全部节点 | `https://sub.example.com/<随机口令>/mihomo.yaml` |

按客户端需要，将末尾文件名替换为 `sing-box.json`、`nodes.txt` 或 `nodes.base64.txt`。未导入的直连组不会产生空订阅；每个独立组只包含该组节点。后台仅提供这些固定组中的四种客户端文件，服务端配置、私钥和 `handoff.json` 不在发布清单中。

后续 `deploy`、`publish-clients`、`geodata` 或 `refresh-clients` 成功后更新内容，各组与合并订阅的 URL 保持不变：

```bash
./sb-chain --state /root/addon-state urls
./sb-chain --state /root/addon-state rotate-token
./sb-chain --state /root/addon-state stop-publish
./sb-chain --state /root/addon-state start-publish
```

轮换口令会让合并订阅与各组的旧 URL 一起失效，需要在客户端更新地址。
各组共用同一个访问口令；独立 URL 用于选择节点组，不提供不同用户之间的访问权限隔离。

部署、订阅切换与管理状态保存放在同一回滚流程中。启动失败、发布失败或最后保存状态失败时恢复之前的配置和订阅；若操作系统拒绝恢复服务，会明确报错，不能把进程健康检查当作跨服务器连通性验证。重新设置发布地址或证书失败时也会恢复原发布设置。

## 更新与启停

直连节点是源配置的导出快照。A 原节点变化后，在 A 重新 `add-direct`；B 原节点变化后，在 B 重新 `export-nodes` 并交给 A 执行 `import-nodes`。最后在 A 执行 `publish-clients`，即可同时更新合并订阅和各组订阅，无需重启 A→B 代理。

重新导入 A 的接入配置或更新证书：

```bash
./sb-chain --state /root/addon-state import-config --config /root/A-server-new.json
./sb-chain --state /root/addon-state deploy
```

证书材料在导入时嵌入，源文件续期不会自动改变附件配置。重新导入时不传 `--inbound` 会沿用之前选择；相同入站 tag 会尽量保留附件端口和客户端凭据。新增或更换协议时检查生成结果。

更换 B 对接文件使用 `update-link --link /root/B-handoff-new.json`，然后 `deploy`。更新 B 地址、端口或 A 来源时，在 B 使用 `update-exit`，参数与 `init-exit` 相同；B 部署后把更新的 `handoff.json` 交给 A。

```bash
./sb-chain --state /root/addon-state stop
./sb-chain --state /root/addon-state start
./sb-chain --state /root/addon-state status
```

`stop` 停止附件并取消其开机启动；`start` 恢复附件并启用开机启动。它们不停止原服务。订阅发布单独通过 `stop-publish` / `start-publish` 管理。

CLI 中，`init-*`、`import-config`、`update-link`、`rules`、`add-direct` 和 `import-nodes` 只准备配置；`deploy` 才启用服务端更新并切换订阅。仅更新直连组使用 `publish-clients`，仅更新规则使用 `geodata` 或 `refresh-clients`，两种情况都无需部署服务端。

## 只生成配置与手动运行

原 `sb.sh` 的旧配置模板已抽到 [lib/sb-config.sh](../lib/sb-config.sh)。旧安装流程明确分为环境准备、配置生成/校验、服务部署；保持原模板的内容与行布局，兼容旧菜单的配置编辑。

新的只生成入口完全独立，不启动服务、不写 crontab，也不修改 `/etc/s-box`。最简单的交互方式：

```bash
bash sb.sh --generate-config
```

向导可使用已有证书或生成后嵌入临时自签证书；可指定本地内核，或下载并校验固定版本。配置生成后打印手动运行命令。需要保留旧 `sb` 菜单并安装新版生成入口时，从完整仓库运行 `bash sb.sh --install-shortcut`；它仅安装命令和所需模块。

自动化仍可使用参数文件：

```bash
bash sb.sh --generate-config --example > /root/server-params.json
```

编辑参数文件：设置协议、端口、Reality 域名，以及实际的 TLS 证书/私钥路径。模板对应 [generate.py 中的 EXAMPLE](generate.py)；相对证书路径以参数文件所在目录为基准。然后生成到一个新文件：

```bash
bash sb.sh --generate-config \
  --params /root/server-params.json \
  --output /root/A-server.json \
  --binary /path/to/sing-box-1.14.0
```

该入口生成并校验配置，不安装或启动服务。`A-server.json` 可直接交给 `init-entry`。

附件也可仅生成发布目录：

```bash
./sb-chain --state /root/addon-state build
```

命令打印 `/root/addon-state/releases/<版本>/`。检查 `server.json` 的监听地址、端口和 `ss -lntup` 的占用情况，再手动执行：

```bash
/path/to/sing-box-1.14.0 check -c /root/addon-state/releases/实际版本/server.json
/path/to/sing-box-1.14.0 run -c /root/addon-state/releases/实际版本/server.json
```

手动进程与 systemd 附件不能同时占用同一端口。`build` 目录包含服务端配置和可能的对接密钥；需要客户端文件时使用 `export`，需要 URL 时使用 `publish`。

## 从旧接管版迁移、卸载

只有旧接管版安装需要一次恢复：

```bash
./sb-chain --state /root/addon-state restore-legacy
```

该操作检查旧配置和服务，停止并禁用 `sing-box-chain.service`，**启动并启用原 `sing-box.service` 的开机启动**；原服务健康后删除接管标记，恢复 `sb` 菜单。加 `--no-enable` 会启动原服务并取消其开机启动。该操作不修改原 crontab；失败会尝试恢复之前的服务状态。

恢复后再按本页初始化独立附件。新模式平时只需停止附件，不需要恢复原版。

```bash
./sb-chain --state /root/addon-state uninstall
```

卸载会停止并移除附件、订阅和规则更新服务/定时器、附件内核和管理命令，保留状态、配置、规则快照、导出内容及 `/etc/sing-box-addon/manager.json` 中记住的目录，便于重新安装。之后从仓库执行 `./sb-chain install` 仍可找到原状态目录。它不会卸载原 `sb`。

## 验证范围

已完成单元测试（含隔离的服务管理、定时器和事务回滚检查），以及本机和 GitHub 真实 GeoIP/GeoSite 转换。五协议完整客户端配置通过 sing-box 1.14.0 和 Mihomo 1.19.31 的配置检查。

可在仓库根目录运行：

```bash
python3 -m unittest discover -s tests -v
python3 -m unittest discover -s chain/tests -v
python3 chain/tests/integration_addon.py --binary /path/to/sing-box-1.14.0
python3 chain/tests/integration_publish_tls.py
```

集成测试只在 `/tmp` 和回环网络运行临时进程，检查独立端口、原服务与附件并行、TCP/UDP、私网与来源限制、链路故障隔离、客户端规则选择直连/代理出口，以及合并、分组订阅的 HTTP/HTTPS 下载、更新、口令轮换和回滚。它不调用 systemd，也不更改现有部署。

配置检查和进程健康检查不代表 A → B 公网连通性。实际部署仍需在目标服务器确认端口可达、B 的来源 IP 正确，并从客户端验证所选节点和分流结果。
