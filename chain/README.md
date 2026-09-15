# 实用版 v1：A 直出 / B 直出 / A→B

> 本文描述旧版的原端口接管模式。新安装请使用 [独立附件](ADDON.md)，入口为仓库根目录 `bash sb-chain`。新版与原服务并行；已使用本页部署的机器可通过新版的“恢复旧接管版的原服务”菜单迁移。旧生成和部署命令保留以便维护历史安装。

本工具复用原脚本已经可用的客户端接入方式，新增私有 SS2022 服务器间连接。代理数据全部由 sing-box 处理；Python 负责参数、聚合文件、校验和部署。

| 聚合组 | 客户端入口 | 最终出口 | 在哪里生成 |
| --- | --- | --- | --- |
| A-direct | A 的原协议端口、原凭据 | A | A |
| A-to-B | A 的同协议端口、新凭据 | B | A |
| B-direct | B 的原协议端口、原凭据 | B | B |

A 用每个入站中不同的认证用户名区分两组流量。链式用户先匹配 `to-exit`，不在 A 解析目标域名；直出用户在 A 解析、直出。B 的 SS 入站独立监听 TCP/UDP，来源限制仅作用于这个入站，因此不会误伤 B 的客户端直连。没有匹配到已知用户/入口的请求拒绝，链式失败不会回退到 A 直出。

## 已支持与边界

- 从本机原 `sb.json` 和 `jhsub.txt` 导入 **VLESS、VMess、Hysteria2、TUIC、AnyTLS**；保留监听参数、TLS/Reality、WS 路径。每个同协议用户的凭据必须唯一，每个用户至少有一条对应分享链接；陈旧链接、未知协议、无认证入站被拒绝。
- WS 的 CDN/Argo 分享地址、Host、SNI、外部端口保持不变，A-to-B 只替换认证凭据和显示名称；不新建 cloudflared 隧道，不改变 CDN 配置。现有 cloudflared/反向代理继续转发到相同本地端口。真实 CDN/Argo 外部服务仍需联调。
- **只导入入站与分享信息**。旧 WARP、SOCKS、direct 分流规则和 endpoints 不导入，三条路径由新生成器统一控制。旧 inbound sniff 字段会移除；不自动做完整旧内核迁移，其他不兼容字段由固定内核检查拒绝。v1 不接受 inbound detour 或启用 multiplex 的配置。
- B 对接文件包含 `2022-blake3-aes-256-gcm`、32 字节随机密钥及 IP/端口。只给 A，不进入任何客户端聚合文件。A 的实际出站地址单独指定，可与 A 的域名/CDN 地址不同。
- 独立参数 schema v2，替代早期双 Reality 原型 schema v1。**尚未部署原型的用户直接初始化；已有原型需要重新生成本版参数，不自动迁移。**
- 固定 sing-box **1.14.0**，归档 SHA256 在 `core.lock.json`。支持 Linux amd64/arm64、Python 3.9+、systemd 247+。服务使用 DynamicUser、LoadCredential，仅保留绑定低端口所需能力，不以 root 运行，不启用系统转发/TUN。
- B 和 A 的直出均先解析目标、再拒绝私网目标。IPv4/IPv6 的实际出口由各机系统网络决定；客户端 DNS 接管仍由客户端配置决定。系统 DNS 故障会影响域名访问。
- 聚合产物包括**逐行节点 URI**和**Base64 订阅内容**，不是新建的公网 HTTP 订阅地址。可导入支持的客户端，或放到自己已有的受控 HTTPS 订阅服务。不会把私钥和 SS 对接文件放进订阅目录。

## 1. 准备固定内核

在仓库根目录执行，输出文件必须不存在；已有同版本验证内核可直接复用：

```bash
python3 chain/fetch-core.py --output /tmp/sing-box-chain-core
```

先验证官方归档哈希，再提取预期可执行文件并检查版本；不安装系统服务。正式文件放在仓库外的持久受限目录，以下使用 `/root/chain-state` 举例：

```bash
mkdir -m 700 /root/chain-state
```

## 2. B：初始化与导出

先确认旧脚本生成的配置与聚合文件互相匹配。以下使用旧脚本默认文件位置；`192.0.2.*` 是示例，替换成真实地址。

```bash
python3 chain/chain.py init-exit \
  --binary /tmp/sing-box-chain-core \
  --legacy-config /etc/s-box/sb.json --legacy-links /etc/s-box/jhsub.txt \
  --server 192.0.2.20 --link-port 9443 --entry-source 192.0.2.10 \
  --output /root/chain-state/B.json

python3 chain/chain.py build --binary /tmp/sing-box-chain-core \
  --spec /root/chain-state/B.json --output-dir /root/chain-state/B-release-1
```

B-release-1 内容：

- `config.json`：B 的客户端接入与 SS 接收端完整配置。
- `B-direct.txt` / `B-direct.base64.txt`：单 B 聚合节点。
- `B-link.json`：只传给 A 的对接参数，含敏感密钥。
- `manifest.json`：角色、固定内核版本、分组和监听端口，便于审查。

`--entry-source` 是 A **连接 B 时的实际源 IP**，可重复指定多个精确 IP。与 B 的服务器间地址使用相同地址族，不接受 `/0` 网段。B 的客户端端口和 SS 端口必须分开。

通过已验证主机密钥的 SSH 将 `B-link.json` 传到 A 的受限目录；不用把 B 的完整参数、Reality 私钥或证书私钥传给 A。

## 3. A：导入 B 并生成两组

```bash
python3 chain/chain.py init-entry \
  --binary /tmp/sing-box-chain-core \
  --legacy-config /etc/s-box/sb.json --legacy-links /etc/s-box/jhsub.txt \
  --link /root/chain-state/B-link.json \
  --output /root/chain-state/A.json

python3 chain/chain.py build --binary /tmp/sing-box-chain-core \
  --spec /root/chain-state/A.json --output-dir /root/chain-state/A-release-1
```

输出 `config.json`、`A-direct.txt`、`A-to-B.txt`、对应两个 Base64 文件和 manifest。原客户端凭据保留，链式凭据独立生成。正常刷新配置不必重新初始化；`init-*` 拒绝覆盖已有参数，防止意外轮换链式用户。

即使有多个 CDN/Argo 地址指向同一个原用户，也会生成相应的多个链式分享变体，并保持相同链式凭据。

## 没有原脚本配置时

也支持新建 Reality 客户端入口（SNI 必须选取实际验证可用的握手目标）：

```bash
# B
python3 chain/chain.py init-exit --binary /tmp/sing-box-chain-core \
  --address 192.0.2.20 --port 8443 --sni www.example.com \
  --server 192.0.2.20 --link-port 9443 --entry-source 192.0.2.10 \
  --output /root/chain-state/B.json
# build B 后安全传递 B-link.json，再在 A 上执行
python3 chain/chain.py init-entry --binary /tmp/sing-box-chain-core \
  --address 192.0.2.10 --port 8443 --sni www.example.com \
  --link /root/chain-state/B-link.json --output /root/chain-state/A.json
```

## 4. 部署与旧服务接管

生成、导出阶段不改系统。部署前审查两个 bundle，确认 SSH、端口、防火墙、时间同步和外部隧道服务。正式部署先 B 后 A。

两台服务器分别安装：

```bash
sudo install -d -m 755 /opt/sing-box-chain
sudo install -d -m 700 /etc/sing-box-chain
sudo install -m 755 /tmp/sing-box-chain-core /opt/sing-box-chain/sing-box
sudo install -m 644 chain/sing-box-chain.service /etc/systemd/system/sing-box-chain.service
sudo systemctl daemon-reload
```

以上用于首次安装；不要通过这些命令直接覆盖运行中的内核。旧配置迁移需要停止原 sing-box 服务，因为沿用它的监听端口。先把 `sb` 快捷命令更新为本分支带接管保护的版本：

```bash
sudo install -m 700 sb.sh /usr/bin/sb
# 在 B 上（A 使用 A-release-1/config.json）
sudo python3 chain/deploy.py --config /root/chain-state/B-release-1/config.json --take-over-legacy
```

`--take-over-legacy` 先完成新配置校验和备份，再写接管标记、停止 `sing-box.service`、启动新服务。失败恢复配置和旧服务原来的运行/开机状态；成功禁用旧服务开机启动，旧菜单读到标记后拒绝继续修改。它不会停用 cloudflared、ACME 或 Web 服务。对系统中其他旧脚本副本、定时任务或 root 手工操作无法强制隔离，应撤下旧脚本的代理重启/升级任务，保留所需隧道任务。

新建部署或接管后的日常更新不需要该选项：

```bash
sudo python3 chain/deploy.py --config /root/chain-state/B-release-2/config.json
```

新旧服务不能同时占用相同端口。接管过程中存在短暂断连，安排维护窗口。过程锁、原子配置替换和 `config.previous.json` 用于失败恢复；无法保证断电/SIGKILL 下的跨服务原子事务。检查失败时读取 `systemctl status` 和受限日志，不公开含凭据的内容。

服务稳定运行 5 秒只证明进程状态，**不是端到端成功**。验收通过后再启用开机启动：

```bash
sudo systemctl enable sing-box-chain.service
```

防火墙要求：

- A、B 原客户端端口按协议保留开放；HY2/TUIC 使用 UDP，其他协议通常使用 TCP。
- B 的 SS2022 端口 **TCP 和 UDP 都只允许 A 的实际源 IP**，同时检查 IPv6。
- 来源路由规则是在认证/代理层检查，不能代替防火墙的握手前限制。
- 不清空防火墙，不关闭 SELinux，不改 SSH 规则；服务器间双方保持时间同步。

## 更新、证书续期和密钥

参数是唯一生成源，勿手工编辑运行配置。`build` 要求新的输出目录，一次发布整套文件，避免配置和订阅半更新。文件 0600，bundle 目录 0700。不要提交到 Git。

导入时证书和私钥嵌入配置，低权限服务不需要读取 `/root`。因此续期后必须刷新并重新部署；不会假装自动跟踪旧证书路径：

```bash
python3 chain/chain.py refresh-profile --binary /tmp/sing-box-chain-core \
  --spec /root/chain-state/A.json \
  --legacy-config /etc/s-box/sb.json --legacy-links /etc/s-box/jhsub.txt
```

原接入用户未变时，刷新会保留对应链式凭据；新用户新增链式凭据，删除的原用户也删除对应链式用户。修改源配置中的端口/密码/域名时，源分享链接须同步；证书续期通常不改分享参数，但使用证书指纹的链接也必须更新。然后 build 新目录、deploy。生产中应把刷新与部署接入经过验证的证书续期钩子。

更换 B 对接参数时，A 客户端节点不必变化：

```bash
python3 chain/chain.py update-link --binary /tmp/sing-box-chain-core \
  --spec /root/chain-state/A.json --link /root/chain-state/B-link-new.json
```

在 B 上用 `rotate-link --binary /tmp/sing-box-chain-core --spec /root/chain-state/B.json` 生成新 SS 密钥，build 后把新的 B-link.json 交给 A，再用上面的 update-link。两个客户端直连组与 A 链式客户端凭据都保持不变。

这些修改命令在验证成功后保存 `.previous` 参数备份。SS 密钥轮换需协调 B 与 A，会有切换窗口；当前没有双密钥无缝轮换。SS2022 提供 AEAD 加密与重放防护，**不提供前向保密**。原分享链接的 TLS 参数按原样继承，原来跳过证书验证的链接不会在导入时自动变安全，需在源接入配置中修复。

## 导入 Clash / Mihomo 客户端

独立工具 `chain/export_clash.py` 离线读取逐行节点链接或 Base64 聚合文件，输出完整的 Mihomo YAML 配置。不需要重新初始化、build 或重启服务，也不需要第三方订阅转换网站。Python 3.9+，仅使用标准库。支持本项目五种协议，保留 Reality、VMess WebSocket 的 CDN/Argo 地址与 Host/SNI、TLS 验证设置、HY2 证书指纹和端口跳跃；遇到尚未支持的参数会停止，不静默丢弃。

在 A 上合并单 A 与 A → B 两组（路径换成实际已部署的发布目录）：

```bash
python3 chain/export_clash.py \
  --input /root/chain-state/A-release-1/A-direct.txt \
  --input /root/chain-state/A-release-1/A-to-B.txt \
  --output /root/chain-state/A-clash.yaml
```

在 B 上导出单 B：

```bash
python3 chain/export_clash.py \
  --input /root/chain-state/B-release-1/B-direct.txt \
  --output /root/chain-state/B-clash.yaml
```

每个 `--input` 对应一个手动选择组。只给一个文件就是单组配置；要把三组放到同一份配置中，通过 SSH/SFTP 把 `B-direct.txt` 安全复制到运行导出工具的机器，再追加一个 `--input /实际路径/B-direct.txt`。不要把服务器间专用的 `B-link.json` 当作客户端输入。Base64 文件可直接代替相应 `.txt` 文件。输出文件必须尚不存在，更新时使用新文件名。

将生成的 `.yaml` 通过 SFTP/SCP 下载到用户设备，在客户端的配置/订阅页面选择「从文件导入」（具体名称随客户端不同），启用配置，然后在「代理选择」中选择组，在对应组中选择节点，开启系统代理或按客户端设置启用 TUN。A → B 由 A 上的 sing-box 路由承担，客户端无需配置 relay 或 dialer-proxy。

目标是支持这五种协议的 **Mihomo 内核**，不是所有历史 Clash 内核；例如旧 Clash 不具备完整的 AnyTLS 支持。导出工具现在默认使用国内与局域网直连、其他流量代理的规则及 DNS 策略；通过 `--routing lan-direct` 仅绕过局域网，或 `--routing global` 使用全部代理。`--rules-dir` 可指定 GeoIP/GeoSite 导入快照，规则将内嵌到 YAML；未提供时国内规则使用远程规则集。支持重复的 `--direct-domain` / `--proxy-domain` / `--direct-cidr` / `--proxy-cidr` 例外。DIRECT 表示客户端设备直连，与 A-direct 节点组不同。文件本身不启用 TUN，也不会自动成为订阅 URL；完整的规则导入和 URL 发布见 [独立附件说明](ADDON.md)。

输出权限为 0600，包含节点凭据，请勿提交到 Git。源节点原本跳过证书验证时导出会保留该设置。转换只改变客户端配置格式，不代表已验证真实公网连通性。

格式依据：[Mihomo VLESS](https://wiki.metacubex.one/config/proxies/vless/)、[VMess](https://wiki.metacubex.one/config/proxies/vmess/)、[Hysteria2](https://wiki.metacubex.one/config/proxies/hysteria2/)、[TUIC](https://wiki.metacubex.one/config/proxies/tuic/)、[AnyTLS](https://wiki.metacubex.one/config/proxies/anytls/)。

## 验收与测试

真实两台 VPS：三组分别验证公网出口、TCP/UDP、域名解析和可用 IPv4/IPv6；停止 B 后 A-to-B 必须失败，A-direct 继续可用；不在白名单的主机不能使用 SS 入站，但 B-direct 仍可用。再验证 CDN/Argo 接入、证书刷新和两机重启恢复。

```bash
bash -n sb.sh
python3 -m unittest discover -s chain/tests -v
python3 -u chain/tests/integration.py --binary /tmp/sing-box-chain-core
```

集成测试只使用 loopback：临时 TLS 握手和 echo 服务、两个代理服务、三组客户端。测试夹具为本地 echo 临时移除私网目标拒绝规则，生产配置保留；不同 loopback 源地址验证实际从 A 或 B 出口访问。它不能代替真实防火墙、systemd 权限、CDN/Argo 和运营商线路测试。

原 `sb.sh` 的修复只覆盖部分危险默认行为、下载失败、原配置保留与重启前校验。HTTP/GitLab 订阅、外部脚本、历史内核模板等仍未全面重构；当前新流程不调用旧菜单安装/升级。

官方参考：[SS 入站](https://sing-box.sagernet.org/configuration/inbound/shadowsocks/)、[认证用户路由](https://sing-box.sagernet.org/configuration/route/rule/#auth_user)、[SS2022 协议](https://shadowsocks.org/doc/sip022.html)。
