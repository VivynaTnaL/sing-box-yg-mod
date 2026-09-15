# 独立链式附件：实现与验证

本分支的交接格式是标准 sing-box 配置。配置生成、附件导入、运行管理和客户端订阅分别有独立入口；使用方法见 [ADDON.md](../chain/ADDON.md)。

## 约定需求

| 需求 | 实现 | 已执行的验证 |
| --- | --- | --- |
| 不依赖原配置生成器 | 导入服务端入站及证书，保存独立快照；公网地址由用户补充 | 删除源配置及证书后，五协议仍可构建与导出 |
| 附件与原运行时独立 | 独立端口、凭据、内核、服务、状态；A 只经 B 出站 | 原服务与附件并行的真实 TCP/UDP 流量；B 故障、错误密钥与停止附件均不影响原服务 |
| 方便回到原服务 | 新模式只需停止附件；旧接管版有显式恢复入口 | 隔离服务管理测试覆盖配置校验、恢复、失败回滚和标记保留 |
| 原脚本生成与运行拆分 | 旧模板抽为纯模块，安装分阶段；独立只生成向导和参数文件入口 | 两套模板与原内容一致；生成失败不调用部署；脱离仓库的快捷入口测试 |
| 简化操作 | `sb-chain` 中文菜单、五协议生成向导，CLI 留给自动化 | 菜单复用同一命令处理；向导与参数入口测试 |
| 服务器 URL 订阅 | Mihomo、sing-box、URI、Base64 四类文件；随机口令、稳定 URL、HTTP/HTTPS | 真实 GET/HEAD、证书校验、更新、旧口令失效、私密文件不可访问 |
| 国内和局域网排除 | 客户端域名/IP 规则与 DNS 分流；支持直连和代理例外 | 三模式完整规则通过两客户端内核检查；真实 TCP/UDP 选择直连和代理出口 |
| 自动获取 GeoIP/GeoSite | 同一 GitHub release 的两个固定资产，大小与 SHA-256 校验，转换为内嵌 CN 规则 | 真实两库下载和转换；损坏、半下载、限流和转换失败测试 |
| 规则自动更新 | 首次构建自动获取，手动刷新和独立每日 timer，失败保留有效快照 | 定时器隔离测试；版本不变复用；更新不重启代理、不发布待部署凭据 |
| 操作失败可恢复 | 服务配置、订阅 manifest 与管理状态联合回滚 | 最后一次状态写入失败仍恢复原服务配置、订阅和 metadata |

## 复现命令

在完整仓库执行，替换实际内核路径：

```bash
python3 -m unittest discover -s tests
SB_TEST_CORE=/path/to/sing-box-1.14.0 CHAIN_TEST_CORE=/path/to/sing-box-1.14.0 \
  python3 -m unittest discover -s chain/tests
python3 chain/tests/integration_addon.py --binary /path/to/sing-box-1.14.0
python3 chain/tests/integration_publish_tls.py
bash -n sb.sh lib/sb-config.sh lib/sb-install.sh sb-chain
```

网络集成测试只绑定回环地址，全部文件和进程使用临时目录，不调用真实系统服务。本轮还使用 GitHub 真实数据，在 sing-box 1.14.0 和 Mihomo 1.19.31 上检查了三种分流模式。

## 验证边界

代码实现和上述本机验证已经完成。没有据此将工作区改动安装到当前服务器，也没有完成两台真实 VPS 与手机客户端的公网验收。目标机器的 systemd、端口开放、NAT 来源、域名/证书和客户端内核支持，仍要在实际部署时确认。

附件不接管原 ACME、WARP、CDN 或 Argo 的运行流程。导入的证书是快照，续期后需要重新导入；纯 URI 订阅不携带分流规则。sing-box 客户端文件默认提供 mixed 入口，TUN/手机客户端需按客户端入口要求接入。后台安装支持 systemd 247+；独立生成和导出不要求启动后台服务。
