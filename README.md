# DNS64 服务（dnslib）+ 样例上游 + Swagger 查询控制台

面向 IPv6 单栈网段（已有 NAT64 出口、旧采集器只配 IPv4 地址）的 DNS64 服务。
收到 UDP AAAA 查询时，按 RFC 6147 思路用 A 记录和配置的 /96 前缀合成 AAAA，
并额外做"两次上游答复终点一致性"校验。

## 组件

| 目录 | 说明 | 容器端口 |
|---|---|---|
| `dns64/` | DNS64 服务（dnslib，采集端仅 UDP；上游支持 UDP+TCP） | 5354/udp |
| `upstream/` | 样例上游 DNS（剧本化应答，UDP/TCP 双栈，覆盖全部场景） | 5353/udp, 5353/tcp |
| `api/` | FastAPI 查询控制台，Swagger UI 在 `/docs` | 8080/tcp |

## 行为规则（`dns64/dns64_server.py`）

1. 原生 AAAA 答复、NXDOMAIN 直接透传（仅改写报文 id）。
2. 名称存在但无 AAAA（NOERROR/NODATA）时，再向上游发 A 查询；
   **两次上游答复指向同一终点**（qname 或其一跳 CNAME 目标）才合成。
3. 支持一跳 CNAME，合成答复中保留该 CNAME（别名）记录。
4. 终点一致但也无 A 记录时，原样返回无记录（NODATA）答复。
5. 合成 TTL = min（无 AAAA 答复的负缓存期 min(SOA TTL, SOA MINIMUM)、
   A 记录剩余 TTL、所用 CNAME 剩余 TTL），各项均从**各自完整答复到达时刻**起算；
   CNAME 记录本身按剩余 TTL 输出。
6. 以下情况返回 SERVFAIL：
   - 上游超时（`UPSTREAM_TIMEOUT`，默认 2.0s）；
   - 两次答复终点不一致；
   - 合成依据过期（任一依据的剩余有效期 < 1s，例如 A 回包太晚，
     负缓存窗口已关闭）。
7. 非 AAAA 查询透传上游答复。
8. **截断（TC=1）回退 TCP**（AAAA、A 及透传路径统一适用）：
   - 先 UDP 询问；UDP 回包带 TC=1（含"截断的空 AAAA 回包"）时，不据此下结论，
     而是向**同一上游、同一问题**用 TCP 重查，只采用完整的 TCP 答复，
     然后才决定是否查 A / 是否合成；
   - UDP 与 TCP **共用该次上游查询的同一时限**：开查时取一次截止时刻，
     TCP 建连、发送、读取长度前缀与每个分段都只使用剩余预算，
     分段到达不会延长总等待；
   - 补查在预算内拿不到完整答复（含 TCP 仍带 TC、连接失败/超时）→ SERVFAIL；
     A 补齐时先前的无 AAAA 答复已过期 → SERVFAIL；
   - 合成前照常核对终点；各 TTL 从对应**完整答复到达时刻**起算。
9. 面向采集端的服务仍然**只监听 UDP**；TCP 仅用于访问上游。

## 启动

```bash
docker compose up --build
```

然后打开 http://localhost:8080/docs ，用 `GET /query` 或
`GET /scenario/{name}` 发起真实查询。

无 Docker 时也可以本地直接跑（三个终端）：

```bash
python3 upstream/mock_upstream.py                 # 127.0.0.1:5353 UDP+TCP
UPSTREAM_HOST=127.0.0.1 python3 dns64/dns64_server.py   # 0.0.0.0:5354/udp
python3 api/main.py                               # http://127.0.0.1:8080/docs
```

## 样例上游剧本（`upstream/mock_upstream.py`）

截断剧本只对 UDP 生效；TCP 始终返回完整、不带 TC 的答复
（`tcdrop` 例外：TCP 挂起不答；`tc-expire` 的 TCP 答复刻意延迟）。

| 场景 / 名字 | AAAA 查询 | A 查询 | 预期结果 |
|---|---|---|---|
| `native` / native.example. | AAAA 2001:db8::53 (ttl 300) | NODATA | 原生透传 |
| `nxdomain` / gone.example. | NXDOMAIN | NXDOMAIN | 透传 |
| `synth` / web.example. | NODATA (neg 30s) | A 192.0.2.10 (ttl 60) | 合成 64:ff9b::c000:20a，ttl≈30 |
| `alias` / alias.example. | CNAME web.example. + NODATA | CNAME + A | 保留别名并合成，ttl≈min(30,60,45) |
| `noaddr` / noaddr.example. | NODATA (neg 20s) | NODATA | 沿用无记录答复 |
| `multi` / multi.example. | NODATA (neg 30s) | A×2 (ttl 120/25) | 合成两条，ttl≈25 |
| `slow` / slow.example. | NODATA (neg 1s) | A 延迟 1.5s 才到 | 依据过期 → SERVFAIL |
| `flap` / flap.example. | CNAME ep-a + NODATA | CNAME ep-b + A | 终点不一致 → SERVFAIL |
| `timeout` / drop.example. | 不应答 | 不应答 | 上游超时 → SERVFAIL |
| `tc_many` / tc-many.example. | UDP 空回包+TC；TCP 完整 NODATA | UDP 仅 1 条 A+TC；TCP 给全 3 条 | 两次回退后合成 3 条完整 AAAA |
| `tc_empty` / tc-empty.example. | UDP 截断空 AAAA（无 SOA）+TC；TCP 完整 NODATA | A 192.0.2.50 | 空截断不误判 NODATA，TCP 补查后合成 |
| `tc_expire` / tc-expire.example. | UDP+TC，TCP 延迟 1.5s 的完整 NODATA (neg 1s) | A 192.0.2.60 | 补查完成时依据已过期 → SERVFAIL |
| `tc_drop` / tcdrop.example. | UDP 空回包+TC；TCP 挂起不答 | — | 共享预算内拿不到完整答复 → SERVFAIL |

## 配置（环境变量）

DNS64 服务：`UPSTREAM_HOST` `UPSTREAM_PORT` `DNS64_PREFIX`（默认 64:ff9b::/96）
`UPSTREAM_TIMEOUT` `LISTEN_HOST` `LISTEN_PORT` `LOG_LEVEL`。

API：`DNS64_HOST` `DNS64_PORT` `PORT`。

## 测试

```bash
python3 -m pytest tests/ -v
```

`tests/test_dns64_unit.py`：地址映射、终点提取、负缓存期、TTL 最小值、
过期判定等纯逻辑；`tests/test_tc_fallback_unit.py`：UDP→TCP 回退、共享
截止时刻、TCP 分段不延长等待等传输机制；`tests/test_e2e.py`：真实
UDP/TCP 起服打满全部场景（采集端仍只用 UDP）。

## 已知限制 / TODO

- 采集端仅 UDP；访问上游支持 UDP，并在 TC=1 时回退 TCP，但仍无多上游/其他重试。
- 无缓存层：每个客户端查询都会真实发起上游查询（TTL 只用于当次合成）。
- 只支持一跳 CNAME；更长的链按"无 A"处理。
- 无 AAAA 答复缺 SOA 时负缓存期按 0 处理，合成会判过期（从严）。
- A 查询发向原始 qname，由上游完成链式解析。
