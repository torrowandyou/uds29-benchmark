# UDS 0x29 无证书 ECS / RSA / ECDSA 性能实验

本目录给出一个可复现的、基于 Tongsuo `libcrypto` 的 UDS Authentication（0x29）四步握手模拟器。它比较：

- `CL-ECS-SM2`：SM2 曲线上的无配对、Schnorr 型无证书 ECS；
- `RSA-2048-PSS+X509`：RSA-2048-PSS/SHA-256 签名和单级 X.509 证书；
- `ECDSA-P256+X509`：ECDSA-P256/SHA-256 签名和单级 X.509 证书。
- `SM2-SM3+X509`：SM2/SM3 签名和由 SM2 根签发的单级 X.509 证书。

这里的“ECS”是本文明确实例化的 certificateless elliptic-curve signature，而不是 Tongsuo 内置的标准签名名称。Tongsuo 提供 SM2 曲线、随机数、SM3、BN/EC 运算、RSA、ECDSA 和 X.509 接口，程序在这些接口上构造并测试协议。

## 构建与运行

```bash
cd uds29-benchmark
JOBS=4 ./build_tongsuo.sh
make clean all
LD_LIBRARY_PATH=build/tongsuo-install/lib \
  taskset -c 0 ./build/uds29_bench \
  --iterations 10000 --warmup 1000 --csv results.csv
```

若平台没有 `taskset`，可去掉该命令。`build_tongsuo.sh` 使用相邻的 `../Tongsuo` 源码，并只把产物写到本目录的 `build/`。可用 `TONGSUO_SOURCE`、`TONGSUO_BUILD`、`TONGSUO_PREFIX` 和 `JOBS` 覆盖默认值。

## ECS 构造和协议映射

设 SM2 曲线生成元为 `P`、阶为 `q`，KGC 主私钥为 `s`，主公钥为 `Ppub=sP`。KGC 为身份 `ID` 随机选择 `r`：

```text
R  = rP
h1 = SM3("UDS29-ECS-H1-v1" || encode(ID,R,Ppub)) mod q
d  = r + h1*s mod q                  # 部分私钥
```

用户选择秘密值 `x`，公开 `X=xP`，完整私钥为 `(x,d)`，0x2901 公共信息为 `(UUID,X,R)`。ECU 预置 `Ppub`，在 0x2901 计算并缓存：

```text
Q = X + R + h1*Ppub = (x+d)P
```

对 32 字节随机挑战 `chal`，客户端选择一次性随机数 `k`：

```text
U  = kP
h2 = SM3("UDS29-ECS-H2-v1" || encode(UUID,X,R,chal,U)) mod q
z  = k + h2*(x+d) mod q
signature = (U,z)
```

ECU 检查 `zP == U + h2*Q`。所有哈希字段均有 32 位长度前缀和域分离串，避免拼接歧义；UUID、公钥信息、挑战和承诺点都被签名绑定。

四个报文按以下方式计数（包含 SID/子功能/结果字节，不含 ISO-TP、CAN、链路层头部）：

| 报文 | CL-ECS | RSA/ECDSA/SM2 + X.509 |
|---|---:|---:|
| 0x2901 | `SID,subfn,UUID,X,R` | `SID,subfn,UUID,leaf_cert_DER` |
| 0x6901 | `SID,subfn,chal[32]` | 相同 |
| 0x2903 | `SID,subfn,U,z` | `SID,subfn,signature` |
| 0x6903 | `SID,subfn,result` | 相同 |

## 计时边界

密钥生成、KGC 部分私钥提取、根证书/叶证书签发属于生产或注册阶段，不计入在线握手。每轮在线计时包含：

1. `2901_credential`：ECS 解码/曲线点校验/计算 `Q`；传统方案 DER 解码、单级证书链验证和提取公钥；
2. `6901_challenge`：`RAND_bytes` 生成 32 字节挑战；
3. `2903_sign`：对挑战签名；
4. `6903_verify`：验证挑战签名。

三种证书方案的叶证书 CN 是 0x2901 所传 UUID 的十六进制形式，ECU 在证书链验证后检查两者相等；0x2903 实际签名输入为 `UUID || chal`。SM2 挑战签名使用标准 16 字节用户 ID `1234567812345678`。因此各证书方案的身份绑定强度与 ECS 测试路径可比，而且该绑定不增加 0x2903 线长。

每种方案先预热，再在每轮中轮换执行顺序。计时使用 `CLOCK_MONOTONIC_RAW`。程序报告均值、中位数、P95 和样本标准差；虚拟化环境有调度长尾时应以中位数和 P95 为主。

程序启动时还会对每种方案执行篡改挑战的负向用例，任何错误接受都会令程序失败。当前实验结果与解释见 [REPORT.md](REPORT.md)。

## 适用边界

- 实验测的是密码计算和实际编码长度，不模拟 CAN 仲裁、总线负载、P2/P2* 定时、网络往返延迟、HSM/安全芯片或证书吊销在线查询。
- 传统方案每次会话验证叶证书；若 ECU 安全地缓存已验证证书，可用结果中的 `2903_sign + 6903_verify` 观察热会话签名成本。
- ECS 的安全性证明、KGC 注册信道、主密钥保护、撤销/更新机制、抗公钥替换证明和正式协议编码需要在论文中单独论证。本程序是性能原型，不是量产安全实现。
- ECDSA DER 签名长度随 `(r,s)` 变化，报文字节数采用观测到的最大值；ECS 使用固定 65 字节压缩编码。
