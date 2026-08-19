# UDS 0x29 无证书 ECS / RSA / ECDSA 性能实验

本目录给出一个可复现的、基于 Tongsuo `libcrypto` 的 UDS Authentication（0x29）四步握手模拟器。它比较：

- `CL-ECS-SM2`：SM2 曲线上的无配对、Schnorr 型无证书 ECS；
- `RSA-2048-PSS+X509`：RSA-2048-PSS/SHA-256 签名和单级 X.509 证书；
- `ECDSA-P256+X509`：ECDSA-P256/SHA-256 签名和单级 X.509 证书。
- `SM2-SM3+X509`：SM2/SM3 签名和由 SM2 根签发的单级 X.509 证书。

这里的“ECS”是本文明确实例化的 certificateless elliptic-curve signature，而不是 Tongsuo 内置的标准签名名称。Tongsuo 提供 SM2 曲线、随机数、SM3、BN/EC 运算、RSA、ECDSA 和 X.509 接口，程序在这些接口上构造并测试协议。

## 项目结构与多设备结果

~~~text
src/                          固定的 C 源码
scripts/make_paper_figures.py 固定的 SVG 绘图程序
scripts/collect_metadata.py   跨平台结构化环境信息采集
run_benchmark.sh              统一的自动构建、测试和绘图入口
results/<device-id>/          各设备的 CSV、控制台输出和环境元数据
figures/<device-id>/          各设备生成的 SVG
build/                        本地编译和 Tongsuo 中间文件（Git 忽略）
~~~

运行脚本默认使用以下信息自动生成设备标识：

~~~text
<用户名>-<短主机名>-<操作系统>-<CPU架构>
~~~

名称会转成小写并清理特殊字符。例如 **alice-labpc-linux-x86_64**。
用户名、主机名和平台信息也会写入该设备的 metadata.json。若不希望将这些信息
上传，可以用不含隐私信息的 DEVICE_ID 覆盖自动名称。

## 一键构建、测试和画图

首次使用前，只需将 Tongsuo 源码放在相邻的 **../Tongsuo** 目录；也可以通过
**TONGSUO_SOURCE** 指定其他位置。随后在任意受支持电脑上执行：

~~~bash
cd uds29-benchmark
./run_benchmark.sh
~~~

统一入口会自动完成：

1. 检测设备标识与平台信息；
2. 在 build/ 中构建并安装本机 Tongsuo（尚未构建时）；
3. 编译 build/uds29_bench；
4. 执行功能负向用例、预热和性能测试；
5. 保存 CSV、控制台输出和结构化环境元数据；
6. 生成三张独立性能子图与 ISO-TP 帧数 SVG。

默认执行 10,000 次测试并预热 1,000 次。可通过环境变量调整：

~~~bash
ITERATIONS=20000 WARMUP=2000 BENCH_CPU=0 ./run_benchmark.sh
~~~

不支持 taskset 的平台不要设置 **BENCH_CPU**。如果需要匿名或稳定的设备名称：

~~~bash
DEVICE_ID=lab-node-01 ./run_benchmark.sh
~~~

查看当前电脑将使用的自动设备名：

~~~bash
./run_benchmark.sh --print-device-id
~~~

也可以使用 Makefile 的等价入口；DEVICE 为空时同样自动识别：

~~~bash
make benchmark
make benchmark DEVICE=lab-node-01 CPU=0 ITERATIONS=10000 WARMUP=1000
~~~

每台设备会生成独立目录：

~~~text
results/<device-id>/results.csv
results/<device-id>/results.txt
results/<device-id>/metadata.json
figures/<device-id>/latency_by_phase.svg
figures/<device-id>/payload_size.svg
figures/<device-id>/latency_payload_tradeoff.svg
figures/<device-id>/isotp_frames.svg
~~~

metadata.json 采用结构化格式，尽可能记录 CPU 型号、架构、核心/线程、缓存与
指令集、标称及采样频率、调频驱动/governor、Boost 状态、内存总量与内存条
型号/频率、操作系统和内核、虚拟化环境、系统负载、编译器与实际编译命令、
benchmark 实际链接库、Tongsuo/OpenSSL/libc/Python 版本及对应 Git 提交。
Linux 上内存条详情依赖 dmidecode 的可用性和当前用户权限；缺失字段会明确记录，
不会中断测试。旧设备目录中的 metadata.txt 是历史格式，不会用其他机器信息补写。

已有 CSV 只需重新画图时，在原设备运行 **make figures**；也可明确指定目录：

~~~bash
make figures
make figures DEVICE=lab-node-01
~~~

也可以直接控制绘图输入和输出文件名：

~~~bash
python3 scripts/make_paper_figures.py input.csv latency.svg --figure latency
python3 scripts/make_paper_figures.py input.csv payload.svg --figure payload
python3 scripts/make_paper_figures.py input.csv tradeoff.svg --figure tradeoff
python3 scripts/make_paper_figures.py input.csv frames.svg --figure isotp
~~~

确认结果后，只提交对应设备目录；build/ 和 Python 缓存会被 Git 忽略：

~~~bash
DEVICE_DIR=$(./run_benchmark.sh --print-device-id)
git add "results/$DEVICE_DIR" "figures/$DEVICE_DIR"
git commit -m "Add benchmark results from $DEVICE_DIR"
git push origin main
~~~

**make clean** 只删除本地 benchmark 可执行文件，不会删除任何设备结果。
可用 **TONGSUO_SOURCE**、**TONGSUO_BUILD**、**TONGSUO_PREFIX**、**JOBS**
和 **CC** 覆盖构建配置。

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
