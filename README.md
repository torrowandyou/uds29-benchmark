# UDS 0x29 无证书 ECS / RSA / ECDSA 性能实验

本目录给出一个可复现的、基于 Tongsuo `libcrypto` 的 UDS Authentication（0x29）四步握手模拟器。它比较：

- `CL-ECS-SM2`：按 GM/T 0130-2023 实现的无证书 SM2 签名；
- `RSA-3072-PSS+X509`：RSA-3072-PSS/SHA-256 签名和单级 X.509 证书；
- `ECDSA-P256+X509`：ECDSA-P256/SHA-256 签名和单级 X.509 证书。
- `SM2-SM3+X509`：SM2/SM3 签名和由 SM2 根签发的单级 X.509 证书。

Tongsuo 提供 SM2 曲线、随机数、SM3、BN/EC 运算、RSA、ECDSA 和 X.509 接口，程序在这些接口上实现并测试协议。无证书方案的密钥生成、公钥恢复及数字签名遵循 GM/T 0130-2023，确定性测试采用该标准附录 A 的参考数据。

本实验按约 128 位经典安全强度选择对比参数。依据
[NIST SP 800-57 Part 1 Rev.5](https://doi.org/10.6028/NIST.SP.800-57pt1r5)，
256 位椭圆曲线与 3072 位 RSA 处于同一安全强度档，因此 RSA 基线使用
3072 位密钥；RSA-2048 约为 112 位安全强度，不再作为主对比方案。

## 项目结构与多设备结果

~~~text
src/                          benchmark 与 GM/T 0130-2023 实现
tests/                        标准附录 A 确定性测试
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

## clangd / code-server 代码导航

在同时包含 `Tongsuo` 和 `uds29-benchmark` 的上级工作区中执行：

~~~bash
cd uds29-benchmark
make compile-db
~~~

该命令会根据当前 Makefile 和本机 Tongsuo 构建配置，在上级工作区生成合并的
`compile_commands.json`。数据库同时包含 benchmark 和 Tongsuo 源文件，因此
clangd 可以使用真实的头文件路径、宏定义和编译选项，并支持跨项目跳转到 Tongsuo
实现。更换编译器、Tongsuo 配置或构建目录后应重新执行该命令。生成完成后，在
code-server 命令面板执行 `clangd: Restart language server`；首次建立 Tongsuo
后台索引可能需要一些时间。

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

当前权威数据与历史结果的可比性说明见
[多设备结果状态与可比性说明](docs/MULTI_DEVICE_ANALYSIS.md)，各结果目录的状态
也记录在 [results/README.md](results/README.md)。

metadata.json 采用结构化格式，尽可能记录 CPU 型号、架构、核心/线程、缓存与
指令集、标称及采样频率、调频驱动/governor、Boost 状态、内存总量与内存条
型号/频率、操作系统和内核、虚拟化环境、系统负载、编译器与实际编译命令、
benchmark 实际链接库、Tongsuo/OpenSSL/libc/Python 版本及对应 Git 提交。
Linux 上内存条详情依赖 dmidecode 的可用性和当前用户权限；缺失字段会明确记录，
不会中断测试。macOS 的硬件序列号、Platform UUID 和 Provisioning UDID 会在写入
结果前过滤。旧设备目录中的 metadata.txt 是历史格式，不会用其他机器信息补写。

当前 RSA-3072 方案生成的 CSV 只需重新画图时，可在原设备运行
**make figures**；也可明确指定目录。RSA-2048 历史 CSV 的方案键与当前绘图脚本
不同，不能直接重画，必须先在对应设备使用当前代码重新测试。

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

设 SM2 曲线生成元为 `G`、阶为 `n`，KGC 主私钥为 `ms`，主公钥为 `Ppub=[ms]G`。用户选择秘密值 `d'` 并向 KGC 提交 `U=[d']G`。KGC 按标准计算用户杂凑值 `HA`，选择随机数 `w`：

~~~text
HA     = SM3(ENTL || ID || a || b || xG || yG || xPpub || yPpub)
W      = [w]G + U
lambda = SM3(xW || yW || HA) mod n
t      = (w + lambda*ms) mod n
d      = (t + d') mod n
~~~

若 `d=0` 则重新生成。最终用户私钥是 `d`，声明公钥是 `W`。0x2901 公共信息为 `(UUID,W)`；ECU 预置 `Ppub`，并在 0x2901 恢复实际公钥：

~~~text
P = W + [lambda]Ppub = [d]G
~~~

对 32 字节随机挑战 `chal`，签名摘要和标准 SM2 签名为：

~~~text
e = SM3(HA || xW || yW || chal)
signature = SM2-SIGN(e, d) = (r,s)
~~~

ECU 使用恢复的实际公钥 `P` 执行标准 SM2 验签。报文中的点使用 33 字节压缩编码；标准内部哈希仍使用固定 32 字节的仿射坐标。签名在线编码为固定 64 字节 `r || s`。

四个报文按以下方式计数（包含 SID/子功能/结果字节，不含 ISO-TP、CAN、链路层头部）：

| 报文 | CL-ECS | RSA/ECDSA/SM2 + X.509 |
|---|---:|---:|
| 0x2901 | `SID,subfn,UUID,W` | `SID,subfn,UUID,leaf_cert_DER` |
| 0x6901 | `SID,subfn,chal[32]` | 相同 |
| 0x2903 | `SID,subfn,r,s` | `SID,subfn,signature` |
| 0x6903 | `SID,subfn,result` | 相同 |

## 计时边界

密钥生成、KGC 部分私钥提取、根证书/叶证书签发属于生产或注册阶段，不计入在线握手。每轮在线计时包含：

1. `2901_credential`：ECS 解码/曲线点校验/按标准恢复实际公钥 `P`；传统方案 DER 解码、单级证书链验证和提取公钥；
2. `6901_challenge`：`RAND_bytes` 生成 32 字节挑战；
3. `2903_sign`：对挑战签名；
4. `6903_verify`：验证挑战签名。

三种证书方案的叶证书 CN 是 0x2901 所传 UUID 的十六进制形式，ECU 在证书链验证后检查两者相等；0x2903 实际签名输入为 `UUID || chal`。SM2 挑战签名使用标准 16 字节用户 ID `1234567812345678`。因此各证书方案的身份绑定强度与 ECS 测试路径可比，而且该绑定不增加 0x2903 线长。

每种方案先预热，再在每轮中轮换执行顺序。计时使用 `CLOCK_MONOTONIC_RAW`。程序报告均值、中位数、P95 和样本标准差；虚拟化环境有调度长尾时应以中位数和 P95 为主。

程序启动时还会对每种方案执行篡改挑战的负向用例，任何错误接受都会令程序失败。当前实验结果与解释见 [REPORT.md](REPORT.md)。

标准附录 A 一致性测试可独立执行：

~~~bash
make test
~~~

测试固定使用附录 A 的 `ms`、`d'`、`w` 和签名随机数 `k`，逐项比较 `Ppub`、`HA`、`W`、`d`、实际公钥 `P` 和签名 `(r,s)`，并检查篡改消息不能通过验签。

## 适用边界

- 实验测的是密码计算和实际编码长度，不模拟 CAN 仲裁、总线负载、P2/P2* 定时、网络往返延迟、HSM/安全芯片或证书吊销在线查询。
- 传统方案每次会话验证叶证书；若 ECU 安全地缓存已验证证书，可用结果中的 `2903_sign + 6903_verify` 观察热会话签名成本。
- KGC 注册信道、主密钥保护、撤销/更新机制、身份授权策略和正式 UDS 数据标识符编码仍需在量产设计中补充。本程序是性能原型，不是量产安全实现。
- ECDSA DER 签名长度随 `(r,s)` 变化，报文字节数采用观测到的最大值；ECS 使用固定 64 字节 `r || s` 编码。
