# 结果目录状态

当前报告的权威数据集是：

`root-c202605211665597-linux-x86_64`

该目录使用 GM/T 0130-2023 CL-ECS-SM2 和 RSA-3072-PSS+X509，在香港 VPS
完成 1,000 次预热与 10,000 次正式测量。其 CSV 中 RSA 公钥和签名均为
384 字节，benchmark 元数据指向干净提交 `65afb38`。

其他目录保留为历史或部分过期数据：

- `wangguilin-wangguilindemac-mini-darwin-arm64`：标准 ECS，但 RSA 仍为
  2048 位；
- `abc-46437092e7f1-linux-aarch64`：早期自定义 ECS/Schnorr 与 RSA-2048；
- `apple-virtualized-aarch64`：早期自定义 ECS/Schnorr 与 RSA-2048，使用旧版
  metadata。

不得把历史文件中的方案名称或测量值直接改写成 RSA-3072。设备完成当前代码重测
后，才可替换其 CSV、控制台输出、元数据和对应图表。详细说明见
[多设备结果状态与可比性说明](../docs/MULTI_DEVICE_ANALYSIS.md)。
