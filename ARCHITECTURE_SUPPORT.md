# 跨平台架构支持

## 支持的架构

compdbgen 现在支持以下 CPU 架构：

### Linux 平台

| 架构 | 系统调用号寄存器 | 参数寄存器 | 状态 |
|------|-----------------|-----------|------|
| x86_64 (AMD64) | `orig_rax` | `rdi`, `rsi`, `rdx` | ✅ 已测试 |
| ARM64 (AArch64) | `x8` | `x0`, `x1`, `x2` | ⚠️ 需测试 |
| ARM32 | `r7` | `r0`, `r1`, `r2` | ⚠️ 需测试 |
| i386 | `orig_eax` | `ebx`, `ecx`, `edx` | ⚠️ 需测试 |

### FreeBSD 平台

- x86_64 和 i386 架构通过 FreeBSD 特有的 ptrace API 支持

## 实现细节

### 系统调用约定

不同架构有不同的系统调用约定：

#### x86_64 Linux
- 系统调用号: `orig_rax`
- 参数 1-6: `rdi`, `rsi`, `rdx`, `r10`, `r8`, `r9`

#### ARM64 Linux
- 系统调用号: `x8`
- 参数 1-6: `x0`, `x1`, `x2`, `x3`, `x4`, `x5`

#### ARM32 Linux
- 系统调用号: `r7`
- 参数 1-6: `r0`, `r1`, `r2`, `r3`, `r4`, `r5`

#### i386 Linux
- 系统调用号: `orig_eax`
- 参数 1-6: `ebx`, `ecx`, `edx`, `esi`, `edi`, `ebp`

## 在 ARM64 上测试

### 方法 1: 使用 QEMU 用户模式

```bash
# 安装 ARM64 交叉编译工具链
sudo apt-get install gcc-aarch64-linux-gnu

# 交叉编译
aarch64-linux-gnu-gcc -static -o compdbgen_arm64 \
    -I. -Icjson main.c mainloop.c cjson/cJSON.c cjson/cJSON_Utils.c

# 使用 QEMU 运行
qemu-aarch64 ./compdbgen_arm64 cc -c test.c -o test.o
```

### 方法 2: 使用 Docker ARM64 容器

```bash
# 拉取 ARM64 镜像
docker pull --platform linux/arm64 ubuntu:22.04

# 运行 ARM64 容器
docker run --rm -it --platform linux/arm64 \
    -v $(pwd):/workspace ubuntu:22.04 bash

# 在容器内编译和测试
apt-get update && apt-get install -y gcc
cd /workspace
sh build.sh
./compdbgen cc -c test.c -o test.o
```

### 方法 3: 使用真实 ARM64 硬件

在树莓派、Apple Silicon Mac 或云服务器（AWS Graviton、Ampere等）上测试。

## 常见问题

### Q: 如何知道当前架构是否被支持？

A: 编译时会自动检测。如果不支持的架构，会得到编译错误。

### Q: 为什么 ARM64 需要 `<asm/ptrace.h>` 而不是 `<sys/user.h>`？

A: ARM64 Linux 使用 `user_pt_regs` 结构体，定义在 `<asm/ptrace.h>` 中，而 x86 使用 `user_regs_struct`，定义在 `<sys/user.h>` 中。

### Q: 如何添加新架构支持？

A: 需要修改三个地方：
1. 添加头文件包含（如果需要）
2. 在 `enter_syscall()` 中添加寄存器结构体类型定义
3. 在两个地方添加架构特定的寄存器访问代码（syscall号和参数）

## 性能影响

跨平台支持通过条件编译实现，在编译时确定，**运行时无性能损失**。
