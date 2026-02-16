# compdbgen - 跨平台编译数据库生成工具

## 概述

compdbgen 是一个跨平台的 `compile_commands.json` 生成工具，通过 ptrace 系统调用拦截来捕获编译命令。

## 支持的平台

### Linux（完整支持）

| 架构 | 状态 | 测试环境 |
|------|------|----------|
| x86_64 | ✅ 完全支持 | Debian/Ubuntu |
| ARM64 | ✅ 代码支持 | 需在 ARM64 硬件上测试 |
| ARM32 | ✅ 代码支持 | 需在 ARM32 硬件上测试 |
| i386 | ✅ 代码支持 | 需在 32位系统上测试 |

### FreeBSD（完整支持）

- 通过 FreeBSD 特有的 ptrace API 实现
- 支持 x86_64 和 i386

## 快速开始

### 编译

```bash
# Linux / FreeBSD
sh build.sh
```

### 基本使用

```bash
# 单文件编译
./compdbgen gcc -c hello.c -o hello.o

# 多文件编译
./compdbgen gcc a.c b.c c.c -o main.elf

# 使用 Makefile
./compdbgen make

# 使用 CMake
./compdbgen cmake --build build/
```

### 输出示例

```json
[
  {
    "directory": "/path/to/project",
    "file": "/path/to/project/hello.c",
    "arguments": ["/usr/lib/gcc/x86_64-linux-gnu/12/cc1", "-quiet", ...]
  }
]
```

## 架构检测

编译时自动检测 CPU 架构：

```c
#if defined(__x86_64__) || defined(__amd64__)
  // x86_64 特定代码
#elif defined(__aarch64__)
  // ARM64 特定代码
#elif defined(__arm__)
  // ARM32 特定代码
#elif defined(__i386__)
  // i386 特定代码
#endif
```

## 在 ARM64 上部署

### 树莓派 4/5 (ARM64)

```bash
# 安装依赖
sudo apt-get update
sudo apt-get install -y gcc make

# 编译
git clone <repo>
cd compdbgen
sh build.sh

# 测试
./compdbgen gcc -c test.c -o test.o
cat compile_commands.json
```

### Apple Silicon Mac (M1/M2/M3)

```bash
# macOS 使用不同的 ptrace 实现
# 建议使用 Docker Linux 容器
docker run --rm -it --platform linux/arm64 \
    -v $(pwd):/workspace ubuntu:22.04

# 在容器内
apt-get update && apt-get install -y gcc
cd /workspace
sh build.sh
./compdbgen gcc -c test.c -o test.o
```

### AWS Graviton

```bash
# EC2 实例 (ARM64)
sudo yum install -y gcc make
# 或
sudo apt-get install -y gcc make

sh build.sh
./compdbgen make
```

## 验证脚本

运行完整的架构测试：

```bash
./test_architecture.sh
```

验证 ARM64 代码正确性：

```bash
./verify_arm64_code.sh
```

## 技术细节

### ptrace 系统调用参数获取

不同架构使用不同的寄存器传递系统调用参数：

**x86_64:**
```
syscall_num = regs.orig_rax
arg0 = regs.rdi
arg1 = regs.rsi
arg2 = regs.rdx
```

**ARM64:**
```
syscall_num = regs.regs[8]  (x8)
arg0 = regs.regs[0]         (x0)
arg1 = regs.regs[1]         (x1)
arg2 = regs.regs[2]         (x2)
```

### vfork 支持

完整支持 Linux 的 `vfork()` 系统调用跟踪：
- `PTRACE_O_TRACEVFORK` - 跟踪 vfork 调用
- `PTRACE_O_TRACEVFORKDONE` - vfork 完成事件

## 限制

1. 需要 `ptrace` 权限（某些容器环境可能受限）
2. 需要 `/proc` 文件系统（Linux）
3. 工作目录通过 `/proc/[pid]/cwd` 获取

## 故障排除

### 问题：无法跟踪进程

```bash
# 检查 ptrace 权限
cat /proc/sys/kernel/yama/ptrace_scope

# 临时允许（需要 root）
echo 0 | sudo tee /proc/sys/kernel/yama/ptrace_scope
```

### 问题：找不到 /proc 文件

确保在 Linux 系统上运行，且 `/proc` 已挂载。

## 贡献

欢迎为其他架构提供测试反馈和代码改进！

## 许可证

BSD 2-Clause License
