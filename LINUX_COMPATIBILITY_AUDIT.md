# CSA Linux 兼容性全面审计

> 审计日期：2026-09-06
> 审计提交：`24e3dab6bb8f881b31061a8b083fb9a4b0363feb`
> 结论对象：CSA Manager `0.1.8` 当前源码、npm 分发、激活/回退链路与 CI 证据

## 1. 结论摘要

当前版本只能认为“CSA Manager 二进制能够在部分 Linux 环境构建和启动”，**不能认为 Linux 上的完整安装、接管、patched runtime 绑定和回退链路已经可用**。

存在两个发布阻断问题：

1. 在线下载的 patched Codex 文件没有 Unix 执行位，标准 Linux 文件系统上会在 prepare 阶段被拒绝；
2. Linux 官方 runtime 发现被代码直接禁用，随后又允许 patched Codex 在没有 runtime 绑定的情况下启动。

此外，Linux 没有持久化 `PATH` 接管、版本检测只有单点命令执行、GNU/musl target 映射在不同命令中不一致，Unix 信号语义、非 UTF-8 路径、Vite+、`noexec` 文件系统和 Linux 用户提示也存在缺口。当前 CI 主要证明“能编译”和“npm launcher 能找到平台二进制”，没有证明 Linux 端到端产品行为。

**建议在修复 LNX-01～LNX-04 并建立 Linux 端到端门禁前，将文档中的 Linux 支持标为 experimental / manager-only，而不是完整支持。**

## 2. 审计范围与验证环境

### 2.1 检查范围

- Rust：`src/detect.rs`、`src/manager.rs`、`src/activation.rs`、`src/process.rs`、`src/state.rs`、`src/isolation.rs`、`src/online.rs`、CLI 和 UI；
- npm：meta launcher、平台包映射、打包脚本和 launcher 测试；
- 发布：Linux x64/arm64 support matrix、CI、release 与 npm publication workflow；
- 文档：README、reference、operations、development、architecture；
- 实机只读检查：现有官方 `@openai/codex` npm 安装的 launcher、package metadata、platform marker 和 runtime 文件。

### 2.2 本地环境

- Fedora Linux 44，x86_64，glibc；
- Rust/Cargo `1.95.0`，本机构建 target `x86_64-unknown-linux-gnu`；
- Node `22.23.1`，npm `12.0.2`；
- 官方 Codex `0.153.4`，npm 全局安装；
- 官方 launcher：`.../@openai/codex/bin/codex.js`；
- 官方 platform root：`.../@openai/codex-linux-x64/vendor/x86_64-unknown-linux-musl`。

实机 `csa doctor --json` 能识别 launcher 版本，但输出中 `official.native` 为 `null`，`official.runtime` 整个字段缺失，和静态分析一致。

### 2.3 已执行验证

- `cargo fmt --all -- --check`：通过；
- `cargo clippy --workspace --all-targets --all-features -- -D warnings`：通过；
- `cargo test --all-targets`：42 个测试通过；
- Node 两个脚本的语法检查：通过；
- `python3 scripts/test_release_tools.py`：通过；
- 合成 npm symlink、bun/pnpm 风格可执行 wrapper：三者均能被当前 launcher 搜索识别；
- 非 UTF-8 manager root：复现 JSON stdout 被写成半截后序列化失败；
- Unix `OpenOptions::create_new(true)` 默认创建下载文件：实测权限为 `0644`；
- `node scripts/test_npm_launcher.mjs`：本地受限执行环境禁止测试中的嵌套 `spawnSync`（`EPERM`），因此此项不能作为通过或失败证据。

本次没有修改官方 Codex，没有执行匹配 patched Release 的真实在线安装，也没有修改用户 shell profile 或持久化 `PATH`。

## 3. 问题总表

| ID | 优先级 | 状态 | 影响 |
| --- | --- | --- | --- |
| LNX-01 | P0 | 已确认 | Linux 在线安装的下载产物无执行位，prepare 必然失败 |
| LNX-02 | P0 | 已确认 | Linux runtime 永远不绑定，patched overlay 缺资源且完整性校验失效 |
| LNX-03 | P1 | 已确认 | Linux 版本检测依赖一次 `launcher --version`，无 metadata/native 交叉校验 |
| LNX-04 | P1 | 已确认 | Linux `install`/`plug` 不持久化 `PATH`，仍可报告安装成功 |
| LNX-05 | P2 | 已确认 | GNU→musl 映射只用于在线发现，doctor/local prepare 行为不一致 |
| LNX-06 | P2 | 部分确认 | 标准 npm/bun/pnpm wrapper 可发现，但 runtime 来源和 opaque shim 未解决 |
| LNX-07 | P2 | 已确认 | package-manager 模型落后于上游，缺 Vite+ 和相应环境清理 |
| LNX-08 | P2 | 已确认 | Unix 子进程信号退出被压成 code 1，npm launcher 也不转发定向信号 |
| LNX-09 | P2 | 已确认 | 非 UTF-8 Linux 路径会破坏 JSON 输出，PATH 证据 hash 还会有损 |
| LNX-10 | P2 | 条件性 | 默认数据目录若位于 `noexec` 挂载，安装可成功但 shim/artifact 无法执行 |
| LNX-11 | P2 | 已确认 | Linux UI/文档仍输出 Windows 命令和错误的“新终端已就绪”结论 |
| LNX-12 | P1 | 已确认 | CI 没有 Linux runtime/安装/接管/回退端到端门禁，且未测试声明的 Node 18 |

## 4. 详细问题与解决方案

### LNX-01（P0）：在线下载的 patched 二进制没有执行位

**证据**

- `src/online.rs:928-932` 使用普通 `OpenOptions` 创建 Release asset；Unix 默认请求 mode `0666`，不会产生任何执行位；
- 下载完成到 `src/online.rs:1009` 之间只做 flush、fsync、size 和 SHA-256 校验，没有 `chmod`；
- `src/manager.rs:470` 随即调用 `reject_same_file()`，最终进入 `src/detect.rs:515-517` 的 `fingerprint()`；
- `src/detect.rs:664-668` 要求至少一个 `0o111` 执行位，否则报 `unsafe_executable_path`；
- 本机用相同 Rust `OpenOptions` 行为创建文件，权限稳定复现为 `0644`。umask 只能继续去除权限，不能补上执行位。

**影响**

标准 Linux 上通过网络下载原始 `codex` asset 后，`csa install` 会在 prepare 阶段失败。npm 包中的 Manager 二进制虽然在 staging 时被设为 `0755`，但这不能修复后来下载的 patched Codex。

**解决方案**

1. 将“普通 Release 文件下载”和“可执行 artifact 落盘”分成两个明确步骤；
2. SHA-256/size 校验通过后，仅对已验证的当前平台 executable 调用 Unix `set_permissions`，至少设置为 `0755`（或按项目策略设置为只读可执行）；
3. 再次 fsync 文件和父目录，然后调用 `fingerprint()` 验证“内容、大小、可执行性”三者；
4. 不要给 catalog、descriptor、checksum 等普通下载文件增加执行位；
5. 新增测试：下载后的 mode 包含 `0o111`、可真实启动、chmod 失败时不发布 state/shim、缓存命中仍验证可执行性。

### LNX-02（P0）：Linux 官方 runtime 发现和 fail-closed 约束全部缺失

**证据**

- `src/detect.rs:109-117` 只在 Windows 调用 runtime discovery，非 Windows 直接令 `discovered = None`；
- 因此 Linux 正常路径只记录 launcher hash/version，`official.native` 和 `official.runtime` 都为空；
- `src/manager.rs:851-860` 在 runtime 缺失时，仅 Windows patched 模式报错，Linux 直接 `Ok(command)`；
- `src/manager.rs:921-928` 同样只在 Windows 要求完整 runtime；
- `tests/manager_core.rs:1001-1002` 明确断言非 Windows 转发环境为空，`tests/manager_core.rs:1379` 还把“schema 2 的 Linux runtime 不是对象”固化成预期；
- 当前官方 Linux 包实际具备可验证结构：`package.json`、`codex-package.json`、`bin/codex`、`bin/codex-code-mode-host`、`codex-resources/bwrap`、`codex-resources/zsh/bin/zsh`、`codex-path/rg`。

**影响**

- patched executable 被放在 CSA 自己的 content-addressed 目录中，旁边没有官方 helper/resource；
- `CSA_CODEX_OFFICIAL_PACKAGE_ROOT`、`CODEX_MANAGED_PACKAGE_ROOT` 和正确的 package-manager marker 不会被设置；
- code-mode host、sandbox、`rg`、bundled shell 等功能可能找不到；
- helper、marker、managed package metadata 或 native binary 漂移不会使 prepared state 失效；
- 工具宣称的“patched overlay + verified official runtime”和“每次启动重新验证所有 runtime component”在 Linux 上不成立。

**解决方案**

1. 把 `discover_windows_runtime` 重构为通用 `discover_official_runtime(platform_spec, ...)`，平台差异只保留 target、文件名和必需资源清单；
2. Linux x64/arm64 使用对应的 musl runtime target，兼容标准布局：
   - meta package 内嵌 optional dependency；
   - meta package 同级 platform package；
   - legacy `vendor/<target>` fallback；
   - npm、bun、pnpm 的 symlink/store 布局；
3. 校验 `codex-package.json` 的 `layoutVersion`、plain version、target、variant、entrypoint、resource/path 目录，并与 managed `@openai/codex/package.json` 交叉一致；
4. 记录并验证 native binary、marker、managed package manifest 和 Linux 必需 helpers；对可执行 helper 使用会检查 execute bit 的 fingerprint 路径；
5. Linux patched 模式必须和 Windows 一样：runtime 缺失即 `official_runtime_incomplete` / `state_upgrade_required`，不得无绑定启动；
6. 将旧的 Linux `runtime: None` state 视为必须 reinstall 的 legacy state；
7. 增加 npm、bun、pnpm、nested/sibling/legacy、ambiguous、missing helper、wrong target、chmod drift 的 Linux fixture tests。

### LNX-03（P1）：Linux version 检测依赖单点 `codex --version`

**证据**

- `src/detect.rs:102-107` 在非 Windows 上无条件执行 launcher 的 `--version`；
- `src/detect.rs:576-589` 只有这一个命令结果来源；
- `src/detect.rs:591-610` 要求整个输出严格等于一行 `codex-cli X.Y.Z`；
- Linux 已安装 package 同时存在 managed `package.json` 的 plain version 和 platform `codex-package.json` 的 plain version，但代码完全不读；
- launcher 缺 Node、optional platform package 损坏、wrapper 添加 stdout 提示、临时环境异常时，即使 metadata/native 仍可定位，也会把官方安装整体判为不可检测。

**影响**

检测脆弱，并且无法证明 launcher、managed package、platform marker 和 native executable 属于同一个版本。当前上游把提示写到 stderr 时恰好可工作，但这是实现偶然性，不是可靠契约。

**解决方案**

1. 先通过 LNX-02 的 package discovery 读取 managed package version 与 marker version；
2. 再分别执行 launcher 和 native `--version` 作为可运行性检查；
3. 四个来源必须一致，任何冲突报 `official_version_mismatch`；
4. 输出解析应在 stdout/stderr 中寻找唯一、完整匹配的版本行，允许明确分离的非版本 warning，但拒绝多个版本、CSA suffix 或冲突值；
5. 错误报告中区分“metadata 可读但 launcher 不可运行”和“metadata/version 冲突”，不要都压成一个 `command_failed`。

### LNX-04（P1）：Linux 没有 PATH 接管，却仍报告安装成功

**证据**

- 默认 Manager 根目录在 Linux 为 `~/.local/share/csa`，其 `bin` 通常不在 `PATH`；
- `src/main.rs:181-227` 的 `activate_user_path()` 只实现 Windows，非 Windows 是 no-op；
- `src/main.rs:229-237` 的卸载 PATH 清理在非 Windows 也是 no-op；
- `plug()` 只创建 `<manager-root>/bin/codex`，不会改变父 shell 环境或 profile；
- `finish_install()` 不要求 `activation.effective == true` 就返回 `status: installed`；
- 因而官方 `codex` 通常仍在 PATH 中先解析，只有 `status --json` 的 `activation.effective=false` 能暴露问题。

**影响**

用户完成 `csa install` 后，直接运行 `codex` 仍可能是官方版本；工具的主要“切换/接管”目标没有实现。使用多个 shell、IDE terminal、alias/function 或 shell command cache 时问题更明显。

**解决方案**

1. 定义明确的 POSIX 激活契约：CSA 只管理自己的目录，不覆盖 npm/bun/pnpm 的 `codex` 文件；
2. 建议实现 `csa shell init <bash|zsh|fish|sh>` 和一个 CSA-owned profile fragment，再由精确 marker block 引用；fish 使用 `conf.d`，bash/zsh/sh 使用各自实际会加载的 profile；
3. `install`/`plug` 若不能安全持久化，应打印可复制的 `export PATH="<manager-bin>:$PATH"`/shell-specific 命令，并把结果标为 `prepared_but_inactive`，不能输出“activation is ready”；
4. 新 shell 的预期 PATH 可在子进程中模拟验证：CSA bin 必须在前、绝对 shim 的 `--version` 必须带 CSA marker；
5. 当前 shell 无法由子进程反向修改，应明确要求 `eval "$(csa shell env)"` 或重开 shell，并提示 bash `hash -r`/zsh `rehash`；
6. alias/function 不属于 PATH，无法被 Manager 子进程可靠覆盖；doctor 应提示用户用 `type -a codex` 检查并移除冲突；
7. `uninstall`/`purge` 只删除 CSA 自己写入的精确 marker/file，保留用户其他 profile 内容。

### LNX-05（P2）：GNU→musl target 映射在命令间不一致

**证据**

- `src/online.rs:398-403` 正确把 `x86_64/aarch64-unknown-linux-gnu` 映射到相应 musl artifact；
- 但 `src/manager.rs:241` 的 doctor 直接检查原始 `BUILD_TARGET`；
- `src/manager.rs:265` 的 local prepare 也直接用原始 `BUILD_TARGET` 加载 artifact；
- 因此从源码在普通 glibc Linux 上执行 `cargo build` 得到 GNU Manager 时，online install 能选择 musl artifact，但 doctor/local artifact prepare 可能报告不支持同一个 manifest。

**解决方案**

1. 把 target 解析移到共享模块，例如 `manager_target -> runtime_artifact_target`；
2. online discovery、doctor、local prepare、state validation、测试和 UI 全部使用同一个 resolved target；
3. state 同时记录 manager build target 与 selected runtime target，避免诊断含义混淆；
4. 对 source build 单独定义约束：若必须按 manifest canonical target 构建，应给出明确 cross-toolchain 错误和命令，而不是和 prebuilt artifact 选择混用。

### LNX-06（P2）：关于 npm/bun/pnpm launcher 的判断需要拆开

**结论**

“`find_codex_launcher` 在 Linux 不支持 npm/bun/pnpm 包装脚本”这一说法对标准安装**不成立**。

- `src/detect.rs:546-568` 在 PATH 中查找名为 `codex` 的候选；
- `src/detect.rs:613-635` 接受具有执行位的普通文件；
- Unix 下 npm 常见的 `codex -> .../bin/codex.js` symlink 在 canonicalize 后可执行；
- bun/pnpm 的可执行 shebang wrapper 也可直接启动；
- 本次用三种合成布局验证，三者均被识别并得到版本。

**真正的缺口**

- 当前返回值只保留 canonical path，可能丢失 package-manager wrapper 的 lexical location；
- Volta 等 opaque shim 虽然能执行 `--version`，却不能仅靠 canonical path 推出真实 package root；
- LNX-02 的 runtime discovery 在 Linux 根本没有实现，所以“找到 launcher”不等于“找到 runtime”。

**解决方案**

1. discovery candidate 同时保存 PATH 中的 lexical path 和 canonical executable path；
2. 先处理可证明的标准 npm/bun/pnpm 布局；
3. 对 Volta 等 opaque shim 使用其受支持的只读解析命令，或要求用户把 `--official` 指向真实 `codex.js`/native path；
4. 不支持 shell alias/function 作为 official identity；它们不是可 fingerprint 的文件，应给出明确诊断；
5. runtime 无法唯一归属时 fail closed，而不是退化成 `runtime: None`。

### LNX-07（P2）：缺少 Vite+ package manager 支持

**证据**

- `src/detect.rs:21-27` 的 `PackageManager` 只有 npm、bun、pnpm；
- `src/manager.rs:842-850` 只清理三种 marker；
- 当前官方 Codex launcher 已识别 Vite+，并使用 `CODEX_MANAGED_BY_VITE_PLUS`；
- 若未来通用 runtime discovery 仍沿用当前 enum，Vite+ 会被误标成 npm，或遗留冲突环境变量。

**解决方案**

- 增加 `VitePlus` variant 和 `CODEX_MANAGED_BY_VITE_PLUS`；
- 清理所有已知 package-manager marker 后只设置一个；
- 增加 Vite+ global metadata/layout fixture；
- 对未知 manager 不要默认伪装为 npm；可记录 `Unknown` 并仅在能证明兼容时继续，否则 fail closed。

### LNX-08（P2）：Unix 信号和 signal-exit 语义不完整

**证据**

- `src/process.rs:110-120`/`123-131` 只保存 `ExitStatus::code()`；Unix 子进程被 signal 终止时该值为 `None`；
- `src/activation.rs:894-895` 和 `src/manager.rs:817-819` 把 `None` 统一返回为 code `1`；
- `npm/meta/bin/csa.js:84-99` 使用阻塞 `spawnSync`，只有 child 已返回 signal 时才重发 signal；Node launcher 自己收到定向 SIGTERM 时无法在 JS handler 中转发；
- 现有 launcher 测试发送的是整个 process group signal，不能覆盖“只向顶层 PID 发 signal”这一常见 supervisor 场景。

**影响**

脚本/CI 可能看到错误的退出码；定向停止 npm launcher 时，下面的 Manager/Codex 可能继续运行。普通终端 Ctrl+C 通常发送给整个 foreground process group，因此不一定复现，但不能覆盖 systemd、IDE task runner、进程管理器等情况。

**解决方案**

1. Linux shim 在完成安全选择后优先使用 `std::os::unix::process::CommandExt::exec()` 替换自身，天然保留 PID、TTY、signal 和退出语义；
2. 必须保留父进程的 `exec --isolated` 路径，使用 `ExitStatusExt::signal()` 记录 signal，并按契约重发同一 signal或返回 `128 + signal`；
3. npm launcher 改为异步 `spawn`，显式转发 SIGINT/SIGTERM/SIGHUP，并等待 child；
4. 增加 process-group signal、top-level-only signal、child self-signal、正常非零退出四类测试。

### LNX-09（P2）：非 UTF-8 路径会产生损坏的 JSON 输出

**证据**

- Linux 路径是任意字节序列，不保证 UTF-8；CLI 和内部结构大多使用 `OsString`/`PathBuf`，前置阶段会接受这类路径；
- `PreparedState`、doctor/status/report 直接通过 serde JSON 序列化 `PathBuf`；
- 实测 `--manager-root` 含 `0xff` 时，stdout 先写出半截 JSON，再返回 `output_error: path contains invalid UTF-8 characters` 到 stderr；
- `src/hash.rs:34-36` 对 PATH 使用 `to_string_lossy()` 后再 hash，不同原始字节可能折叠成相同 replacement character 序列。

**解决方案**

最小兼容方案：

1. 明确要求所有持久化/JSON-visible 路径为 UTF-8，并在任何下载、prepare、state 写入或 stdout 输出前统一验证；
2. JSON 先序列化到内存 buffer，成功后一次写出，永远不要留下 partial JSON；
3. Unix PATH evidence hash 使用 `std::os::unix::ffi::OsStrExt::as_bytes()`；Windows 使用无损 UTF-16 code units。

若要完整支持非 UTF-8，则需要新 schema，以 display 字符串加 raw bytes/base64 表示路径，不能继续依赖 serde 的默认 `PathBuf` JSON 表示。

### LNX-10（P2，条件性）：默认 Manager root 可能位于 `noexec` 文件系统

**证据与场景**

Linux 默认把 shim 和 patched executable 放到 `~/.local/share/csa`。企业主机、容器、某些 NFS/FUSE/home 挂载可能带 `noexec`。当前代码只检查 mode bits 和 hash，不真实启动 staging executable，因此可能创建 state/shim 后才在首次运行时报 `EACCES`。

**解决方案**

- activation 前对 staging Manager 和 patched artifact 做无副作用的绝对路径执行探测；
- 将 `EACCES`/`noexec` 诊断成专用错误，提示选择可信的 executable-capable `--manager-root`；
- 不要自动退到 `/tmp` 或其他弱信任目录；
- 在文档列出 overlayfs、NFS/FUSE、`noexec` 的支持边界，并在容器门禁中至少覆盖一个失败场景。

### LNX-11（P2）：Linux UI 和文档仍是 Windows 操作流

**证据**

- `src/ui.rs:1499-1537` 和 `1558-1594` 无条件显示“新终端激活已就绪”；
- 同一位置无条件要求运行 `where.exe codex`；
- `src/ui.rs:235-236` 的 progress 文案无条件提示 Windows UAC；
- README/operations 的安装确认、故障排查和大多数代码块只给 PowerShell、`Get-Command`、`where.exe`；
- 这会掩盖 LNX-04，并给 Linux 用户不可执行的恢复步骤。

**解决方案**

- 按平台生成 UI 文案；Linux 使用 `type -a codex`、`command -v codex`、`readlink -f "$(command -v codex)"` 和 `codex --version`；
- 只有 PATH 配置与下一进程验证都成功时才显示“ready”；
- 增加独立 Linux quick start、bash/zsh/fish 激活、uninstall、fallback、shell cache、alias 冲突和 WSL/容器说明；
- 文档明确区分“Manager 平台包可启动”和“patched runtime 已正式验收”。

### LNX-12（P1）：Linux CI/发布证据不足以阻止上述回归

**证据**

- `.github/workflows/ci.yml:318-443` 的 Linux lane 主要执行 Rust tests、clippy/build、npm staging 和 `csa --version`；
- `scripts/test_installed_launcher.mjs` 只检查 npm meta launcher 能启动 Manager 并输出版本；
- 完整 npm distribution、cold plug、runtime binding、command takeover、fallback、uninstall 测试只有 Windows PowerShell 脚本；
- test fixture 在非 Windows 主动省略 runtime，并断言这是正常状态；
- README 已明确写明正式 runtime acceptance 目前只覆盖 Windows x64；
- `npm/meta/package.json` 声明 Node `>=18`，但 support matrix/workflow 只测试 22、24、26。

**解决方案**

建立 Linux x64 与 arm64 的发布阻断门禁，至少覆盖：

1. 从本地 tarball 安装 CSA npm meta/platform 包；
2. npm、bun、pnpm（以及支持后 Vite+）官方 package layout discovery；
3. launcher/package marker/native version 四方一致；
4. online-download executable mode 的单元/集成测试；
5. prepare → plug → 新 shell PATH first → patched env/runtime → official drift → fallback → uninstall；
6. helper hash/size/execute-bit drift；
7. glibc Ubuntu/Fedora 类环境与 Alpine/musl 环境；
8. x64 与 arm64 原生运行，不只 cross-compile；
9. signal、TTY、stdin/stdout/stderr、cwd、argv、exit code；
10. Node 18/20/22/24/26，或把 `engines.node` 收紧到实际测试下限；
11. 所有测试使用隔离 HOME/XDG/CODEX_HOME/npm prefix，不触碰 runner 的全局安装或 profile。

## 5. 推荐修复顺序

### 阶段 A：先恢复最小可用性

1. 修复下载 artifact 的 Unix 执行位（LNX-01）；
2. 实现 Linux runtime discovery、fingerprint 与强制绑定（LNX-02）；
3. 引入 metadata/launcher/native 多源版本一致性（LNX-03）；
4. 加入 Linux runtime fixture 与真实 executable-mode tests。

完成标准：绝对路径运行 managed shim 时，patched 模式能获得完整官方 runtime env；任一官方 helper 漂移都会 fallback；在线下载的 artifact 可执行。

### 阶段 B：实现真实命令接管

1. 设计 POSIX shell init/profile 机制；
2. install/plug/uninstall/purge 对 CSA-owned PATH 配置保持幂等和可逆；
3. 修正 activation 状态和 Linux UI；
4. 增加新 shell、alias/cache 冲突与 official fallback tests。

完成标准：新 shell 中 `command -v codex` 指向 CSA shim，`codex --version` 带 CSA marker；uninstall 后恢复官方 launcher，用户其他 profile 内容不变。

### 阶段 C：统一平台契约并扩大兼容面

1. 统一 GNU/musl target resolver（LNX-05）；
2. 完善 wrapper/opaque shim 和 Vite+（LNX-06/LNX-07）；
3. 修复 signal、非 UTF-8 与 `noexec` 诊断（LNX-08～LNX-10）；
4. 建立 Linux x64/arm64、glibc/musl、Node 支持下限的发布门禁（LNX-12）。

## 6. 修复后的验收标准

- `official.runtime` 和 `official.native` 在受支持的 Linux npm/bun/pnpm 安装中均非空；
- runtime marker、managed package、launcher、native 的 version/target 必须一致；
- patched 启动必须设置且只设置正确的 package-manager marker、`CODEX_MANAGED_PACKAGE_ROOT` 和 `CSA_CODEX_OFFICIAL_PACKAGE_ROOT`；
- 下载、缓存和最终 artifact 均有执行位并能在目标文件系统真实启动；
- `csa install` 不得在 `activation.effective=false` 且未给出明确手动步骤时宣称接管成功；
- 新 shell 中 CSA shim first，runtime 漂移时安全回退到 official，且无递归；
- signal/退出码、TTY、argv、cwd、stdio 与直接执行 Codex 一致；
- JSON 输出永远完整；不支持的路径编码在副作用发生前失败；
- GNU source build 与 musl published artifact 的 target 解释在 doctor/online/local/status 中一致；
- Linux x64/arm64 的发布必须有完整 distribution + runtime + activation evidence，而不是只有 build/version smoke test。

## 7. 已确认不是问题或目前实现正确的部分

- **标准 npm/bun/pnpm wrapper 本身可以被 `find_codex_launcher` 找到**；问题在后续 runtime 归属和验证，不在 shebang wrapper 的基本执行；
- npm platform staging 对非 Windows Manager binary 显式设置 `0755`（`scripts/stage_npm_packages.mjs:126-128`）；
- Linux GNU Manager 到 musl patched artifact 的在线 catalog 映射已经存在且有单元测试；问题是该映射没有被其他命令复用；
- PATH 遍历使用 `OsStr`/`split_paths`，普通空格和 Unicode 路径不是问题；非 UTF-8 的持久化/JSON 才是问题；
- shim fallback 会在搜索 official launcher 时排除当前 Manager root，基本的防递归方向正确；
- Linux x64/arm64 都有 npm platform package 和 native CI runner 条目，但现有证据只覆盖构建/启动层，不代表完整 runtime 支持。

## 8. 当前限制

这是一份基于当前仓库、当前官方 Linux npm package layout、静态调用链和受限本机验证的审计。未实际下载匹配的 patched Release，未在 Alpine、arm64、bun/pnpm/Vite+ 真机全局安装和多种 shell 中执行破坏性端到端测试。因此这些环境仍需按 LNX-12 建立自动化与正式 acceptance，不能把“本报告未发现其他静态问题”解释成对所有 Linux 发行版、shell、文件系统和 package manager 的完成证明。

## 9. 修复后状态（2026-09-06，当前工作树）

第 1～8 节保留为修复前审计快照。下面的状态针对当前工作树，优先于前文同一 LNX 条目的“已确认”描述。

| ID | 当前状态 | 当前实现与证据 |
| --- | --- | --- |
| LNX-01 | 已修复 | `src/platform.rs` 为 Unix 可执行 artifact 补执行位；发布前、缓存命中和最终 fingerprint 都重新校验。`platform` 单元测试覆盖 `0644` artifact 转为可执行。 |
| LNX-02 | 已修复 | `src/detect.rs` 使用通用 official runtime discovery，覆盖 Linux npm、Bun、pnpm、Vite+、nested/sibling 和 legacy `vendor/<target>` 布局，校验 marker、managed/platform manifest、native 与 helpers；Linux patched 模式缺 runtime 时 fail closed。Linux fixture、manager integration 和 `scripts/test_linux_runtime.mjs` 已通过。 |
| LNX-03 | 已修复 | launcher、native、managed manifest 和 platform marker 的版本交叉校验已实现；版本解析允许独立 warning，拒绝多版本行、CSA suffix 和冲突版本。Rust detect 测试已覆盖版本漂移和解析边界。 |
| LNX-04 | 已修复 | POSIX 激活写入精确且可逆的 CSA marker block，支持 `.profile`、`.bashrc`、`.zshrc` 和 fish `conf.d`；`csa shell init/env` 提供当前或新 shell 的明确步骤。无法持久化时返回 `manual_required` / `prepared_but_inactive`，不会报告已完成接管。 |
| LNX-05 | 已修复 | `src/platform.rs` 提供共享 GNU→musl target resolver；doctor、online/local prepare、runtime discovery 和 state validation 使用 resolved artifact target，state 同时保存 `manager_build_target` 与 runtime `build_target`。 |
| LNX-06 | 部分修复 | 标准 npm、Bun、pnpm wrapper 以及常见布局已经纳入 discovery fixture，并覆盖 runtime 归属和歧义拒绝。opaque shim、shell alias/function 仍不作为可证明的 official package identity，需用户提供真实 launcher/native 路径或由后续平台适配解决。 |
| LNX-07 | 已修复 | `PackageManager::VitePlus`、`CODEX_MANAGED_BY_VITE_PLUS` 和已知 marker 清理已加入；Vite+ 布局和未知 package manager fail-closed 行为有测试。 |
| LNX-08 | 已修复 | Unix `CommandResult` 保留 signal 并按 `128 + signal` 映射；shim 的 Unix 转发使用 `exec()`，npm launcher 异步 spawn 并转发 SIGINT/SIGTERM/SIGHUP。Rust signal、process-group 和 top-level signal 测试已通过。 |
| LNX-09 | 已修复（UTF-8 边界） | JSON 先序列化到内存后一次写出；manager root、manifest、isolated path、record/fingerprint path 在副作用前要求 UTF-8；Unix PATH evidence hash 使用原始 path bytes。非 UTF-8 路径仍按明确不支持处理，不产生 partial JSON。 |
| LNX-10 | 已修复（诊断路径） | staging shim 和 patched artifact 在发布/激活前执行探测；权限拒绝映射为 `noexec_filesystem`，并提示选择可执行的 manager root。已有 noexec 专用错误测试；本机未在真实 noexec 挂载上执行 acceptance。 |
| LNX-11 | 已修复 | Linux/POSIX UI、README、operations 和 reference 已改用 shell-specific activation、`command -v`/`type -a` 等步骤，并区分已保存 PATH 与需要手动激活的状态。 |
| LNX-12 | 部分修复 | CI 和 release workflow 已加入 Linux runtime/POSIX activation acceptance、Linux x64/arm64 target lane、实际 npm tarball 安装后的 Linux acceptance、隔离 HOME/npm cache，以及 Node 18/20/22/24/26 兼容矩阵。本机已通过 x86_64 Linux 的 Rust、release、runtime、launcher 和 release-tool checks；GitHub 原生 arm64、Windows/macOS、Alpine 和真实多 package-manager 发布门禁仍需在对应 runner 执行。 |

### 当前工作树的验证记录

- `cargo fmt --all -- --check`：通过；
- `cargo clippy --workspace --all-targets --all-features -- -D warnings`：通过；
- `cargo test --all-targets -- --test-threads=4`：59 个测试通过（36 + 8 + 15）；
- `cargo build --release`：通过；
- `node scripts/test_linux_runtime.mjs target/release/csa`：runtime discovery、POSIX activation 和 helper drift 全部通过；
- `node --check`（meta launcher、stage script、npm launcher test、Linux runtime test）：通过；
- `node scripts/test_npm_launcher.mjs`：argv/env/cwd/stdio、exit code、checksum drift、missing platform、process-group signal 和 top-level signal 全部通过；
- 当前 release binary 的本地 npm staging、`npm pack`、隔离 prefix 的 offline install、已安装 launcher version 检查和已安装 Linux runtime acceptance：通过；staged Manager 与 launcher 均为 0755；
- `python3 scripts/test_release_tools.py`：assembler、atomic corruption rejection、deterministic source bundle、CI input、release notes 和 producer boundary 全部通过；
- npm 默认 cache 只读时使用临时 `NPM_CONFIG_CACHE`，没有改动用户的全局 npm cache。

### 仍未在当前环境完成的验证

当前本机构建 target 只有 `x86_64-unknown-linux-gnu` 和 `x86_64-unknown-linux-musl`。musl cross-check 需要的 `x86_64-linux-musl-gcc` 不存在；Windows target check 还受 target/依赖和当前网络解析限制影响。因此本地结果不能替代 Windows、macOS、Linux arm64、Alpine 或真实 noexec 挂载上的原生 acceptance。上述限制不删除原始审计结论，只限定本次修复的验证范围。
