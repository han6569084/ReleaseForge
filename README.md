# Release FW Pipeline 使用说明

本仓库的主入口脚本是 `release_pipeline_run.py`，用于在 Windows（PowerShell）环境下串联执行：

1. 从 Jenkins 下载产物（Debug / Release）
2. 运行可配置的 Prepare 流程（解压、挑选文件、拷贝到 payload、下载 Jenkins consoleText 等）
3. 通过 NAS WebDAV 上传
4. 通过 Synology DSM FileStation 生成共享链接
5. 生成本地版本文档（Markdown）
6. （可选）复制飞书 Wiki 模板并替换 Docx 占位符

> 说明：配置文件中的 `${...}` 变量会在运行时做字符串展开；相对路径以“主配置文件所在目录”为基准解析。

---

## 1. 环境要求

- Python 3（建议 3.9+）
- Windows PowerShell
- `curl.exe` 可用（Windows 10/11 通常自带）
- 可访问的网络：Jenkins、NAS WebDAV、DSM（以及飞书 OpenAPI 如启用）

---

## 2. 快速开始

### 2.1 创建配置文件

1) 复制示例配置：

- 将 `release_pipeline_config.example.json` 复制为 `release_pipeline_config.json`

2) 按项目修改：

- `release.project / release.device_name / release.stage / release.version / release.variant`
- Jenkins build：`jenkins.builds.release.build_url`、`jenkins.builds.debug.build_url`
- NAS：`nas.webdav.*`、`nas.dsm.*`、`nas.remote.*`
- （可选）飞书：`feishu.*`

### 2.2 运行

- 全流程（debug + release）：

```powershell
python .\release_pipeline_run.py --config .\release_pipeline_config.json
```

- 只跑 Release：

```powershell
python .\release_pipeline_run.py --config .\release_pipeline_config.json --only release
```

- 只跑 Debug：

```powershell
python .\release_pipeline_run.py --config .\release_pipeline_config.json --only debug
```

---

## 3. 命令行参数（CLI）

运行 `python .\release_pipeline_run.py -h` 可以看到完整帮助；目前支持的参数如下：

- `--config`：必填。主配置 JSON 路径
- `--only {all,debug,release}`：只跑某一条流水线（默认 `all`）
- `--skip-download`：跳过 Jenkins 下载
- `--skip-prepare`：跳过 Prepare（解压/挑选/payload 等）
- `--skip-upload`：跳过 NAS WebDAV 上传
- `--skip-share`：跳过 DSM 共享链接生成
- `--skip-doc`：跳过生成本地版本文档
- `--skip-feishu`：跳过飞书 Wiki/Docx 操作
- `--dry-run`：仅打印计划动作，不进行真实下载/上传/写入
- `--no-progress`：关闭 curl 的进度输出（CI 日志更干净）
- `--doc-output <dir>`：指定本地版本文档输出目录（默认会落到用户目录下的 `release_docs`）

常用组合示例：

- 只验证规则/路径是否匹配（不会真的操作网络）：

```powershell
python .\release_pipeline_run.py --config .\release_pipeline_config.json --only release --dry-run
```

- 远端已存在文件，只想重新生成 DSM 分享链接：

```powershell
python .\release_pipeline_run.py --config .\release_pipeline_config.json --only release --skip-upload
```

---

## 4. 脚本执行步骤说明（做了什么）

脚本整体分为“每个 run（debug/release）循环执行”的步骤：

1) 读取主配置 JSON，并展开 `${...}` 变量
2) 根据 `--only` 选择执行 debug / release
3) 对每个 run：
   - Jenkins 下载（可 `--skip-download`）
   - Prepare 阶段（可 `--skip-prepare`）
     - `prepare.mode=placeholders_dsl`：执行 DSL steps（支持按 `run` 字段过滤，只执行当前 run 的 step）
     - `prepare.mode=release_extract`：旧的 release 解压逻辑（仅 release 生效）
   - NAS 上传（可 `--skip-upload`）
   - DSM 共享链接生成（可 `--skip-share`）
4) 生成本地版本文档（可 `--skip-doc`）
5) 飞书：复制 Wiki 模板、替换 Docx 占位符、可插入 Markdown（可 `--skip-feishu`）

> 提示：即使 `--skip-upload`，只要不加 `--skip-share`，脚本仍会尝试对“远端已存在的同名文件”生成分享链接。

---

## 5. 主配置文件说明（release_pipeline_config.json）

下面按模块说明主配置的关键字段。

### 5.1 `release`

- `project`：项目名（用于匹配产物/命名/文档标题等）
- `device_name`：设备名（某些产物正则用到）
- `stage`：例如 `alpha/beta/rc` 等
- `version`：版本号
- `variant`：用于 NAS 目录名（通常包含项目/阶段/版本）
- `notes`：文档中的备注

### 5.2 `jenkins`

- `auth.type`：当前用 `basic`
- `auth.username/password`：Jenkins 账号密码
- `builds.debug.build_url` / `builds.release.build_url`：某一次构建的 URL（以 `/` 结尾更稳）
- `download`：
  - `mode`：目前使用 `artifacts`
  - `include_globs` / `exclude_globs`：控制下载哪些文件
  - `output_dir`：下载输出目录（相对路径会以主配置文件目录为基准）
  - `overwrite`：重复运行时是否覆盖

### 5.3 `prepare`

- `mode`：
  - `placeholders_dsl`（推荐）：由 DSL JSON 驱动（解压/挑选/拷贝/下载 console log 等）
  - `release_extract`：旧逻辑（只对 release 生效）
  - `none`：不做 prepare
- `workspace_dir`：prepare 工作区根目录（例如 `work/prepare`）
- `clean`：prepare 前是否清理工作区
- `placeholders_config`（可选）：显式指定 DSL 文件路径
  - 不指定时默认使用：`placeholders.default.json`

### 5.4 `nas`

- `webdav`：负责上传
  - `base_url`：例如 `https://<ip>:5006`
  - `verify_tls`：自签证书环境可设 `false`
  - `auth.username/password`

- `dsm`：负责生成共享链接
  - `base_url`：例如 `https://<ip>:5001`
  - `verify_tls`：自签证书环境可设 `false`
  - `auth.username/password`

- `remote`：远端目录策略
  - `base_dir`：NAS 上的基础目录
  - `folder_name`：通常使用 `${release.variant}`
  - `path_strategy`：当前使用 `base_plus_folder`

- `uploads[]`：定义 debug/release 各自上传什么
  - `name`：必须是 `debug` 或 `release`（用于和 Jenkins builds 对应）
  - `remote_subdir`：远端子目录名，例如 `Release` / `Monkey`
  - `local_dir`：主要上传目录
  - `extra_local_dirs`：额外要上传的目录（DSL 模式下，payload 目录会被自动加入）

### 5.5 `doc`

- `enabled`：是否生成本地版本文档（Markdown）
- `output_dir`：可留空，或配合 CLI `--doc-output`
- `filename_template`：例如 `{project}_{version}_{timestamp}_版本文档.md`

### 5.6 `feishu`

- `enabled`：是否执行飞书
- `use_wiki`：是否使用 Wiki v2 复制节点方式（推荐）
- `template_node_token`：Wiki 模板节点 token
- `target_space_id` / `target_parent_token`：复制目标位置
- `name_template`：页面标题模板（支持占位符 `{{REL_*}}`）

- Docx 模板模式（不走 Wiki）：
  - `use_wiki=false`
  - `template_file_token`：Docx 模板（支持两种写法）
    - 直接填 docx token（document_id）
    - 或填完整 URL，例如 `https://zepp.feishu.cn/docx/<token>`（脚本会自动提取 token，并复用该域名生成新文档链接）
  - `docx_domain`（可选）：生成文档链接的域名（例如 `zepp.feishu.cn`）。不填则优先使用模板 URL 的域名。
  - `docx_replace_placeholders`：是否在复制/创建后的 Docx 里做占位符替换
  - `docx_replace_only`：只做占位符替换，不进行“Markdown 转 blocks + 插入”（避免依赖 `docx:document.block:convert` 应用权限）
  - `docx_insert_markdown`（可选，默认 true）：是否把生成的版本文档 Markdown 插入到 Docx（为 false 时不会调用 blocks/convert）
  - `admin_email`（可选，默认 `hanzhijian@zepp.com`）：创建后自动把该邮箱加入协作者并授予 `full_access`（管理员）
    - `share_admin_perm`：默认 `full_access`
    - `share_file_type`：建议 `docx`（用于 drive 权限接口的 `type` 参数）

- token 获取策略（默认优先使用“应用/tenant token”，避免每次手动授权）：
  - `token_mode`：可选 `tenant` / `user` / `auto`
    - `tenant`（默认）：使用 `tenant_access_token`（应用身份），可通过 `app_id/app_secret` 自动获取并本地缓存
    - `user`：使用 `user_access_token`（用户身份），支持 localhost OAuth
    - `auto`：优先 tenant，取不到再走 user/OAuth

- tenant token（应用身份，推荐）：
  - `tenant_access_token`：直接填写（不推荐长期放在配置里）
  - `tenant_access_token_env`：从环境变量读取（例如 `FEISHU_TENANT_ACCESS_TOKEN`）
  - `tenant_access_token_cache`：是否开启本地缓存（默认 `true`）
  - `tenant_access_token_cache_file`：缓存文件路径（默认落在配置同目录的 `.feishu_tenant_access_token.json`）
  - `app.app_id / app.app_secret`：用于自动获取 tenant token（也可复用 `oauth.app_id/app_secret`）

- user token（用户身份，兼容/兜底）：
  - `user_access_token`：直接填写 token（不推荐长期使用）
  - `user_access_token_env`：从环境变量读取（推荐，例如 `FEISHU_USER_ACCESS_TOKEN`）
  - `oauth.enabled=true`：启用 localhost OAuth，遇到 token 过期/权限不足可自动重新授权

- `docx_replace_placeholders`：是否在复制后的 Docx 里做占位符替换
- `print_placeholder_mapping`：是否输出最终 mapping JSON（便于排查）

> 安全建议：不要把真实的 Jenkins/NAS/Feishu 密钥提交到仓库；优先通过环境变量或私有配置文件管理。

> 注意：使用 tenant token 想“彻底跳过每次授权”，前提是飞书应用已被管理员在租户内完成安装/授权（应用权限已审批通过），并且模板/目标目录对应用身份可访问（例如在云文档/知识库里给应用开放权限）。

---

## 6. placeholders DSL（placeholders.default.json）

DSL 文件用于“定义 prepare 的步骤 + 定义占位符如何映射”。结构主要是两块：

- `prepare.flow.steps[]`：准备/产物提取流水线
- `placeholders.mappings{}`：占位符替换规则

### 6.1 DSL 文件选择规则

当 `prepare.mode=placeholders_dsl`：

1) 若主配置显式设置了 `prepare.placeholders_config`（或同义字段），则使用该文件
2) 否则使用默认文件：`placeholders.default.json`

### 6.2 prepare.flow.steps 支持的操作（op）

常用字段：

- `name`：仅用于日志
- `run`：`release` 或 `debug`（不写则用 defaults.run）
- `optional`：找不到/失败时是否允许继续
- `save_as` / `also_save_as`：保存变量名供后续步骤引用

已支持的 `op`：

- `find`：在 `root` 下按 `match` 搜索文件
- `pick`：在 `root` 下按 `match` 挑选文件
- `extract_tgz`：解压 `.tgz` 到 `to`
- `extract_if_single_tar`：如果目录下仅有单一 `.tar`，则进一步解压
- `copy_to_payload`：拷贝文件到 `${prepare.flow.upload_payload_dir}`（用于后续上传/分享）
- `download_jenkins_console`：下载 Jenkins `consoleText` 到指定文件（用于 `{{REL_BUILD_LOG_FILE}}`）

`match` 支持：

- `{ "exact": "xxx" }`
- `{ "regex": "..." }`
- `{ "fallback_regex": "..." }`（当 exact 不存在时兜底）

### 6.3 placeholders.mappings 支持的模式（mode）

- `var`：从主配置读取，例如 `release.version`
- `const`：常量字符串
- `nas_share`：生成/读取 NAS 文件共享链接
  - 优先级由 `placeholders.strategy.nas_share_priority` 控制
  - 典型用法：`from: "some_payload_var"`（推荐）或 `match`（从已上传文件列表里匹配）

### 6.4 当前默认配置：解压/上传/占位符的对应关系

默认 DSL 文件是 `placeholders.default.json`。它把“从 Jenkins 下载目录里解压出来的关键文件”拷贝到一个统一的 payload 目录，再由 NAS 上传与 DSM 分享链接生成统一处理。

#### 6.4.1 目录与阶段关系

- Jenkins 下载目录（由主配置决定）
  - Release：`${jenkins.builds.release.download.output_dir}`（示例：`work/download/release`）
  - Debug：`${jenkins.builds.debug.download.output_dir}`（示例：`work/download/debug`）

- Prepare 工作区（由主配置 `prepare.workspace_dir` 决定）
  - 默认 work：`${prepare.workspace_dir}/release_extract/_work`
  - 默认 payload：`${prepare.workspace_dir}/release_extract/upload_payload`

- 上传阶段（由主配置 `nas.uploads[]` 决定）
  - Release 上传：
    - 主目录：`${jenkins.builds.release.download.output_dir}`（整目录上传到 NAS 的 `Release/`）
    - 额外目录：payload（DSL 模式下会自动加入；示例配置里也显式写了 `extra_local_dirs`）
  - Debug 上传：
    - 主目录：`${jenkins.builds.debug.download.output_dir}`（整目录上传到 NAS 的 `Monkey/`）
    - （可选）payload：如果 DSL 在 debug run 里生成了 payload 文件，也会自动加入

#### 6.4.2 Release：默认解压/拷贝（prepare.flow.steps，run=release）

Release 的典型链路是：

1) 在 Release 下载目录里找 top tgz：`archive_${release.project}_*.tgz`
2) 解压到：`step1_archive_${release.project}`（step1_dir）
3) 如果 step1 内只有一个 `.tar`，继续解一层得到 step1_content_dir
4) 从 step1_content_dir 挑选并处理：
   - `archive_OTA_CLOUD_*.tgz` → 拷贝到 payload（`ota_cloud_payload`）
   - 解 `archive_OTA_CLOUD_*.tgz` 后从 cloud 内容里挑选：
     - `watch@mhs003_ota_sign.zip`（或兜底 `*_ota_sign.zip`）→ 拷贝到 payload（`ota_sign_payload`）
   - 从 step1_content_dir 里挑选 `archive_OTA_(非 CLOUD / 非 SLEEP)*.tgz` → 解压后挑选：
     - `watch@mhs003.elf` → 拷贝到 payload（`watch_elf_payload`）
   - （可选）`archive_BOOT_*.tgz` → 解压后挑选 `manifest_BOOT_*.xml` → 拷贝到 payload（`boot_manifest_payload`）
   - （可选）`archive_RECOVERY_*.tgz` → 解压后挑选 `manifest_RECOVERY_*.xml` → 拷贝到 payload（`recovery_manifest_payload`）
5) 从 Release 下载目录里（不是 step1）可选挑选：
   - `archive_OTA_SLEEP_*.tgz` → 拷贝到 payload（`ota_sleep_payload`）
6) （可选）下载 Jenkins Release consoleText：
   - `${jenkins.builds.release.build_url}/consoleText` → 保存到 payload：`jenkins_release_console.log`（`release_console_log_payload`）

这些 payload 文件会作为 Release 的“额外上传目录”上传到 NAS 的 `Release/` 下，因此它们的分享链接可以稳定生成并用于占位符替换。

#### 6.4.3 Debug：默认拷贝（prepare.flow.steps，run=debug）

Debug 的默认规则比较克制：

- 在 Debug 下载目录里找 `archive_${release.project}*_*.tgz`（OTA 整包）
- 找到后拷贝到 payload（`debug_full_archive_payload`）

Debug 的主目录本身会整目录上传到 NAS 的 `Monkey/` 下；如果上述 payload 生成了文件，它也会被上传并生成分享链接。

#### 6.4.4 占位符如何拿到“共享链接”

默认 `placeholders.mappings` 里，`nas_share` 的来源分两类：

1) **优先用 payload 变量（from=...）**：
   - `{{REL_BOOTLOADER_MANIFEST_INFO}}` ← `boot_manifest_payload`（可选 BOOT）
   - `{{REL_RECOVERY_MANIFEST_INFO}}` ← `recovery_manifest_payload`（可选 RECOVERY）
   - `{{REL_RELEASE_OTA_CLOUD_ARCHIVE}}` ← `ota_cloud_payload`
   - `{{REL_RELEASE_OTA_SIGN_ZIP}}` ← `ota_sign_payload`
   - `{{REL_RELEASE_OTA_SLEEP_ARCHIVE}}` ← `ota_sleep_payload`（可选）
   - `{{REL_MONKEY_FULL_ARCHIVE}}` ← `debug_full_archive_payload`（可选）
   - `{{REL_BUILD_LOG_FILE}}` ← `release_console_log_payload`（可选）

2) **从已上传文件列表里按名字正则匹配（match=...）**（通常匹配的是“整目录上传”的 Jenkins 下载目录中的文件）：
   - `{{REL_RELEASE_FULL_ARCHIVE}}`：匹配 `archive_${release.device_name}*_*.tgz`
   - `{{REL_APP_MANIFEST_INFO}}`：匹配 `manifest_*${release.project}*.xml`
   - `{{REL_RELEASE_FACTORY_TOOL_ZIP}}`：匹配 `*factory*.zip`
   - `{{REL_MD5SUM_FILE}}`：匹配 `*md5*.txt` 等

这样做的好处是：

- “必须稳定存在、并且需要稳定链接”的关键文件（例如 `watch@mhs003.elf`、`ota_sign.zip`、console 日志）统一进入 payload，链接生成更可控。
- “本来就在 Jenkins 下载目录里且无需解压”的文件（例如 top tgz、工厂工具 zip、md5 等）直接靠整目录上传 + 正则匹配，避免 DSL 写得过长。

---

## 7. 常见问题（Troubleshooting）

### 7.1 Jenkins 下载失败

- 检查 `jenkins.builds.*.build_url` 是否可在浏览器打开
- 检查 `jenkins.auth.username/password`（更推荐使用 Jenkins API Token）
- 推荐做法：设置环境变量 `JENKINS_USER` + `JENKINS_API_TOKEN`，并在配置里写 `jenkins.auth.password_env=JENKINS_API_TOKEN`
- 需要代理/证书问题时，优先确认系统网络与公司证书策略

### 7.2 DSM 分享链接失败

- 检查 `nas.dsm.base_url`（通常 `https://<ip>:5001`）
- 自签证书环境：`nas.dsm.verify_tls=false`
- 检查 DSM 账号权限（FileStation API 需要对应权限）

### 7.2.1 NAS WebDAV 上传 401

- 401 通常表示 WebDAV 账号/密码不对，或账号没有目标路径权限
- 推荐用环境变量提供密码：`NAS_WEBDAV_PASSWORD`（配置里写 `nas.webdav.auth.password_env=NAS_WEBDAV_PASSWORD`）
- 如果配置里还是 `"password": "<REDACTED>"`，上传会必然失败（会把 `<REDACTED>` 当成真实密码去请求）

### 7.3 飞书报错 99991677 / 99991679

- `99991677`：token 过期。启用 `feishu.oauth.enabled=true` 后可自动重新授权
- `99991679`：缺少用户授权 scope 或 app 权限。确认 `feishu.oauth.scopes` 包含 docx/wiki 相关权限，并重新授权获取新的 user_access_token

---

## 8. 附：辅助脚本

- `feishu_oauth_get_user_token.py`：手动获取/调试飞书 user_access_token
- `feishu_wiki_get_ids.py`：查询 wiki 节点/space 等信息（用于填配置）

### 8.1 feishu_wiki_get_ids.py 使用方法

用途：给定一个飞书 Wiki 页面 URL（或 node_token），查询该节点对应的 `space_id / node_token / parent_node_token / obj_type / obj_token` 等信息。

常见场景：

- 配置 `feishu.template_node_token`（模板节点 token）
- 确认模板节点底层指向的 `obj_type` 是否是 `docx`（脚本需要 `docx` 才能做占位符替换）
- 找到目标空间/父节点 token（用于把复制的页面放到正确位置）

#### 必要条件

- 需要 `user_access_token`（建议通过环境变量 `FEISHU_USER_ACCESS_TOKEN` 提供）
- 需要用户已授权至少以下 Wiki 相关 scope（否则会报 99991679）：
  - `wiki:wiki` 或 `wiki:wiki:readonly`
  - `wiki:node:read`

#### 参数说明

- `--url <wiki_url>`：Wiki 页面 URL（脚本会自动从 URL 里提取 node token）
- `--node-token <token>`：直接传入 node token（通常是 URL 中 `/wiki/` 后面的那段）
- `--token <user_access_token>`：也可直接传 token；不传则读取环境变量 `FEISHU_USER_ACCESS_TOKEN`

调试辅助：

- `--show-token`：打印 token 的来源/长度/打码后的前后缀
- `--inspect-token`：尝试解码 JWT payload（不验签）并打印部分 claim（用于确认 app_id、scope、exp 等）
- `--dump`：打印完整 JSON 响应
- `--timeout <sec>`：HTTP 超时，默认 30

> 兼容：`--page-id` 是旧 knowledge API 用法（Deprecated），建议优先用 `--url/--node-token`。

#### 常用示例（Windows PowerShell）

1) 先准备 token（推荐环境变量）：

```powershell
$env:FEISHU_USER_ACCESS_TOKEN = "<your_user_access_token>"
```

2) 通过 URL 查询（最常用）：

```powershell
python .\feishu_wiki_get_ids.py --url "https://zepp.feishu.cn/wiki/E4NRwVTmkigYl0kjStJcu7eYnAb"
```

3) 通过 node token 查询：

```powershell
python .\feishu_wiki_get_ids.py --node-token "E4NRwVTmkigYl0kjStJcu7eYnAb"
```

4) 排查权限/scope/过期问题：

```powershell
python .\feishu_wiki_get_ids.py --show-token --inspect-token --url "https://zepp.feishu.cn/wiki/E4NRwVTmkigYl0kjStJcu7eYnAb" --dump
```

#### 输出字段如何填回主配置（release_pipeline_config.json）

脚本会输出（典型）：

- `node_token`：Wiki 节点 token
- `space_id`：该节点所在 space
- `parent_node_token`：父节点 token
- `obj_type`：底层对象类型（期待为 `docx`）
- `obj_token`：底层对象 token（例如 docx document_id）

对应配置建议：

- `feishu.template_node_token`：填输出的 `node_token`（作为模板）
- `feishu.target_space_id`：填你希望复制到的目标 space（通常等于模板的 `space_id`，或你另选一个 space）
- `feishu.target_parent_token`：填你希望复制到的目标父节点 token（常用：输出的 `parent_node_token`，代表与模板同级；也可以填空表示默认位置）

如果你发现 `obj_type` 不是 `docx`：

- 脚本仍可复制 Wiki 节点，但 Docx 占位符替换会不可用/报错。
- 需要把 Wiki 模板节点指向一个 Docx 文档（在飞书里调整模板页的关联文档类型）。

### 8.2 feishu_oauth_get_user_token.py 使用方法（获取 user_access_token）

用途：通过 OAuth（授权码模式 `authorization_code`）在本机启动一个 `localhost` 回调服务，引导用户在浏览器里登录并点击同意，从而拿到该用户自己的 `user_access_token`。

这个 token 之后可用于：

- `release_pipeline_run.py` 的飞书 Wiki/Docx 操作
- `feishu_wiki_get_ids.py` 查询 Wiki 节点信息

#### 必要前置（飞书开放平台）

1) 在飞书开放平台控制台为你的应用配置 **重定向 URL（Redirect URL）**，必须包含（默认值）：

- `http://localhost:8000/callback`

2) 在应用权限里添加并通过审批/启用你需要的能力，并在 OAuth 时请求相应 scope。

常见 scope 示例：

- 仅 Wiki 查询：`wiki:wiki:readonly wiki:node:read`
- Wiki 复制 + Docx 替换：`wiki:wiki wiki:node:read wiki:node:copy docx:document`

> 注意：如果你后来新增了 scope，用户必须重新走一次授权流程（重新点同意），旧 token 可能不会包含新 scope。

#### 参数说明

- `--app-id <cli_xxx>`：应用的 App ID（也可用环境变量 `FEISHU_APP_ID`）
- `--app-secret <secret>`：应用密钥（也可用环境变量 `FEISHU_APP_SECRET`）
- `--redirect-uri`：回调地址，默认 `http://localhost:8000/callback`
- `--scopes`：要请求的 OAuth scope（空格或逗号分隔；也可用环境变量 `FEISHU_OAUTH_SCOPES`）
- `--timeout`：等待用户在浏览器完成授权并回调的时间（秒），默认 300
- `--no-browser`：不自动打开浏览器（适合在远程桌面/无 GUI 场景手动复制链接）
- `--stdout-token`：仅把 token 输出到 stdout（其他日志输出到 stderr），便于 PowerShell 捕获
- `--dump`：输出完整 token 交换 JSON（可能包含敏感字段，不建议在共享终端/CI 使用）

#### 推荐用法（PowerShell）

1) 用 `--stdout-token` 一行拿到 token 并写入环境变量（推荐）：

```powershell
$env:FEISHU_USER_ACCESS_TOKEN = (
  python .\feishu_oauth_get_user_token.py --stdout-token `
    --app-id "<cli_xxx>" --app-secret "<secret>" `
    --scopes "wiki:wiki wiki:node:read wiki:node:copy docx:document"
)
```

2) 如果你不想在命令行里直接写 app_secret，可以先用环境变量：

```powershell
$env:FEISHU_APP_ID = "<cli_xxx>"
$env:FEISHU_APP_SECRET = "<secret>"
$env:FEISHU_OAUTH_SCOPES = "wiki:wiki wiki:node:read wiki:node:copy docx:document"

$env:FEISHU_USER_ACCESS_TOKEN = (python .\feishu_oauth_get_user_token.py --stdout-token)
```

3) 手动打开浏览器（不自动打开）：

```powershell
python .\feishu_oauth_get_user_token.py --no-browser --app-id "<cli_xxx>" --app-secret "<secret>"
```

#### 运行时会发生什么

脚本会：

1) 在本机启动 `http://localhost:8000/callback` 的 HTTP Server
2) 打印授权 URL（并默认自动打开浏览器）
3) 用户在浏览器里登录飞书账号并点击同意
4) 浏览器回调到本机 `/callback?code=...`
5) 脚本用 `code` 交换得到 `user_access_token`

#### 常见问题

- 浏览器提示 redirect_uri 不匹配：说明开放平台后台没把 `http://localhost:8000/callback` 加到白名单，或你改了 `--redirect-uri` 但后台没同步。
- 报 99991679：说明应用权限或用户授权 scope 不够；确认开放平台权限已开通，并用 `--scopes` 请求所需 scope 后重新授权。
- token 很快失效：属于正常现象；建议启用主脚本里的 `feishu.oauth.enabled=true` 让其在必要时自动重新 OAuth。

### 8.3 jenkins_trigger_build.py 使用方法（触发 Jenkins 构建并写回 build_url）

用途：根据配置发起 Jenkins 参数化构建（先触发 `release`，然后立刻触发 `debug`，不等待 release 完成），并监测两次构建直到都结束且 `SUCCESS` 后，把 build 号对应的 `build_url` 直接写回到你的配置文件中：

- `jenkins.builds.release.build_url`
- `jenkins.builds.debug.build_url`

> 说明：如果 JSON 中没有指定某个参数 key，该参数不会提交给 Jenkins，从而使用 Jenkins Job 的默认值。

另外：如果配置里启用了 `notifications.webhook`，脚本会：

- Jenkins build 号一出来就发送：`Jenkins <release|debug> started: #<id> <url>`
- 任意一个先结束就先发送：`Jenkins <release|debug> finished: #<id> result=<...> <url>`（不会等另一个结束）

WebHook 发送格式固定为：

```json
{ "text": "..." }
```

#### 配置示例（最小）

在你的主配置里增加 `jenkins.triggers`：

```json
{
  "jenkins": {
    "base_url": "https://jenkins.huami.com",
    "auth": {
      "type": "basic",
      "username": "<your-username>",
      "password": "<your-password>"
    },
    "triggers": {
      "job_url": "https://jenkins.huami.com/job/firmware_auto_trigger/job/HuamiOS_HS3/",
      "release": {
        "parameters": {
          "PRODUCT": "matterhorn",
          "TAG_NAME": "your_tag",
          "BOOT_TAG_NAME": "boot_tag",
          "RECOVERY_TAG_NAME": "recovery_tag",
          "FCT_TAG_NAME": "fct_tag"
        }
      },
      "debug": {
        "parameters": {
          "PRODUCT": "matterhorn",
          "TAG_NAME": "your_tag"
        }
      }
    }
  }
}
```

#### 运行示例（PowerShell）

1) 真实触发并写回配置（默认会生成 `.bak.<timestamp>` 备份）：

```powershell
python .\jenkins_trigger_build.py --config .\release_pipeline_config.json
```

2) 干跑：只打印会提交哪些参数，不触发构建：

```powershell
python .\jenkins_trigger_build.py --config .\release_pipeline_config.json --dry-run
```

3) 调整超时/轮询：

```powershell
python .\jenkins_trigger_build.py --config .\release_pipeline_config.json `
  --poll-interval-sec 5 --queue-timeout-sec 1200 --build-timeout-sec 10800
```

4) Jenkins 构建完成后自动执行发版主流程（下载/上传/文档/飞书）：

```powershell
python .\jenkins_trigger_build.py --config .\release_pipeline_config.json --run-pipeline
```

你也可以在配置里开启自动执行，这样就算你忘了加 `--run-pipeline` 也会在构建成功后自动启动主流程：

```json
{
  "jenkins": {
    "triggers": {
      "auto_run_pipeline": true,
      "pipeline_args": []
    }
  }
}
```

如果你需要给主流程额外参数（例如跳过飞书、跳过上传等），用 `--pipeline-args` 透传：

```powershell
python .\jenkins_trigger_build.py --config .\release_pipeline_config.json --run-pipeline `
  --pipeline-args=--skip-feishu --pipeline-args=--skip-upload --pipeline-args=--skip-share
```

#### 常见问题

- 触发成功但报“Location header for queue item missing”：说明 Jenkins 或代理吞掉了响应头 `Location`，脚本 v1 无法从 queue 反查 build number；需要你们调整代理透传响应头，或后续我再加“时间窗口 + 参数匹配”的 fallback。
- 报 403：可能是 CSRF(crumb) 或权限不足；脚本会自动探测 crumb（`/crumbIssuer/api/json`），如果你们禁用了该接口需要放开或手工关闭 CSRF。

---

## 9. 占位符参考（示例）

占位符会在飞书 Docx 替换阶段使用（或输出 mapping 文件供人工替换），常见示例：

- `{{REL_DEVICE_NAME}}` / `{{REL_STAGE}}` / `{{REL_VERSION}}`
- `{{REL_APP_TAG}}` / `{{REL_BOOT_TAG}}` / `{{REL_RECOVERY_TAG}}` / `{{REL_FCT_TAG}}`

> 提示：即使你使用 `prepare.mode=placeholders_dsl`，以上 4 个 TAG 占位符也会从 `jenkins.triggers.release.parameters` 自动注入到映射里用于飞书替换。
- `{{REL_RELEASE_FULL_ARCHIVE}}`
- `{{REL_RELEASE_OTA_CLOUD_ARCHIVE}}`
- `{{REL_RELEASE_OTA_SIGN_ZIP}}`
- `{{REL_RELEASE_FACTORY_TOOL_ZIP}}`
- `{{REL_RELEASE_OTA_SLEEP_ARCHIVE}}`（可选）
- `{{REL_MONKEY_FULL_ARCHIVE}}`（可选）
- `{{REL_BUILD_LOG_FILE}}`（可选：Jenkins consoleText 下载并上传后得到）

---

## 10. WebHook 通知（打包完成提醒）

你可以在流水线完成后自动发送一条 WebHook 消息（例如飞书群机器人）。配置在 `notifications.webhook`：

- `enabled`：是否启用
- `url`：WebHook 地址
- `verify_tls`：HTTPS 证书校验（内网自签可设为 false）
- `timeout_sec`：请求超时
- `on_success` / `on_failure`：成功/失败是否通知
- `on_success`：正常完成时发送（包括 Feishu copy-only / replace-only 这类提前结束）
- `on_failure`：失败退出时发送（包括 `SystemExit`/参数缺失/权限错误等导致的非 0 退出，以及未捕获异常）
- `on_progress`：进度通知（例如开始下载）是否发送
- `payload_by_event`：按事件覆盖 payload（例如 `download_start`）
- `payload`：要 POST 的 JSON（支持 `${...}` 占位符）

`payload` 中可用的 runtime 变量：

- `${runtime.status}`：`success`/`failed`
- `${runtime.message}`：简短描述
- `${runtime.duration_sec}`：耗时秒数
- `${runtime.config_path}`：配置文件路径
- `${runtime.extra.feishu_url}`：生成的飞书文档/Wiki 链接（未生成则为空字符串）

示例（飞书 Flow WebHook，要求格式：`{"text":"..."}`）：

```json
{
  "notifications": {
    "webhook": {
      "enabled": true,
      "url": "https://www.feishu.cn/flow/api/trigger-webhook/REPLACE_ME",
      "payload": {
        "text": "${release.device_name} ${release.stage} ${release.version} 打包完成\n耗时: ${runtime.duration_sec}s"
      }
    }
  }
}
```
