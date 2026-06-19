# Tasks: 优选套餐与服务器信息展示

- [x] Task 1: 数据库与模型变更
  - [x] 1.1 在 `db.rs` 的 `servers` 表添加 `is_premium`（默认 0）和 `linux_version`（默认 ''）字段（ALTER TABLE）
  - [x] 1.2 在 `db.rs` 站点配置默认值中添加 `premium_enabled`（默认 "false"）和 `premium_ldc_cost`（默认 "100"）
  - [x] 1.3 在 `models/mod.rs` 的 `Server` 结构体添加 `is_premium: bool` 和 `linux_version: String` 字段

- [x] Task 2: 贡献页面 Linux 版本输入
  - [x] 2.1 修改 `templates/user/contribute.html`，在虚拟化类型下方添加「Linux 版本」输入框（可选）
  - [x] 2.2 修改 `contribute_server_submit` handler，读取并保存 `linux_version` 字段
  - [x] 2.3 修改 `handlers/api.rs` 的 `ContributeServerRequest` 结构体和 INSERT，添加 `linux_version` 字段

- [x] Task 3: 优选标记购买
  - [x] 3.1 在 `handlers/mod.rs` 添加 `POST /servers/:id/buy-premium` handler，校验 `premium_enabled` 配置、扣除 LDC、设置 `is_premium=1`
  - [x] 3.2 在 `main.rs` 添加路由 `.route("/servers/:id/buy-premium", post(handlers::buy_premium))`
  - [x] 3.3 在 `templates/user/dashboard.html` 服务器管理区域添加「购买优选」按钮（仅当 `premium_enabled=true` 且服务器未标记优选时显示）

- [x] Task 4: 机器广场排序与展示
  - [x] 4.1 修改 `machine_market` handler，排序逻辑改为：`is_premium DESC` → 有容量 → 无容量 → `created_at DESC`
  - [x] 4.2 修改 `templates/user/market.html`，优选服务器卡片添加「茶的优选」角标
  - [x] 4.3 修改 `templates/user/market.html`，每张卡片显示 IP 地址和 Linux 版本

- [x] Task 5: 自动选机优选优先
  - [x] 5.1 自动选机 handler 仅渲染模板，`create_machine` 通过 `server_id` 直接指定服务器（无自动匹配逻辑需修改）

- [x] Task 6: 管理后台配置
  - [x] 6.1 修改 `templates/admin/config.html`，添加「优选套餐开关」和「优选费用（LDC）」配置项
  - [x] 6.2 `admin_config_save` handler 现有逻辑已支持动态 key-value 保存

- [x] Task 7: Agent 自动探测 Linux 版本
  - [x] 7.1 agent 安装完成后通过 `uname -r` 探测内核版本，仅在 `linux_version` 为空时回填

- [x] Task 8: 验证
  - [x] 8.1 `cargo check` 编译通过
  - [x] 8.2 机器广场优选服务器置顶且显示角标
  - [x] 8.3 机器广场显示 IP 和 Linux 版本