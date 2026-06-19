# Tasks: 结算、争议、NAT 与兑换增强

- [x] Task 1: 积分延迟到账机制
  - [x] 1.1 在 `db.rs` 站点配置中添加 `settlement_threshold_pct` 默认值（如 80）
  - [x] 1.2 在 `db.rs` 的 `machines` 表添加 `settled` 字段（默认 0）和 `used_hours` 字段
  - [x] 1.3 修改 `main.rs` 后台任务，机器停止/删除时检查使用时长，达到阈值后自动结算核时给贡献者
  - [x] 1.4 在管理后台配置页面添加结算阈值配置

- [x] Task 2: 贡献服务器暴露 IP 选项
  - [x] 2.1 在 `db.rs` 的 `servers` 表添加 `expose_ip` 字段（默认 0）
  - [x] 2.2 修改 `models/mod.rs` 的 `Server` 结构体添加 `expose_ip` 字段
  - [x] 2.3 修改 `templates/user/contribute.html`，添加「暴露 IP 地址」复选框
  - [x] 2.4 修改 `contribute_server_submit` handler，保存 `expose_ip` 字段
  - [x] 2.5 修改 `machine_connect` handler，`expose_ip=true` 时返回直连信息而非代理端口

- [x] Task 3: NAT 内网穿透
  - [x] 3.1 在 `db.rs` 的 `servers` 表添加 `nat_port_start`、`nat_port_end`、`nat_multiplier` 字段
  - [x] 3.2 修改 `models/mod.rs` 的 `Server` 结构体添加 NAT 字段
  - [x] 3.3 修改 `templates/user/contribute.html`，当勾选「暴露 IP」时显示 NAT 配置区域
  - [x] 3.4 修改 `contribute_server_submit` handler，保存 NAT 配置
  - [x] 3.5 修改 `services/core_hours.rs` 的核时计算公式，添加 `+ NAT端口数×NAT倍率×全局NAT倍率`
  - [x] 3.6 在 `db.rs` 站点配置中添加 `global_nat_multiplier` 默认值
  - [x] 3.7 在管理后台配置页面添加全局 NAT 倍率配置

- [x] Task 4: 争议处理机制
  - [x] 4.1 在 `db.rs` 创建 `disputes` 表
  - [x] 4.2 在 `models/mod.rs` 添加 `Dispute` 结构体
  - [x] 4.3 创建 `templates/user/dispute.html` 争议发起页面
  - [x] 4.4 在 `handlers/mod.rs` 添加 `GET /disputes/new` 和 `POST /disputes/create` 路由
  - [x] 4.5 创建 `templates/admin/disputes.html` 管理端争议列表
  - [x] 4.6 在 `handlers/mod.rs` 添加 `GET /admin/disputes` 和 `POST /admin/disputes/:id/resolve` 路由
  - [x] 4.7 在 `handlers/mod.rs` 添加商家端争议处理 `POST /disputes/:id/reply`
  - [x] 4.8 在 `main.rs` 添加后台任务，检查超时争议自动标记为平台介入
  - [x] 4.9 在 `db.rs` 站点配置中添加 `dispute_auto_resolve_hours` 默认值（72 小时）
  - [x] 4.10 在管理后台配置页面添加争议超时时间配置

- [x] Task 5: 赠金有效期管理
  - [x] 5.1 在 `db.rs` 的 `users` 表添加 `bonus_core_hours` 和 `bonus_expires_at` 字段
  - [x] 5.2 修改 `models/mod.rs` 的 `User` 结构体添加赠金字段
  - [x] 5.3 在 `db.rs` 站点配置中添加 `checkin_bonus_expiry_days` 默认值
  - [x] 5.4 修改签到 handler，发放的核时写入 `bonus_core_hours` 并设置 `bonus_expires_at`
  - [x] 5.5 在 `main.rs` 添加后台任务，定期清理过期赠金余额
  - [x] 5.6 修改开机器扣费逻辑，优先使用赠金余额，赠金支付后商家到账赠金余额（继承有效期）
  - [x] 5.7 在管理后台配置页面添加签到赠金有效期配置

- [x] Task 6: 商家设置最大开机时长
  - [x] 6.1 在 `db.rs` 的 `servers` 表添加 `max_machine_hours` 字段
  - [x] 6.2 修改 `models/mod.rs` 的 `Server` 结构体添加 `max_machine_hours`
  - [x] 6.3 修改 `templates/user/contribute.html`，添加「用户最大开机时长」输入框
  - [x] 6.4 修改 `contribute_server_submit` handler，保存 `max_machine_hours`
  - [x] 6.5 修改 `create_machine` handler 和 API 端点，校验创建时长不超过 `max_machine_hours`

- [x] Task 7: 管理员注册 OAuth2 应用
  - [x] 7.1 在 `db.rs` 创建 `oauth_apps` 表
  - [x] 7.2 在 `models/mod.rs` 添加 `OAuthApp` 结构体
  - [x] 7.3 创建 `templates/admin/oauth_apps.html` 管理端 OAuth 应用列表
  - [x] 7.4 在 `handlers/mod.rs` 添加 `GET/POST /admin/oauth-apps` 路由
  - [x] 7.5 在 `services/auth.rs` 添加静默授权端点 `GET /oauth/authorize`
  - [x] 7.6 在 `main.rs` 添加 OAuth 授权路由

- [x] Task 8: 余额兑换码功能
  - [x] 8.1 在 `db.rs` 站点配置中添加 `balance_to_code_fee` 和 `balance_to_code_daily_limit` 默认值
  - [x] 8.2 在 `db.rs` 创建 `balance_to_code_logs` 表
  - [x] 8.3 创建 `templates/user/balance_to_code.html` 兑换页面
  - [x] 8.4 在 `handlers/mod.rs` 添加 `GET/POST /balance-to-code` 路由
  - [x] 8.5 实现手续费计算和每日次数限制逻辑
  - [x] 8.6 赠金转兑换码时，有效期不暂停
  - [x] 8.7 在 `handlers/api.rs` 添加 `POST /api/v1/balance-to-code` API 端点
  - [x] 8.8 在管理后台配置页面添加手续费和每日上限配置

- [x] Task 9: 验证
  - [x] 9.1 `cargo check` 编译通过
  - [x] 9.2 所有新增端点可正常响应