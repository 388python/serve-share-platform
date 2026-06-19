# Tasks: 仪表盘与 API 增强

- [x] Task 1: 启动欢迎 JSON 响应
  - [x] 1.1 在 `api.rs` 添加 `GET /api/v1/health` 端点，返回平台信息 JSON（含 `platform`、`version`、`started_at`）
  - [x] 1.2 在 `main.rs` 启动时将 `started_at` 时间戳写入全局或 `api.rs` 可访问的位置

- [x] Task 2: 用户仪表盘 API Key 显示
  - [x] 2.1 修改 `templates/user/dashboard.html`，在「每日签到」卡片上方新增「我的 API Key」区域
  - [x] 2.2 修改 `user_dashboard` handler，查询用户 `api_key` 并传递给模板
  - [x] 2.3 新增 `POST /dashboard/api-key` 路由，支持重新生成 API Key（复用已有的 `regenerate` 逻辑）

- [x] Task 3: API POST 端点
  - [x] 3.1 在 `api.rs` 添加 `POST /api/v1/servers/contribute`，接收 JSON body 复用 `contribute_server_submit` 逻辑
  - [x] 3.2 在 `api.rs` 添加 `POST /api/v1/machines/create`，接收 JSON body 复用 `create_machine` 逻辑
  - [x] 3.3 在 `api.rs` 添加 `POST /api/v1/redeem`，接收 JSON body 复用 `redeem_submit` 逻辑
  - [x] 3.4 在 `api.rs` 添加 `POST /api/v1/packages/buy`，接收 JSON body 复用 `buy_package` 逻辑

- [x] Task 4: README.md API 文档
  - [x] 4.1 在项目根目录创建 `README.md`（如不存在），包含 API 端点列表、认证方式、curl 示例
  - [x] 4.2 文档覆盖所有用户端 GET/POST 端点和管理端 GET/PUT 端点

- [x] Task 5: OpenGFW 流量监控
  - [x] 5.1 创建 `src/services/traffic_monitor.rs`，实现 VPN 协议特征检测逻辑（基于常见端口/协议指纹）
  - [x] 5.2 在 `db.rs` 站点配置中添加 `traffic_monitor_enabled` 和 `traffic_bandwidth_threshold_mbps` 默认值
  - [x] 5.3 在 `main.rs` 添加后台任务，定期检查运行中机器的流量，违规时自动停止并记录告警
  - [x] 5.4 在 `db.rs` 创建 `traffic_alerts` 表，记录告警日志
  - [x] 5.5 在管理后台配置页面添加流量监控开关和带宽阈值配置

- [x] Task 6: 机器广场排序优化
  - [x] 6.1 修改 `machine_market` handler，查询服务器时计算剩余容量（CPU/内存/磁盘）
  - [x] 6.2 按剩余容量排序：有容量 > 无容量，同等条件下 `created_at DESC`

- [x] Task 7: 邀请码备注
  - [x] 7.1 在 `db.rs` 的 `invites` 表添加 `private_note` 和 `public_note` 字段（ALTER TABLE）
  - [x] 7.2 修改 `templates/admin/invites.html`，生成表单中添加私有备注和公开备注输入框，列表显示备注
  - [x] 7.3 修改 `admin_generate_invites` handler，保存备注字段
  - [x] 7.4 修改 `models/mod.rs` 的 `Invite` 结构体，添加 `private_note` 和 `public_note` 字段
  - [x] 7.5 修改 OAuth 回调中的邀请码验证逻辑，公开备注传递给注册失败/成功页面

- [x] Task 8: 用户数据看板
  - [x] 8.1 创建 `templates/user/stats.html` 模板，展示平台统计数据
  - [x] 8.2 在 `handlers/mod.rs` 添加 `GET /stats` 路由和 handler，查询统计数据
  - [x] 8.3 在 `main.rs` 添加 `/stats` 路由
  - [x] 8.4 在导航栏（`components/base.html`）添加「数据看板」链接

- [x] Task 9: 验证
  - [x] 9.1 `cargo check` 编译通过
  - [x] 9.2 所有新增 API 端点可正常响应

# Task Dependencies

- Task 1, 2, 3, 4, 5, 6, 7, 8 可并行开发
- Task 9 依赖所有前置任务