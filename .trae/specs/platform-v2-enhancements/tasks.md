# Tasks: 平台 V2 增强

- [ ] Task 1: 健康检查 JSON 响应
  - [ ] 1.1 在 `db.rs` 的 `site_config` 默认值中添加 `health_check_message` 键（默认 "欢迎使用茶的服务器公益站"）
  - [ ] 1.2 修改 `main.rs` 中的 `/health` 路由，改为返回 JSON 格式响应 `{ "status": "ok", "message": "...", "site_name": "..." }`

- [ ] Task 2: 用户仪表盘 API Key 展示
  - [ ] 2.1 修改 `user_dashboard` handler，查询用户 `api_key` 并传递给模板
  - [ ] 2.2 修改 `templates/user/dashboard.html`，添加「我的 API Key」展示区域（含复制按钮和重新生成表单）
  - [ ] 2.3 新增 `POST /dashboard/api-key` 路由，处理 API Key 重新生成请求

- [ ] Task 3: 操作类 POST API 端点
  - [ ] 3.1 在 `handlers/api.rs` 中添加 `POST /api/v1/servers/contribute` 端点（贡献服务器）
  - [ ] 3.2 在 `handlers/api.rs` 中添加 `POST /api/v1/machines/create` 端点（创建机器）
  - [ ] 3.3 在 `handlers/api.rs` 中添加 `POST /api/v1/redeem` 端点（兑换码）
  - [ ] 3.4 在 `handlers/api.rs` 中添加 `POST /api/v1/packages/buy` 端点（购买套餐）
  - [ ] 3.5 在 `handlers/api.rs` 中添加 `POST /api/v1/checkin` 端点（签到）
  - [ ] 3.6 在 `handlers/api.rs` 中添加 `POST /api/v1/me/api-key` 路由（与现有 GET 共存）

- [ ] Task 4: README.md API 文档
  - [ ] 4.1 创建 `README.md`，包含项目简介、环境变量说明、API 接口列表和 curl 示例

- [ ] Task 5: Agent OpenGFW 监控模块
  - [ ] 5.1 在 `db.rs` 中添加 `violations` 表迁移
  - [ ] 5.2 在 `models/mod.rs` 中添加 `Violation` 结构体
  - [ ] 5.3 在 `handlers/api.rs` 中添加 `POST /api/v1/agent/violations` 端点（agent 上报）
  - [ ] 5.4 在 `handlers/mod.rs` 中添加 `admin_violations` handler 和 `/admin/violations` 路由
  - [ ] 5.5 创建 `templates/admin/violations.html` 违规记录页面
  - [ ] 5.6 更新 `agent/agent.py`，添加 OpenGFW 流量检测和违规上报逻辑
  - [ ] 5.7 更新 `agent/install.sh`，添加 OpenGFW 安装步骤

- [ ] Task 6: 站长封禁账号增强
  - [ ] 6.1 修改 `admin_user_edit` handler，封禁时自动停止该用户所有运行中的机器
  - [ ] 6.2 修改 `require_auth` 中间件，检查 `is_banned` 状态，已封禁用户拒绝访问

- [ ] Task 7: 机器广场排序优化
  - [ ] 7.1 修改 `machine_market` handler，查询时按容量排序（有剩余容量优先、新建时间倒序）
  - [ ] 7.2 修改 `api_market` handler，采用相同的排序逻辑

- [ ] Task 8: 邀请码备注
  - [ ] 8.1 在 `db.rs` 的 `invites` 表迁移中添加 `private_note` 和 `public_note` 字段
  - [ ] 8.2 更新 `Invite` model 添加 `private_note` 和 `public_note` 字段
  - [ ] 8.3 修改 `admin_generate_invites` handler，接收备注参数并存入数据库
  - [ ] 8.4 修改 `templates/admin/invites.html`，生成表单中添加备注输入框，列表显示备注
  - [ ] 8.5 修改 `auth_callback` handler，注册时读取邀请码的公开备注并传递给模板/显示

- [ ] Task 9: 验证与编译
  - [ ] 9.1 `cargo check` 编译通过
  - [ ] 9.2 验证所有路由和 API 端点可正常访问

# Task Dependencies

- Task 2, 3, 4, 5, 6, 7, 8 可并行开发
- Task 1 独立，可并行
- Task 9 依赖所有前置任务
- Task 3 依赖 Task 2 的 API 认证机制（已存在）