# Tasks: API 与管理增强

- [ ] Task 1: SSH 代理端口数可配置
  - [ ] 1.1 在 `AppConfig` 中新增 `ssh_proxy_port_count` 字段（默认 100）
  - [ ] 1.2 修改 `main.rs` 中 SSH 代理启动循环，使用 `cfg.ssh_proxy_port_count` 替代硬编码的 100
  - [ ] 1.3 更新 `.env.example` 和 `docker-compose.yml` 添加 `SSH_PROXY_PORT_COUNT`

- [ ] Task 2: 管理员权限授予
  - [ ] 2.1 修改 `admin_users` 模板，在用户编辑 Modal 中添加「设为管理员」复选框
  - [ ] 2.2 修改 `admin_user_edit` handler，支持设置 `is_admin` 字段
  - [ ] 2.3 添加保护逻辑：管理员不能撤销自己的权限

- [ ] Task 3: 赠金锁定配置
  - [ ] 3.1 在 `db.rs` 的默认站点配置中添加 `lock_bonus` 键（默认 "unlocked"）
  - [ ] 3.2 修改 `admin/config.html` 模板，添加赠金锁定模式下拉选择
  - [ ] 3.3 修改 `admin_config_save` handler，保存 `lock_bonus` 配置
  - [ ] 3.4 修改 `contribute_server_page` handler，读取 `lock_bonus` 并传递给模板
  - [ ] 3.5 修改 `templates/user/contribute.html`，根据 `lock_bonus` 值控制赠金复选框状态

- [ ] Task 4: RESTful API 接口层
  - [ ] 4.1 创建 API 认证中间件，支持 Bearer token 验证
  - [ ] 4.2 在 `db.rs` 站点配置中添加 `admin_api_key` 默认值
  - [ ] 4.3 在 `users` 表添加 `api_key` 字段（或创建 api_keys 表）
  - [ ] 4.4 实现用户端 API 端点（/api/v1/me, /machines, /servers, /checkin, /redeem, /packages, /recharge）
  - [ ] 4.5 实现管理端 API 端点（/api/v1/admin/users, /servers, /machines, /config, /codes, /invites, /orders）
  - [ ] 4.6 在用户中心页面添加 API Key 生成/查看区域
  - [ ] 4.7 在管理后台配置页面添加 Admin API Key 设置

- [ ] Task 5: 验证与推送
  - [ ] 5.1 `cargo check` 编译通过
  - [ ] 5.2 推送代码到远程仓库

# Task Dependencies

- Task 2, 3, 4 依赖 Task 1（可并行开发）
- Task 5 依赖所有前置任务