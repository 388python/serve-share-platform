# API 与管理增强 Spec

## Why

当前平台仅支持 HTML 页面交互，缺少 API 接口供外部调用；SSH 代理端口数硬编码为 100；管理员无法授予其他用户管理员权限；贡献服务器时赠金开关不可控。

## What Changes

- 新增 RESTful API 接口层（用户端 + 管理端），使用 API Key 认证
- SSH 代理端口数改为环境变量 `SSH_PROXY_PORT_COUNT` 可配置
- 管理员可授予/撤销其他用户的管理员权限
- 管理员可锁定「是否使用赠金」开关（全局禁用或强制开启）
- 管理员后台可调整用户核时/LDC 额度（已有，需 API 暴露）

## Impact

- Affected specs: tea-server-platform
- Affected code: `src/main.rs`, `src/config.rs`, `src/handlers/mod.rs`, `src/db.rs`, `templates/admin/config.html`, `templates/admin/users.html`, `templates/user/contribute.html`, `.env.example`, `docker-compose.yml`

---

## ADDED Requirements

### Requirement: RESTful API 接口层

系统 SHALL 提供 `/api/v1/` 前缀的 RESTful JSON API 接口，使用 API Key 认证。

#### Scenario: API 认证
- **WHEN** 请求携带 `Authorization: Bearer <api_key>` 头
- **THEN** 系统验证 API Key 有效性
- **AND** 用户 API Key 在用户中心生成/查看
- **AND** 管理员 API Key 通过 `ADMIN_API_KEY` 环境变量或管理后台配置

#### Scenario: API 用户端接口
- **WHEN** 用户调用 API
- **THEN** 提供以下端点：
  - `GET /api/v1/me` — 当前用户信息（余额、核时、机器列表）
  - `GET /api/v1/machines` — 我的机器列表
  - `POST /api/v1/machines` — 创建机器（选择服务器+配置）
  - `POST /api/v1/machines/:id/stop` — 停止机器
  - `POST /api/v1/machines/:id/delete` — 删除机器
  - `GET /api/v1/machines/:id/connect` — 获取连接信息
  - `GET /api/v1/servers` — 可用服务器列表（机器广场）
  - `POST /api/v1/checkin` — 签到
  - `POST /api/v1/redeem` — 兑换码
  - `GET /api/v1/packages` — 套餐列表
  - `POST /api/v1/recharge` — 创建充值订单

#### Scenario: API 管理端接口
- **WHEN** 管理员调用 API
- **THEN** 提供以下端点：
  - `GET /api/v1/admin/users` — 用户列表
  - `GET /api/v1/admin/users/:id` — 用户详情
  - `PATCH /api/v1/admin/users/:id` — 修改用户（额度/封禁/管理员）
  - `GET /api/v1/admin/servers` — 服务器列表
  - `PATCH /api/v1/admin/servers/:id` — 修改服务器（启用/停用）
  - `GET /api/v1/admin/machines` — 所有机器列表
  - `GET /api/v1/admin/config` — 获取站点配置
  - `PUT /api/v1/admin/config` — 更新站点配置
  - `POST /api/v1/admin/codes/generate` — 生成兑换码
  - `POST /api/v1/admin/invites/generate` — 生成邀请码
  - `GET /api/v1/admin/orders` — 订单列表

### Requirement: 管理员权限授予

系统 SHALL 允许管理员授予或撤销其他用户的管理员权限。

#### Scenario: 授予管理员权限
- **WHEN** 管理员在后台用户管理页面或 API 将用户 `is_admin` 设为 true
- **THEN** 该用户获得管理员权限，可访问 `/admin` 后台
- **AND** 该用户 session 下次登录时自动变为管理员

#### Scenario: 撤销管理员权限
- **WHEN** 管理员将用户 `is_admin` 设为 false
- **THEN** 该用户失去管理员权限
- **AND** 当前管理员不能撤销自己的权限

### Requirement: SSH 代理端口可配置数量

系统 SHALL 通过环境变量 `SSH_PROXY_PORT_COUNT` 配置 SSH 代理端口数量。

#### Scenario: 配置端口数量
- **WHEN** 设置 `SSH_PROXY_PORT_COUNT=500`
- **THEN** 系统启动时监听 `SSH_PROXY_PORT_START` 到 `SSH_PROXY_PORT_START + 500 - 1` 共 500 个端口
- **WHEN** 未设置 `SSH_PROXY_PORT_COUNT`
- **THEN** 默认值为 100

### Requirement: 后台调整用户额度

系统 SHALL 允许管理员在后台调整用户的核时余额和 LDC 余额。

#### Scenario: 调整用户额度
- **WHEN** 管理员在用户管理页面编辑用户
- **THEN** 可修改核时余额（直接设置数值）
- **AND** 可修改 LDC 余额（直接设置数值）
- **AND** 可封禁/解封用户
- **AND** 操作结果立即生效

### Requirement: 锁死赠金开关

系统 SHALL 允许管理员锁定「是否使用赠金」选项。

#### Scenario: 锁定赠金开关
- **WHEN** 管理员在后台配置中将 `lock_bonus` 设为 "enabled"（强制开启）
- **THEN** 贡献服务器页面赠金复选框被勾选且不可取消
- **WHEN** 管理员将 `lock_bonus` 设为 "disabled"（强制关闭）
- **THEN** 贡献服务器页面赠金复选框被取消勾选且不可勾选
- **WHEN** 管理员将 `lock_bonus` 设为 "unlocked"（默认）
- **THEN** 贡献服务器页面赠金复选框可自由选择

## MODIFIED Requirements

### Requirement: SSH 端口转发（修改）

系统 SHALL 通过平台 SSH 代理转发连接，端口数量由 `SSH_PROXY_PORT_COUNT` 环境变量配置（默认 100）。

#### Scenario: 连接服务器
- **WHEN** 用户通过平台请求连接已分配机器
- **THEN** 系统返回平台中转 SSH 端口（在配置的端口范围内）
- **AND** 用户通过该端口连接，平台代理转发到真实服务器
- **AND** 原始服务器 IP 不被暴露

### Requirement: 管理员后台（修改）

系统 SHALL 提供完整的管理后台功能，新增管理员权限管理和赠金锁定配置。

#### Scenario: 管理后台配置
- **WHEN** 管理员登录后台
- **THEN** 可配置以下全局参数（新增项）：
  - 管理员 API Key
  - 赠金锁定模式（unlocked / enabled / disabled）
  - 新增原有配置项不变

#### Scenario: 用户管理
- **WHEN** 管理员在用户列表操作
- **THEN** 可授予/撤销管理员权限（新增）
- **AND** 可调整核时余额和 LDC 余额（已有）
- **AND** 可封禁/解封用户（已有）