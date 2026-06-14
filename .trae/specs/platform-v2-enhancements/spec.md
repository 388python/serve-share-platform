# 平台 V2 增强 Spec

## Why

平台已有基础功能，但缺少 API 文档、健康检查、操作类 API 端点；机器广场排序不合理；邀请码缺少备注功能；没有 OpenGFW 流量监控防止 VPN 滥用。

## What Changes

- 新增 `/health` 返回 JSON 格式欢迎信息，内容可通过站点配置
- 用户仪表盘页面添加「我的 API Key」展示/复制/重新生成区域
- 补充操作类 POST API 端点（contribute/machine/redeem/buy）
- 补充 README.md 中的 API 使用说明和 curl 示例
- 新增 OpenGFW 自动监控模块，检测并阻止 VPN/代理流量
- 管理员可封禁/解封用户账号（已有，需确认完整性）
- 机器广场列表排序：有空容量的在前，无容量的在后，新上传的在前
- 邀请码支持备注：生成时填写私有备注和公开备注，公开备注在注册时显示

## Impact

- Affected specs: tea-server-platform, api-admin-enhancements
- Affected code: `src/main.rs`, `src/handlers/mod.rs`, `src/handlers/api.rs`, `src/db.rs`, `src/models/mod.rs`, `src/config.rs`, `templates/user/dashboard.html`, `templates/user/market.html`, `templates/admin/invites.html`, `README.md`, `docker-compose.yml`

---

## ADDED Requirements

### Requirement: 健康检查 JSON 响应

系统 SHALL 在 `GET /health` 端点返回 JSON 格式的欢迎信息，内容通过站点配置 `health_check_message` 自定义。

#### Scenario: 健康检查返回
- **WHEN** 客户端请求 `GET /health`
- **THEN** 返回 `{ "status": "ok", "message": "<站点配置的欢迎信息>", "site_name": "<站点名称>" }`
- **AND** 默认 message 为 "欢迎使用茶的服务器公益站"

### Requirement: 用户仪表盘 API Key 展示

系统 SHALL 在用户仪表盘页面（dashboard）展示用户的 API Key，支持复制和重新生成。

#### Scenario: 查看 API Key
- **WHEN** 用户访问 `/dashboard`
- **THEN** 页面显示「我的 API Key」区域
- **AND** 若用户已有 API Key，显示 Key 值（可点击复制）
- **AND** 若用户尚无 API Key，显示"生成 API Key"按钮

#### Scenario: 重新生成 API Key
- **WHEN** 用户点击"重新生成"
- **THEN** 系统生成新的 `usr_` 前缀 API Key，更新数据库
- **AND** 页面刷新显示新 Key

### Requirement: 操作类 POST API 端点

系统 SHALL 提供以下 RESTful POST API 端点，支持 Bearer token 认证。

#### Scenario: POST /api/v1/servers/contribute — 贡献服务器
- **WHEN** 用户 POST JSON 包含服务器信息（name, ip, ssh_port, ssh_key, cpu_cores, memory_gb, bandwidth_mbps, disk_gb, cpu_multiplier, memory_multiplier, bandwidth_multiplier, disk_multiplier, use_bonus, virt_type, expires_days）
- **THEN** 系统创建服务器记录，分配代理端口，返回服务器详情

#### Scenario: POST /api/v1/machines/create — 创建机器
- **WHEN** 用户 POST JSON 包含 server_id, cpu_cores, memory_gb, disk_gb, hours
- **THEN** 系统计算核时、校验余额、扣减核时、创建机器，返回机器详情

#### Scenario: POST /api/v1/redeem — 兑换码
- **WHEN** 用户 POST JSON 包含 code
- **THEN** 系统验证兑换码，发放奖励，标记已使用，返回结果

#### Scenario: POST /api/v1/packages/buy — 购买套餐
- **WHEN** 用户 POST JSON 包含 package_id
- **THEN** 系统创建订单，返回支付 URL

#### Scenario: POST /api/v1/checkin — 签到
- **WHEN** 用户 POST 签到（无需 body）
- **THEN** 系统检查签到开关和今日是否已签到，发放奖励，返回结果

### Requirement: OpenGFW 自动监控

系统 SHALL 集成 OpenGFW 流量监控，自动检测并阻止 VPN、代理、P2P 大流量等违规流量。

#### Scenario: 检测 VPN/代理流量
- **WHEN** 服务器上的 agent 检测到 VPN/代理特征流量（OpenVPN、WireGuard、Shadowsocks、V2Ray、Trojan 等协议）
- **THEN** agent 自动阻断该流量
- **AND** 向平台上报违规记录（server_id, machine_id, 违规类型, 时间）

#### Scenario: 检测大流量滥用
- **WHEN** 单台机器带宽持续超过阈值（如 100Mbps 持续 5 分钟）
- **THEN** agent 自动限速或阻断
- **AND** 向平台上报违规记录

#### Scenario: 管理员查看违规记录
- **WHEN** 管理员访问 `/admin/violations`
- **THEN** 显示所有违规记录列表（服务器、机器、类型、时间）
- **AND** 管理员可手动封禁相关用户/服务器

### Requirement: 站长封禁账号

系统 SHALL 允许管理员在后台封禁和解除封禁用户账号。

#### Scenario: 封禁用户
- **WHEN** 管理员在用户管理页面勾选「封禁用户」并保存
- **THEN** 该用户 `is_banned = 1`，无法登录、无法使用 API
- **AND** 该用户的现有机器被自动停止
- **AND** 封禁不会删除用户数据

#### Scenario: 解封用户
- **WHEN** 管理员取消「封禁用户」勾选并保存
- **THEN** 该用户 `is_banned = 0`，恢复正常使用

### Requirement: 机器广场排序优化

系统 SHALL 按以下规则对机器广场的服务器列表排序：
1. 有可用容量的服务器排在前（有空余 CPU/内存/磁盘的）
2. 无可用容量的服务器排在后
3. 同等条件下，新上传的服务器排在前

#### Scenario: 机器广场展示
- **WHEN** 用户访问 `/market` 或 `GET /api/v1/market`
- **THEN** 服务器列表按「有容量优先 → 无容量在后 → 新建时间倒序」排序

### Requirement: 邀请码备注

系统 SHALL 支持邀请码附带备注，分为私有备注和公开备注。

#### Scenario: 生成邀请码时填写备注
- **WHEN** 管理员在生成邀请码页面填写备注内容并选择可见性
- **THEN** 系统将备注（private_note 和 public_note）存入数据库
- **AND** 邀请码列表页面显示备注信息

#### Scenario: 注册时显示公开备注
- **WHEN** 用户通过携带邀请码的链接注册
- **THEN** 系统在 OAuth 回调页面（或注册确认页）显示该邀请码的公开备注
- **AND** 私有备注仅管理员可见

---

## MODIFIED Requirements

### Requirement: 数据库表结构（修改）

`invites` 表新增字段：
- `private_note TEXT` — 私有备注（仅管理员可见）
- `public_note TEXT` — 公开备注（注册时显示给用户）

`site_config` 新增默认键：
- `health_check_message` — 健康检查欢迎信息

新增 `violations` 表：
- `id` INTEGER PRIMARY KEY AUTOINCREMENT
- `server_id` INTEGER
- `machine_id` INTEGER
- `violation_type` TEXT — 违规类型（vpn, proxy, bandwidth_abuse, etc.）
- `detail` TEXT — 详细信息
- `created_at` DATETIME

### Requirement: Agent 功能（修改）

`agent.py` 新增：
- OpenGFW 集成：启动流量监控，检测 VPN/代理协议特征
- 流量限速：当带宽超过阈值时触发限速
- 违规上报：HTTP POST 到平台 `/api/v1/agent/violations` 上报违规记录

### Requirement: API 接口层（修改）

`/api/v1/` 路由新增以下端点：
- `POST /api/v1/servers/contribute`
- `POST /api/v1/machines/create`
- `POST /api/v1/redeem`
- `POST /api/v1/packages/buy`
- `POST /api/v1/checkin`