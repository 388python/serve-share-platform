# 仪表盘与 API 增强 Spec

## Why
当前系统缺少面向全体用户的统计数据看板、API 文档、流量安全监控，以及邀请码备注等运营工具。同时机器广场排序逻辑需要优化，API 层也需要补充 POST 端点以支持完整的第三方集成。

## What Changes
- 新增 `GET /api/v1/health` 欢迎 JSON 响应，启动时打印平台信息
- 用户仪表盘新增「我的 API Key」显示与复制区域
- API 层新增 POST 端点：contribute server、create machine、redeem code、buy package
- 新增 `README.md` 中 API 使用说明与 curl 示例
- 新增 OpenGFW 流量监控后台任务，阻断 VPN 协议与异常大带宽流量
- 站长已可通过现有 `is_banned` 功能封禁账号（API 已支持）
- 优化机器广场排序：有剩余容量的排前面，无容量的排最后，新上传的优先
- 邀请码生成时支持备注（私有备注 + 公开备注），公开备注在注册页面展示
- 新增面向所有用户的数据看板页面（总用户数、总机器数、在线机器数等）

## Impact
- Affected specs: api-admin-enhancements
- Affected code: `src/main.rs`, `src/handlers/api.rs`, `src/handlers/mod.rs`, `src/db.rs`, `src/services/mod.rs`, `templates/user/dashboard.html`, `templates/admin/invites.html`, `templates/user/market.html`, `README.md`

## ADDED Requirements

### Requirement: 启动欢迎 JSON 响应
系统 SHALL 在启动后提供 `GET /api/v1/health` 端点，返回平台名称、版本、启动时间等 JSON 信息。

#### Scenario: 健康检查返回欢迎信息
- **WHEN** 用户访问 `GET /api/v1/health`
- **THEN** 返回 `{"platform": "茶的服务器公益站", "version": "0.1.0", "started_at": "..."}`

### Requirement: 用户仪表盘 API Key 显示
用户仪表盘 SHALL 显示当前用户的 API Key，支持一键复制和重新生成。

#### Scenario: 查看 API Key
- **WHEN** 已登录用户访问 `/dashboard`
- **THEN** 页面显示「我的 API Key」区域，包含当前 API Key（脱敏显示）和复制/重新生成按钮

### Requirement: API POST 端点
API 层 SHALL 支持以下 POST 端点：
- `POST /api/v1/servers/contribute` — 贡献服务器
- `POST /api/v1/machines/create` — 创建机器
- `POST /api/v1/redeem` — 兑换码兑换
- `POST /api/v1/packages/buy` — 购买套餐

#### Scenario: 通过 API 贡献服务器
- **WHEN** 用户使用 Bearer token 发送 JSON 到 `POST /api/v1/servers/contribute`
- **THEN** 服务器信息被写入数据库，返回成功响应

#### Scenario: 通过 API 创建机器
- **WHEN** 用户使用 Bearer token 发送 JSON 到 `POST /api/v1/machines/create`
- **THEN** 核时校验通过后创建机器，返回机器信息

### Requirement: API 文档
项目 SHALL 在 README.md 中包含完整的 API 使用说明和 curl 示例。

#### Scenario: 开发者查看 API 文档
- **WHEN** 开发者阅读 README.md
- **THEN** 能看到所有 API 端点列表、认证方式、示例 curl 命令

### Requirement: OpenGFW 流量监控
系统 SHALL 在后台运行流量监控任务，检测并阻断 VPN 协议流量（包括但不限于 OpenVPN、WireGuard、Shadowsocks、VMess、Trojan 等）以及异常大带宽占用流量。

#### Scenario: 检测到 VPN 流量
- **WHEN** 系统检测到某台机器存在 VPN 协议流量特征
- **THEN** 自动停止该机器，记录日志，并在管理后台展示告警

#### Scenario: 检测到异常带宽占用
- **WHEN** 某台机器带宽持续超过阈值（默认 100 Mbps，可配置）
- **THEN** 自动限制或停止该机器，记录日志

### Requirement: 机器广场排序优化
机器广场列表 SHALL 按以下规则排序：
1. 有剩余容量（CPU/内存/磁盘未被全部占用）的服务器排前面
2. 无剩余容量的服务器排最后
3. 同等条件下，新上传的服务器优先

#### Scenario: 查看机器广场
- **WHEN** 用户访问 `/market`
- **THEN** 有容量的服务器显示在前，无容量的显示在后，新服务器优先

### Requirement: 邀请码备注
管理员生成邀请码时 SHALL 可添加备注，包括：
- 私有备注（仅管理员可见）
- 公开备注（注册时在页面上显示给用户）

#### Scenario: 生成带备注的邀请码
- **WHEN** 管理员在邀请码生成表单中填写备注
- **THEN** 邀请码携带备注信息，公开备注在用户注册时显示

#### Scenario: 用户使用带公开备注的邀请码注册
- **WHEN** 用户通过带公开备注的邀请码链接注册
- **THEN** 注册页面显示该公开备注内容

### Requirement: 用户数据看板
系统 SHALL 提供面向所有用户（无需登录）的数据看板页面，展示平台统计数据。

#### Scenario: 查看数据看板
- **WHEN** 用户访问 `/stats` 页面
- **THEN** 显示：总注册用户数、总贡献服务器数、总运行机器数、总核时消耗量、平台运行天数等