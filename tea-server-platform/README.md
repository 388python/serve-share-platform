# 茶的服务器公益站

一个基于 Rust 构建的服务器共享平台，旨在让用户贡献闲置服务器资源，其他用户可按需租用虚拟机，并通过"核时"体系进行资源计量与结算。

## 功能特性

- **LinuxDo Connect OAuth 登录** — 通过 LinuxDo Connect 进行身份认证，安全便捷
- **服务器贡献** — 用户可贡献自己的闲置服务器，支持 LXD/Infiniband 等多种虚拟化类型
- **机器市场** — 浏览可用服务器，按需创建虚拟机（VM）
- **核时系统** — 基于 CPU 核数 × 使用时间的资源计量体系，公平透明
- **LDC 支付集成** — 集成 LDC 支付网关，支持充值与提现
- **SSH 代理转发** — 自动代理 SSH 连接，无需暴露服务器真实 IP
- **代理端自动部署** — 通过 SSH 自动在贡献服务器上安装管理代理
- **RESTful API** — 提供完整的 JSON API，支持 API Key 认证，适合自动化与脚本调用
- **邀约码与兑换码** — 支持邀请制注册和兑换码福利
- **每日签到** — 用户可每日签到领取核时奖励
- **管理后台** — 完善的管理面板，支持用户管理、服务器管理、配置调整等

## 快速开始

### 前置要求

- [Rust](https://rustup.rs) 1.75+
- SQLite 3

### 安装与运行

```bash
# 克隆仓库
git clone <repository-url>
cd tea-server-platform

# 配置环境变量
cp .env.example .env
# 编辑 .env，填入 LinuxDo OAuth 凭证等信息

# 编译并运行
cargo run
```

服务默认监听 `0.0.0.0:3000`。

## 环境变量

以下所有变量通过 `.env` 文件配置：

| 变量名 | 必需 | 默认值 | 说明 |
|--------|------|--------|------|
| `DATABASE_URL` | 否 | `sqlite:tea-server.db?mode=rwc` | SQLite 数据库连接字符串 |
| `BIND_ADDR` | 否 | `0.0.0.0:3000` | 服务监听地址 |
| `SESSION_SECRET` | 是 | `change-me-to-a-random-secret` | Session 加密密钥，生产环境务必更换 |
| `LINUXDO_CLIENT_ID` | 是 | — | LinuxDo Connect OAuth Client ID |
| `LINUXDO_CLIENT_SECRET` | 是 | — | LinuxDo Connect OAuth Client Secret |
| `LINUXDO_REDIRECT_URI` | 否 | `https://example.com/auth/callback` | OAuth 回调地址 |
| `LINUXDO_AUTH_URL` | 否 | `https://connect.linux.do/oauth2/authorize` | OAuth 授权端点 |
| `LINUXDO_TOKEN_URL` | 否 | `https://connect.linux.do/oauth2/token` | OAuth Token 端点 |
| `LINUXDO_USER_INFO_URL` | 否 | `https://connect.linux.do/api/user` | OAuth 用户信息端点 |
| `PLATFORM_DOMAIN` | 否 | `https://example.com` | 平台域名，用于生成回调地址等 |
| `ADMIN_USERNAME` | 否 | `admin` | 管理员登录用户名 |
| `ADMIN_PASSWORD` | 否 | `admin` | 管理员登录密码（生产环境务必修改） |
| `SSH_PROXY_PORT_START` | 否 | `30001` | SSH 代理端口起始值 |
| `SSH_PROXY_PORT_COUNT` | 否 | `100` | SSH 代理端口数量（分配范围） |

## API 文档

所有 API 接口前缀为 `/api/v1`，返回 JSON 格式。用户 API 需要 `Authorization: Bearer <api_key>` 请求头认证，管理员 API 可使用管理员 API Key 或具有管理员权限的用户 API Key。

**通用响应格式：**

```json
// 成功
{ "success": true, "data": { ... } }

// 失败
{ "error": "error_code", "message": "Human readable message" }
```

---

### 用户 API

所有用户 API 需在请求头中携带 API Key：`Authorization: Bearer usr_xxx`

#### GET /api/v1/me — 获取当前用户信息

```bash
curl -H "Authorization: Bearer usr_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx" \
     https://your-domain.com/api/v1/me
```

响应示例：

```json
{
  "success": true,
  "data": {
    "id": 1,
    "linuxdo_id": 12345,
    "username": "tea_lover",
    "email": "tea@example.com",
    "ldc_balance": 100.0,
    "core_hours": 50.5,
    "total_usage_hours": 200.0,
    "is_admin": false,
    "is_banned": false,
    "created_at": "2025-01-01T00:00:00Z",
    "last_checkin": "2025-01-15T08:00:00Z"
  }
}
```

#### POST /api/v1/me/api-key — 重新生成 API Key

```bash
curl -X POST \
     -H "Authorization: Bearer usr_old_key" \
     https://your-domain.com/api/v1/me/api-key
```

#### GET /api/v1/servers — 我贡献的服务器

```bash
curl -H "Authorization: Bearer usr_xxx" \
     https://your-domain.com/api/v1/servers
```

#### POST /api/v1/servers/contribute — 贡献服务器

```bash
curl -X POST \
     -H "Authorization: Bearer usr_xxx" \
     -H "Content-Type: application/json" \
     -d '{
       "name": "我的服务器",
       "ip": "192.168.1.100",
       "ssh_port": 22,
       "ssh_key": "ssh-rsa AAAAB3...",
       "cpu_cores": 16,
       "memory_gb": 64,
       "disk_gb": 500,
       "bandwidth_mbps": 100,
       "cpu_multiplier": 1.0,
       "memory_multiplier": 1.0,
       "bandwidth_multiplier": 1.0,
       "disk_multiplier": 1.0,
       "use_bonus": false,
       "virt_type": "lxd",
       "expires_days": 30
     }' \
     https://your-domain.com/api/v1/servers/contribute
```

#### GET /api/v1/machines — 我的虚拟机

```bash
curl -H "Authorization: Bearer usr_xxx" \
     https://your-domain.com/api/v1/machines
```

#### POST /api/v1/machines/create — 创建虚拟机

```bash
curl -X POST \
     -H "Authorization: Bearer usr_xxx" \
     -H "Content-Type: application/json" \
     -d '{
       "server_id": 1,
       "cpu_cores": 2,
       "memory_gb": 4,
       "disk_gb": 50,
       "hours": 24
     }' \
     https://your-domain.com/api/v1/machines/create
```

#### GET /api/v1/market — 机器市场

```bash
curl -H "Authorization: Bearer usr_xxx" \
     https://your-domain.com/api/v1/market
```

#### GET /api/v1/orders — 我的订单

```bash
curl -H "Authorization: Bearer usr_xxx" \
     https://your-domain.com/api/v1/orders
```

#### GET /api/v1/packages — 可用套餐

```bash
curl -H "Authorization: Bearer usr_xxx" \
     https://your-domain.com/api/v1/packages
```

#### POST /api/v1/packages/buy — 购买套餐

```bash
curl -X POST \
     -H "Authorization: Bearer usr_xxx" \
     -H "Content-Type: application/json" \
     -d '{"package_id": 1}' \
     https://your-domain.com/api/v1/packages/buy
```

#### POST /api/v1/redeem — 兑换码兑换

```bash
curl -X POST \
     -H "Authorization: Bearer usr_xxx" \
     -H "Content-Type: application/json" \
     -d '{"code": "abc123def456"}' \
     https://your-domain.com/api/v1/redeem
```

#### POST /api/v1/checkin — 每日签到

```bash
curl -X POST \
     -H "Authorization: Bearer usr_xxx" \
     https://your-domain.com/api/v1/checkin
```

---

### 管理员 API

管理员 API 可使用专用管理员 API Key（在管理后台配置）或具有 `is_admin = true` 的用户 API Key 进行认证。

#### GET /api/v1/admin/users — 所有用户列表

```bash
curl -H "Authorization: Bearer admin_key_or_usradmin_xxx" \
     https://your-domain.com/api/v1/admin/users
```

#### GET /api/v1/admin/users/:id — 查看用户详情

```bash
curl -H "Authorization: Bearer admin_key_or_usradmin_xxx" \
     https://your-domain.com/api/v1/admin/users/1
```

#### PUT /api/v1/admin/users/:id — 修改用户（调整余额、封禁、管理员）

```bash
curl -X PUT \
     -H "Authorization: Bearer admin_key_or_usradmin_xxx" \
     -H "Content-Type: application/json" \
     -d '{
       "core_hours": 500.0,
       "ldc_balance": 200.0,
       "is_banned": false,
       "is_admin": true
     }' \
     https://your-domain.com/api/v1/admin/users/1
```

| 字段 | 类型 | 说明 |
|------|------|------|
| `core_hours` | float | 设置核时余额 |
| `ldc_balance` | float | 设置 LDC 余额 |
| `is_banned` | bool | 封禁/解封用户 |
| `is_admin` | bool | 授予/撤销管理员权限 |

#### GET /api/v1/admin/servers — 所有服务器

```bash
curl -H "Authorization: Bearer admin_key" \
     https://your-domain.com/api/v1/admin/servers
```

#### POST /api/v1/admin/servers/:id/toggle — 启用/禁用服务器

```bash
curl -X POST \
     -H "Authorization: Bearer admin_key" \
     https://your-domain.com/api/v1/admin/servers/1/toggle
```

#### GET /api/v1/admin/machines — 所有虚拟机

```bash
curl -H "Authorization: Bearer admin_key" \
     https://your-domain.com/api/v1/admin/machines
```

#### GET /api/v1/admin/config — 站点配置

```bash
curl -H "Authorization: Bearer admin_key" \
     https://your-domain.com/api/v1/admin/config
```

#### PUT /api/v1/admin/config — 修改站点配置

```bash
curl -X PUT \
     -H "Authorization: Bearer admin_key" \
     -H "Content-Type: application/json" \
     -d '{"key": "checkin_reward", "value": "20"}' \
     https://your-domain.com/api/v1/admin/config
```

常用配置项：`site_name`、`checkin_enabled`、`checkin_reward`、`free_plan_enabled`、`registration_enabled`、`require_invite`、`recharge_multiplier`、`recharge_fee`、`withdraw_fee`、`select_mode`、`lock_bonus`、`virt_type` 等。

#### GET /api/v1/admin/orders — 所有订单

```bash
curl -H "Authorization: Bearer admin_key" \
     https://your-domain.com/api/v1/admin/orders
```

#### GET /api/v1/admin/packages — 所有套餐

```bash
curl -H "Authorization: Bearer admin_key" \
     https://your-domain.com/api/v1/admin/packages
```

---

### 常用操作 curl 示例

**获取当前用户信息：**

```bash
curl -H "Authorization: Bearer usr_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx" \
     https://your-domain.com/api/v1/me
```

**创建虚拟机：**

```bash
curl -X POST \
     -H "Authorization: Bearer usr_xxx" \
     -H "Content-Type: application/json" \
     -d '{"server_id":1,"cpu_cores":2,"memory_gb":4,"disk_gb":50,"hours":24}' \
     https://your-domain.com/api/v1/machines/create
```

**兑换码兑换：**

```bash
curl -X POST \
     -H "Authorization: Bearer usr_xxx" \
     -H "Content-Type: application/json" \
     -d '{"code":"my-redeem-code"}' \
     https://your-domain.com/api/v1/redeem
```

**调整用户余额（管理员）：**

```bash
curl -X PUT \
     -H "Authorization: Bearer admin_key" \
     -H "Content-Type: application/json" \
     -d '{"core_hours": 1000.0}' \
     https://your-domain.com/api/v1/admin/users/1
```

## 架构概览

本项目采用经典的 Rust Web 技术栈：

- **[axum](https://github.com/tokio-rs/axum)** — 高性能异步 HTTP 框架，基于 `tower` 中间件生态
- **[tokio](https://tokio.rs)** — 异步运行时，驱动全异步 I/O 和后台任务调度
- **[sqlx](https://github.com/launchbadge/sqlx)** — 异步、编译期检查的 SQL 工具包，直接操作 SQLite 数据库
- **[tera](https://tera.netlify.app)** — 服务端模板引擎，渲染 HTML 页面
- **[ssh2](https://docs.rs/ssh2)** — SSH2 协议客户端，实现代理端自动部署
- **[tower-http](https://docs.rs/tower-http)** — HTTP 中间件，提供静态文件服务、Cookie 管理等
- **[reqwest](https://docs.rs/reqwest)** — HTTP 客户端，与 OAuth 服务、代理端、支付网关通信

**架构设计要点：**

- **前后端一体**：直接渲染 HTML 模板返回页面，无需额外的前端构建
- **后台任务**：通过 `tokio::spawn` 运行过期机器清理、SSH 代理转发等后台循环
- **Web 表单 + RESTful API 双通道**：用户可通过浏览器页面操作，也可通过 API Key 调用 JSON 接口
- **SQLite 单文件数据库**：轻量部署，无需额外数据库服务

## 许可证

[MIT](LICENSE)