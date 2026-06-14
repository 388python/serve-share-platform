# 茶的服务器公益站

基于 Rust + Axum 的服务器公益共享平台，用户可贡献闲置服务器资源，也可按需创建虚拟机实例。

## 认证方式

所有需要认证的 API 端点均使用 Bearer Token 认证。在请求头中携带：

```
Authorization: Bearer {api_key}
```

用户可通过 `GET /api/v1/me` 获取自己的 API Key，或通过 `POST /api/v1/me/api-key` 重新生成。

## API 端点

### 健康检查

| 方法 | 路径 | 认证 | 说明 |
|------|------|------|------|
| GET | `/api/v1/health` | 否 | 返回平台欢迎信息、版本号和启动时间 |

### 用户

| 方法 | 路径 | 认证 | 说明 |
|------|------|------|------|
| GET | `/api/v1/me` | 是 | 获取当前用户信息 |
| POST | `/api/v1/me/api-key` | 是 | 重新生成 API Key |

### 服务器

| 方法 | 路径 | 认证 | 说明 |
|------|------|------|------|
| GET | `/api/v1/servers` | 是 | 获取当前用户贡献的服务器列表 |
| POST | `/api/v1/servers/contribute` | 是 | 贡献一台新服务器 |

### 虚拟机

| 方法 | 路径 | 认证 | 说明 |
|------|------|------|------|
| GET | `/api/v1/machines` | 是 | 获取当前用户的虚拟机列表 |
| POST | `/api/v1/machines/create` | 是 | 创建一台新虚拟机 |

### 市场

| 方法 | 路径 | 认证 | 说明 |
|------|------|------|------|
| GET | `/api/v1/market` | 否 | 获取可用服务器市场列表 |

### 订单

| 方法 | 路径 | 认证 | 说明 |
|------|------|------|------|
| GET | `/api/v1/orders` | 是 | 获取当前用户的订单列表 |

### 套餐

| 方法 | 路径 | 认证 | 说明 |
|------|------|------|------|
| GET | `/api/v1/packages` | 否 | 获取可用充值套餐列表 |
| POST | `/api/v1/packages/buy` | 是 | 购买套餐 |

### 兑换码

| 方法 | 路径 | 认证 | 说明 |
|------|------|------|------|
| POST | `/api/v1/redeem` | 是 | 使用兑换码兑换奖励 |

### 管理员

| 方法 | 路径 | 认证 | 说明 |
|------|------|------|------|
| GET | `/api/v1/admin/users` | 是（管理员） | 获取所有用户列表 |
| GET | `/api/v1/admin/users/:id` | 是（管理员） | 查看单个用户详情 |
| PUT | `/api/v1/admin/users/:id` | 是（管理员） | 更新用户信息 |
| GET | `/api/v1/admin/servers` | 是（管理员） | 获取所有服务器列表 |
| POST | `/api/v1/admin/servers/:id/toggle` | 是（管理员） | 切换服务器启用/禁用 |
| GET | `/api/v1/admin/machines` | 是（管理员） | 获取所有虚拟机列表 |
| GET | `/api/v1/admin/config` | 是（管理员） | 获取站点配置 |
| PUT | `/api/v1/admin/config` | 是（管理员） | 更新站点配置 |
| GET | `/api/v1/admin/orders` | 是（管理员） | 获取所有订单 |
| GET | `/api/v1/admin/packages` | 是（管理员） | 获取所有套餐 |

## curl 示例

### 获取欢迎信息

```bash
curl http://localhost:3000/api/v1/health
```

### 获取当前用户信息

```bash
curl -H "Authorization: Bearer usr_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx" \
  http://localhost:3000/api/v1/me
```

### 贡献服务器

```bash
curl -X POST http://localhost:3000/api/v1/servers/contribute \
  -H "Authorization: Bearer usr_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx" \
  -H "Content-Type: application/json" \
  -d '{
    "name": "我的服务器",
    "ip": "192.168.1.100",
    "ssh_port": 22,
    "ssh_key": "ssh-ed25519 AAAA...",
    "cpu_cores": 8,
    "memory_gb": 32.0,
    "bandwidth_mbps": 100.0,
    "disk_gb": 500.0,
    "cpu_multiplier": 1.0,
    "memory_multiplier": 1.0,
    "bandwidth_multiplier": 1.0,
    "disk_multiplier": 1.0,
    "use_bonus": false,
    "virt_type": "lxd",
    "expires_days": 30
  }'
```

### 创建虚拟机

```bash
curl -X POST http://localhost:3000/api/v1/machines/create \
  -H "Authorization: Bearer usr_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx" \
  -H "Content-Type: application/json" \
  -d '{
    "server_id": 1,
    "cpu_cores": 2,
    "memory_gb": 4.0,
    "disk_gb": 50.0,
    "hours": 24
  }'
```

### 获取管理员用户列表

```bash
curl -H "Authorization: Bearer {admin_api_key}" \
  http://localhost:3000/api/v1/admin/users
```

### 兑换码

```bash
curl -X POST http://localhost:3000/api/v1/redeem \
  -H "Authorization: Bearer usr_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx" \
  -H "Content-Type: application/json" \
  -d '{"code": "your-redeem-code"}'
```

### 购买套餐

```bash
curl -X POST http://localhost:3000/api/v1/packages/buy \
  -H "Authorization: Bearer usr_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx" \
  -H "Content-Type: application/json" \
  -d '{"package_id": 1}'
```