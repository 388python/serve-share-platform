# Checklist: 仪表盘与 API 增强

## 启动欢迎 JSON 响应
- [x] `GET /api/v1/health` 返回平台名称、版本、启动时间 JSON
- [x] 无需认证即可访问

## 用户仪表盘 API Key
- [x] `/dashboard` 页面显示「我的 API Key」区域
- [x] API Key 脱敏显示（默认截断为 16 字符 + "..."，点击「显示」查看完整）
- [x] 支持一键复制和重新生成按钮
- [x] 重新生成后旧 Key 立即失效

## API POST 端点
- [x] `POST /api/v1/servers/contribute` 可成功创建服务器记录
- [x] `POST /api/v1/machines/create` 核时校验通过后创建机器
- [x] `POST /api/v1/redeem` 可兑换兑换码
- [x] `POST /api/v1/packages/buy` 可购买套餐
- [x] 所有 POST 端点返回正确的 JSON 响应

## README.md API 文档
- [x] 文档包含所有 API 端点列表
- [x] 包含认证方式说明（Bearer token）
- [x] 包含 curl 示例命令

## OpenGFW 流量监控
- [x] `traffic_monitor_enabled` 配置项可控制开关
- [x] `traffic_bandwidth_threshold_mbps` 可配置带宽阈值
- [x] 检测到 VPN 协议流量时自动停止机器（通过查询 agent 端口和进程）
- [x] 检测到超阈值带宽时自动停止机器（通过查询 agent 流量数据）
- [x] 告警记录写入 `traffic_alerts` 表
- [x] 管理后台可查看告警记录（`/admin/traffic-alerts` + 导航链接）

## 机器广场排序
- [x] 有剩余容量的服务器排在最前面
- [x] 无剩余容量的服务器排在最后
- [x] 同等条件下新上传的服务器优先

## 邀请码备注
- [x] `invites` 表有 `private_note` 和 `public_note` 字段
- [x] 管理员生成邀请码时可填写备注
- [x] 邀请码列表页显示备注
- [x] 用户注册时可见公开备注（通过 OAuth 回调错误 URL 参数传递）

## 用户数据看板
- [x] `/stats` 页面无需登录可访问
- [x] 显示总注册用户数
- [x] 显示总贡献服务器数
- [x] 显示总运行机器数
- [x] 导航栏有「数据看板」入口

## 编译验证
- [x] `cargo check` 编译通过
- [x] 无新增编译错误