# Checklist: 结算、争议、NAT 与兑换增强

## 积分延迟到账
- [x] `settlement_threshold_pct` 配置项存在且可配置
- [x] `machines` 表有 `settled` 和 `used_hours` 字段
- [x] 机器停止时若使用时长 >= 阈值，自动结算核时给贡献者
- [x] 未达阈值不结算

## 暴露 IP 选项
- [x] `servers` 表有 `expose_ip` 字段
- [x] 贡献页面有「暴露 IP 地址」复选框
- [x] 勾选暴露 IP 后，SSH 连接返回直连信息
- [x] 不勾选时保持原有代理转发行为

## NAT 内网穿透
- [x] `servers` 表有 `nat_port_start`、`nat_port_end`、`nat_multiplier` 字段
- [x] 仅当勾选「暴露 IP」时 NAT 配置区域可见
- [x] 核时公式包含 `+ NAT端口数×NAT倍率×全局NAT倍率`
- [x] 管理后台可配置全局 NAT 倍率

## 争议处理
- [x] `disputes` 表存在且结构正确
- [x] 用户可发起争议（填写原因）
- [x] 发起争议后相关积分冻结
- [x] 商家可回复争议（退款/驳回）
- [x] 超时后平台自动介入
- [x] 管理后台可查看和处理争议
- [x] 争议超时时间可配置

## 赠金有效期
- [x] `users` 表有 `bonus_core_hours` 和 `bonus_expires_at` 字段
- [x] 签到发放的核时记录到 `bonus_core_hours` 并设置有效期
- [x] 过期赠金自动清零
- [x] 赠金支付后商家到账赠金余额（继承有效期）
- [x] 签到赠金有效期可配置

## 商家最大开机时长
- [x] `servers` 表有 `max_machine_hours` 字段
- [x] 贡献页面可设置最大开机时长
- [x] 创建机器时校验不超过最大开机时长

## OAuth2 应用注册
- [x] `oauth_apps` 表存在且结构正确
- [x] 管理员可注册/管理 OAuth2 应用
- [x] 静默授权端点无需用户确认
- [x] `client_id`/`client_secret` 验证正确

## 余额兑换码
- [x] 兑换码生成逻辑正确（扣除余额 + 手续费）
- [x] 每日兑换次数限制生效
- [x] 手续费率和每日上限可配置
- [x] 赠金兑换码有效期不暂停
- [x] API 端点 `POST /api/v1/balance-to-code` 可用

## 编译验证
- [x] `cargo check` 编译通过
- [x] 无新增编译错误