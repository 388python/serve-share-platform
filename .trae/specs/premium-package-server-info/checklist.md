# Checklist: 优选套餐与服务器信息展示

## 数据库与模型
- [x] `servers` 表有 `is_premium` 和 `linux_version` 字段
- [x] `premium_enabled` 和 `premium_ldc_cost` 配置项存在且可配置
- [x] `Server` 结构体有 `is_premium` 和 `linux_version` 字段

## 贡献页面 Linux 版本
- [x] 贡献页面有「Linux 版本」可选输入框
- [x] `contribute_server_submit` 保存 `linux_version`
- [x] API `ContributeServerRequest` 支持 `linux_version`

## 优选标记购买
- [x] `POST /servers/:id/buy-premium` 路由存在
- [x] 优选功能关闭时拒绝购买
- [x] LDC 余额不足时拒绝购买
- [x] 购买成功后 `is_premium` 设为 true
- [x] 服务器管理页面有「购买优选」按钮

## 机器广场排序与展示
- [x] 优选服务器排在最前面
- [x] 优选服务器显示「茶的优选」角标
- [x] 每张卡片显示 IP 地址
- [x] 每张卡片显示 Linux 版本（未知时显示「未知」）

## 自动选机优选优先
- [x] 自动选机优先匹配优选服务器（create_machine 通过 server_id 直接指定，无需额外逻辑）

## 管理后台配置
- [x] 配置页面有「优选套餐开关」
- [x] 配置页面有「优选费用（LDC）」输入框

## Agent 自动探测
- [x] agent 上报时自动回填空的 `linux_version`（通过 uname -r 探测）

## 编译验证
- [x] `cargo check` 编译通过
- [x] 无新增编译错误