# 结算、争议、NAT 与兑换增强 Spec

## Why
当前平台缺少积分延迟结算机制、NAT 内网穿透支持、争议处理系统、赠金有效期管理、以及余额兑换码等功能。这些功能对平台运营效率、商家体验和用户信任至关重要。

## What Changes
- 新增积分延迟到账：用户购买的机器使用超过配置阈值（%）后，核时才到账给贡献者
- 贡献服务器页面新增「暴露 IP 地址」选项，选择后 SSH 直连不经代理
- 新增 NAT 内网穿透：勾选「暴露 IP」后可用，机器发布者配置免费 NAT 端口范围，超出部分按 NAT 倍率计入核时公式
- 新增争议处理/举报系统：用户可发起争议，涉及的积分暂时冻结，商家可回复或退款，超时后平台介入
- 新增赠金有效期：签到赠送的核时可设置有效期，赠金支付后商家到账赠金余额（继承有效期）
- 商家可设置用户开机最大时长
- 新增管理员注册 OAuth2 应用（静默授权，无需用户确认）
- 新增余额兑换码功能：用户可将余额转化为兑换码，后台可配置手续费和每日上限次数

## Impact
- Affected specs: tea-server-platform, api-admin-enhancements, dashboard-api-enhancements
- Affected code: `src/handlers/mod.rs`, `src/handlers/api.rs`, `src/db.rs`, `src/models/mod.rs`, `src/main.rs`, `src/services/mod.rs`, `src/services/core_hours.rs`, `templates/user/contribute.html`, `templates/admin/config.html`, `templates/user/dashboard.html`, `templates/user/market.html`

---

## ADDED Requirements

### Requirement: 积分延迟到账机制
系统 SHALL 支持积分延迟到账：当用户创建的机器已使用时长达到贡献者设定过期时间的可配置百分比（如 80%）后，对应核时才自动结算给服务器贡献者。

#### Scenario: 延迟到账触发
- **WHEN** 用户创建的机器状态变为 `stopped` 或 `deleted`，且已使用时长 >= 服务器过期时间 × 配置的结算阈值
- **THEN** 对应核时自动记入贡献者账户

#### Scenario: 未达阈值不结算
- **WHEN** 机器在达到阈值前被停止或删除
- **THEN** 核时不会结算给贡献者

### Requirement: 贡献服务器暴露 IP 选项
贡献服务器页面 SHALL 提供「暴露 IP 地址」复选框。勾选后，用户的 SSH 连接将直连服务器 IP，不经过平台 SSH 代理。

#### Scenario: 选择暴露 IP
- **WHEN** 贡献者勾选「暴露 IP 地址」
- **THEN** 服务器 `expose_ip` 字段设为 true，后续创建的机器 SSH 端口使用服务器真实 IP:端口

#### Scenario: 不暴露 IP（默认）
- **WHEN** 贡献者未勾选「暴露 IP 地址」
- **THEN** 保持原有行为，SSH 连接走平台代理端口转发

### Requirement: NAT 内网穿透
当贡献者勾选「暴露 IP 地址」时，系统 SHALL 允许配置 NAT 内网穿透。发布者可设置免费 NAT 端口范围（如 10000-10100），超出免费额度的 NAT 端口按 `NAT端口数 × NAT倍率 × 全局NAT倍率` 加入核时计算公式。

#### Scenario: 配置 NAT 端口范围
- **WHEN** 贡献者勾选「暴露 IP」后，在 NAT 配置区域设置免费起始端口和结束端口
- **THEN** 范围内的端口免费，超出部分按 NAT 倍率计费

#### Scenario: 未勾选暴露 IP 时 NAT 不可用
- **WHEN** 贡献者未勾选「暴露 IP 地址」
- **THEN** NAT 配置区域不可见/不可用

### Requirement: 核时计算公式扩展
核时计算公式 SHALL 扩展为：`CPU核数×CPU倍率×全局CPU倍率 + 内存GB×内存倍率×全局内存倍率 + 带宽Mbps×带宽倍率×全局带宽倍率 + 磁盘GB×磁盘倍率×全局磁盘倍率 + NAT端口数×NAT倍率×全局NAT倍率`

#### Scenario: 计算含 NAT 的核时
- **WHEN** 机器使用了超出免费范围的 NAT 端口
- **THEN** 核时计算包含 NAT 项的加值

### Requirement: 争议处理机制
系统 SHALL 提供争议处理（举报）流程：
1. 用户可对某笔交易/机器发起争议，填写原因
2. 发起争议后，对应交易的积分被暂时冻结
3. 系统向商家端发起处理请求
4. 商家可在后台查看争议并回复（退款或出示已完成服务证据）
5. 若商家在配置时间内（默认 72 小时）未处理，平台自动介入
6. 平台介入后可根据证据判定退款或驳回

#### Scenario: 发起争议
- **WHEN** 用户对某台机器点击「发起争议」并填写原因
- **THEN** 相关核时冻结，争议记录创建，商家收到通知

#### Scenario: 商家处理争议
- **WHEN** 商家在后台回复争议（退款/驳回）
- **THEN** 若退款，冻结的核时退还给用户；若驳回，核时释放给商家

#### Scenario: 商家超时未处理
- **WHEN** 争议超过配置时间未处理
- **THEN** 平台自动介入，管理员可手动裁决

### Requirement: 赠金/签到核时有效期
系统 SHALL 支持为签到赠送的核时设置有效期。管理员可在后台配置签到奖励有效期（天数），过期自动清零。

#### Scenario: 赠金到期
- **WHEN** 签到奖励核时超过配置的有效期天数
- **THEN** 过期核时自动从用户余额中扣除

### Requirement: 赠金余额与商家到账
当用户使用赠金支付核时费用时，商家收到的 SHALL 是赠金余额而非普通余额，且该赠金余额的有效期 SHALL 继承原赠金余额的剩余有效期。

#### Scenario: 赠金支付给商家
- **WHEN** 用户使用赠金支付机器费用
- **THEN** 商家收到等额赠金余额，有效期 = 原赠金剩余有效期

### Requirement: 商家设置最大开机时长
服务器贡献者 SHALL 可在贡献服务器时设置「用户最大开机时长」（小时），限制用户在该服务器上创建机器的最大运行时长。

#### Scenario: 设置最大开机时长
- **WHEN** 贡献者设置最大开机时长为 720 小时（30 天）
- **THEN** 用户在该服务器上创建机器时，时长上限为 720 小时

### Requirement: 管理员注册 OAuth2 应用
系统 SHALL 支持管理员在后台注册 OAuth2 应用（Client ID / Client Secret），授权过程为静默授权，无需用户点击确认。

#### Scenario: 第三方应用接入
- **WHEN** 第三方应用使用管理员注册的 OAuth2 凭据发起授权请求
- **THEN** 系统静默完成授权，无需用户手动确认

### Requirement: 余额兑换码功能
系统 SHALL 支持用户将余额（赠金或充值余额）转化为兑换码。管理员可在后台配置手续费比例和每日兑换次数上限。赠金转换的兑换码有效期不会暂停，继续计算。

#### Scenario: 用户生成兑换码
- **WHEN** 用户在兑换码页面选择金额并提交
- **THEN** 扣除余额 + 手续费后生成兑换码

#### Scenario: 每日上限
- **WHEN** 用户当日兑换次数已达上限
- **THEN** 拒绝兑换并提示

#### Scenario: 赠金兑换码有效期不暂停
- **WHEN** 用户使用赠金余额生成兑换码
- **THEN** 兑换码的有效期与原赠金有效期一致，不会暂停计算