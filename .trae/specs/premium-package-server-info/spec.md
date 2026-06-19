# 优选套餐与服务器信息展示 Spec

## Why
当前机器广场和自动选机缺少优先级机制，优质服务器无法获得更多曝光；同时用户在选机时无法看到服务器地址和 Linux 版本等关键信息，影响选机决策。新增「茶的优选」付费置顶功能可激励贡献者提供更优质资源，同时提升平台 LDC 消耗。

## What Changes
- 管理后台新增「优选套餐」开关（`premium_enabled`）和优选费用配置（`premium_ldc_cost`）
- `servers` 表新增 `is_premium` 字段（标记优选状态）和 `linux_version` 字段（Linux 发行版版本）
- 贡献服务器页面新增 Linux 版本输入框（可选，留空则由 agent 自动探测）
- 贡献者可付费 LDC 将自己的服务器标记为「茶的优选」
- 机器广场排序：优选服务器置顶 → 有剩余容量 → 无容量 → 按 created_at DESC
- 自动选机模式：优选服务器优先匹配
- 机器广场和自动选机页面显示服务器 IP 地址和 Linux 版本
- 优选服务器在列表中显示「茶的优选」角标

## Impact
- Affected specs: tea-server-platform, settlement-dispute-nat-enhancements
- Affected code: `src/db.rs`, `src/models/mod.rs`, `src/handlers/mod.rs`, `src/handlers/api.rs`, `templates/user/market.html`, `templates/user/contribute.html`, `templates/admin/config.html`, `templates/user/machines.html`

---

## ADDED Requirements

### Requirement: 优选套餐开关
管理员 SHALL 可在后台配置是否开放「优选套餐」功能。关闭后，所有服务器的优选标记不生效，贡献者无法购买优选。

#### Scenario: 管理员开启优选
- **WHEN** 管理员在后台配置页面将「优选套餐」设为开启
- **THEN** 贡献者可付费 LDC 标记服务器为优选，机器广场中优选服务器置顶

#### Scenario: 管理员关闭优选
- **WHEN** 管理员将「优选套餐」设为关闭
- **THEN** 已标记优选的服务器不再显示角标和置顶，贡献者无法购买新的优选

### Requirement: 优选标记购买
贡献者 SHALL 可通过支付 LDC 将自己的服务器标记为「茶的优选」。优选费用由管理员配置（`premium_ldc_cost`）。

#### Scenario: 购买优选标记
- **WHEN** 贡献者在服务器管理页面点击「购买优选」并确认支付
- **AND** 贡献者 LDC 余额充足
- **THEN** 扣除对应 LDC，服务器 `is_premium` 设为 true

#### Scenario: LDC 余额不足
- **WHEN** 贡献者 LDC 余额不足
- **THEN** 拒绝购买，提示余额不足

#### Scenario: 优选功能关闭时购买
- **WHEN** 优选功能已关闭，贡献者尝试购买
- **THEN** 拒绝购买，提示功能未开放

### Requirement: 机器广场优选置顶
机器广场列表 SHALL 按以下优先级排序：
1. 优选服务器（`is_premium=1`）置顶
2. 有剩余容量的服务器
3. 无剩余容量的服务器
4. 同级别内按 `created_at DESC`

#### Scenario: 优选服务器置顶
- **WHEN** 用户访问机器广场
- **THEN** 标记为优选的服务器显示在列表最前面，并带「茶的优选」角标

### Requirement: 自动选机优选优先
当选机模式为「系统自动选机」时，系统 SHALL 优先将用户匹配到优选服务器。

#### Scenario: 自动匹配优选优先
- **WHEN** 用户在自动选机模式下创建机器
- **THEN** 系统优先从优选服务器中匹配满足资源需求的服务器

### Requirement: 服务器信息展示
机器广场和自动选机页面 SHALL 显示服务器的 IP 地址和 Linux 版本信息。

#### Scenario: 查看服务器信息
- **WHEN** 用户浏览机器广场或自动选机页面
- **THEN** 每台服务器卡片显示 IP 地址和 Linux 版本（如未探测到则显示「未知」）

### Requirement: Linux 版本采集
贡献者 SHALL 可在贡献服务器时手动填写 Linux 版本（可选）。若留空，系统 SHALL 在 agent 安装时自动探测并回填。

#### Scenario: 手动填写 Linux 版本
- **WHEN** 贡献者在贡献表单中填写 Linux 版本（如 "Ubuntu 22.04"）
- **THEN** 该版本信息保存到服务器记录

#### Scenario: Agent 自动探测
- **WHEN** 贡献者未填写 Linux 版本，agent 安装完成后
- **THEN** agent 上报系统版本，平台自动回填 `linux_version` 字段