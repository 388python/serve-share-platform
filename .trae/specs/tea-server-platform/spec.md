# 茶的服务器公益站 Spec

## Why

构建一个基于 Rust 的服务器资源共享平台，允许用户通过 LinuxDo OAuth 登录后贡献和租用服务器资源（LXD/KVM 虚拟化），使用 LDC（LinuxDo Credit）积分进行核时结算，管理员可通过后台配置全局参数、管理套餐与用户。

## What Changes

- 新建 Rust Web 项目，实现完整的服务器公益共享平台
- 实现 LinuxDo Connect OAuth 登录（唯一登录方式）
- 实现管理员独立路径登录 `/admin-login/?username=xxx&password=xxxx`
- 用户端：贡献服务器、浏览机器广场/系统自动选机、开机器、核时消费
- 管理后台：站点配置、套餐管理、订阅码/核时码生成、用户管理
- 集成 LinuxDo Credit 支付 API（官方 Ed25519 签名 + 易支付兼容 MD5 签名双模式）
- SSH 端口转发代理，不暴露原始服务器 IP
- 贡献服务器时自动安装套件（虚拟化管理 agent）

## Impact

- Affected specs: 无（全新项目）
- Affected code: 全新代码库

---

## ADDED Requirements

### Requirement: 用户认证系统

系统 SHALL 使用 LinuxDo Connect OAuth 作为唯一用户登录方式，不提供密码登录等任何其他登录方式。

#### Scenario: 用户通过 OAuth 登录
- **WHEN** 用户点击「登录」按钮
- **THEN** 系统跳转至 LinuxDo Connect OAuth 授权页面
- **AND** 用户授权后回调至平台，创建或匹配用户账号
- **AND** 登录成功后跳转至首页

#### Scenario: 管理员通过路径登录
- **WHEN** 访问 `/admin-login/?username=xxx&password=xxxx`
- **THEN** 系统验证用户名和密码
- **AND** 验证通过后设置管理员 session
- **AND** 跳转至管理后台首页

### Requirement: 服务器贡献

系统 SHALL 允许已登录用户贡献服务器资源，贡献时需填写完整信息。

#### Scenario: 贡献服务器
- **WHEN** 用户在贡献页面提交服务器信息
- **THEN** 系统要求输入：IP 地址、SSH 端口、SSH 密钥、CPU 核心数、内存 GB、带宽 Mbps、磁盘 GB
- **AND** 系统允许选择是否使用赠金
- **AND** 系统允许设置 CPU 倍率、内存倍率、带宽倍率、磁盘倍率（核时倍率）
- **AND** 系统允许选择过期时间
- **AND** 当管理后台设置了 LXD/KVM 虚拟化方式时，用户可选择虚拟化方式
- **AND** 贡献成功后，后台自动安装套件（agent），待用户开机时自动启用虚拟化

### Requirement: 核时计算

系统 SHALL 按照公式计算核时消耗。

公式：
```
核时 = CPU核心数 × CPU倍率 × 全局CPU倍率
     + 内存GB × 内存倍率 × 全局内存倍率
     + 带宽Mbps × 带宽倍率 × 全局带宽倍率
     + 磁盘GB × 磁盘倍率 × 全局磁盘倍率
```

#### Scenario: 核时计算
- **WHEN** 用户开机器时
- **THEN** 系统根据所选服务器配置按公式计算每小时核时消耗
- **AND** 全局倍率由管理后台设置

### Requirement: SSH 端口转发

系统 SHALL 通过平台 SSH 代理转发连接，不暴露原始服务器 IP。

#### Scenario: 连接服务器
- **WHEN** 用户通过平台请求连接已分配机器
- **THEN** 系统返回平台中转 SSH 端口
- **AND** 用户通过该端口连接，平台代理转发到真实服务器
- **AND** 原始服务器 IP 不被暴露

### Requirement: 机器广场与自动选机

系统 SHALL 支持两种选机模式，由管理员切换。

#### Scenario: 用户机器广场选机
- **WHEN** 管理员设置选机模式为「用户到机器广场」
- **THEN** 用户可在机器广场浏览可用服务器列表
- **AND** 用户可选择机器并配置规格开机器

#### Scenario: 系统自动选机
- **WHEN** 管理员设置选机模式为「系统自动选机」
- **THEN** 用户只需选择所需配置（CPU/内存/磁盘等）
- **AND** 系统自动匹配最合适的服务器

### Requirement: 开机器与过期控制

系统 SHALL 限制机器运行时间不超过所选服务器的过期时间。

#### Scenario: 开机器
- **WHEN** 用户发起开机器请求
- **THEN** 系统检查所选时长是否超过服务器过期时间
- **AND** 若超过则拒绝并提示
- **AND** 若未超过则扣减核时并启动虚拟化

### Requirement: LDC 积分充值

系统 SHALL 集成 LinuxDo Credit 支付，积分名称为 LDC。

#### Scenario: 用户充值
- **WHEN** 用户发起充值
- **THEN** 系统生成 LDC 支付订单（支持官方 Ed25519 签名模式或易支付兼容 MD5 模式，由后台配置选择）
- **AND** 调用 LinuxDo Credit API 发起支付
- **AND** 支付成功后通过回调或轮询更新用户积分余额
- **AND** 管理员可设置充值倍率和充值/提现手续费

### Requirement: 管理员后台

系统 SHALL 提供完整的管理后台功能。

#### Scenario: 管理后台配置
- **WHEN** 管理员登录后台
- **THEN** 可配置以下全局参数：
  - 站点名称（默认「茶的服务器公益站」）
  - 是否开放签到/免费套餐
  - 是否开放注册、注册是否需要邀请码
  - 充值倍率、充值手续费、提现手续费
  - 虚拟化方式：LXD 或 KVM
  - 选机模式：系统自动选机 或 用户机器广场
  - 全局倍率：CPU倍率、内存倍率、带宽倍率、磁盘倍率
  - 新用户赠送核时数量

#### Scenario: 生成订阅码和核时码
- **WHEN** 管理员生成订阅码/核时码
- **THEN** 系统生成唯一兑换码
- **AND** 用户可在平台兑换相应核时或订阅套餐

#### Scenario: 核时套餐管理
- **WHEN** 管理员管理核时套餐
- **THEN** 可创建时长+核时套餐（如 30 天 / 1000 核时）
- **AND** 可创建累计时长套餐（如累计使用满 100 小时赠送 X 核时）
- **AND** 可设置新用户登录赠送核时数量

### Requirement: 签到与免费套餐

系统 SHALL 支持签到功能和免费套餐，由管理员控制开关。

#### Scenario: 用户签到
- **WHEN** 管理员开启签到功能
- **THEN** 用户每日可签到获得一定核时奖励
- **WHEN** 管理员关闭签到功能
- **THEN** 签到入口不可见

#### Scenario: 免费套餐
- **WHEN** 管理员开启免费套餐
- **THEN** 用户可领取免费套餐（固定配置机器）
- **WHEN** 管理员关闭免费套餐
- **THEN** 免费套餐入口不可见

### Requirement: 用户注册控制

系统 SHALL 支持注册开关和邀请码机制。

#### Scenario: 注册开关
- **WHEN** 管理员关闭注册
- **THEN** 新用户无法通过 OAuth 登录创建账号（已有账号不受影响）

#### Scenario: 邀请码注册
- **WHEN** 管理员开启邀请码要求
- **THEN** OAuth 回调后要求输入有效邀请码才能完成注册

### Requirement: 提现功能

系统 SHALL 支持用户提现 LDC 积分。

#### Scenario: 用户提现
- **WHEN** 用户发起提现
- **THEN** 系统按管理员设置的提现手续费扣除
- **AND** 调用 LDC 商户分发接口 `/lpay/distribute` 完成积分分发