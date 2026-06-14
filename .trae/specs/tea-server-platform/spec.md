# 茶的服务器公益站 Spec

## Why
构建一个基于 Rust 的服务器分享平台，用户可以通过 LinuxDo Connect OAuth 登录，贡献闲置服务器资源（LXD/KVM 虚拟化），其他用户可使用核时兑换虚拟机。平台通过 SSH 端口转发隐藏原始服务器 IP，保障安全性。支付使用 LinuxDo Credit (LDC) 积分体系。

## What Changes
- 新建完整的 Rust Web 应用项目
- 实现 LinuxDo Connect OAuth 登录（唯一登录方式）
- 实现管理员通过 `/admin-login/?username=xxx&password=xxxx` 路径登录
- 用户贡献服务器（IP、SSH 密钥、赠金、核时倍率、过期时间）
- 核时计算公式：`CPU核心数 × CPU倍率 × 全局CPU倍率 + 内存GB × 内存倍率 × 全局内存倍率 + 宽带Mbps × 宽带倍率 × 全局宽带倍率 + 磁盘GB × 磁盘倍率 × 全局磁盘倍率`
- SSH 端口转发代理，不暴露原始服务器 IP
- 管理后台：签到/免费套餐开关、注册开关、邀请码、充值倍率/手续费、虚拟化方式(LXD/KVM)、选机模式、订阅码/核时码生成、核时套餐管理、新用户赠送核时
- LDC 支付集成（易支付兼容接口 + Ed25519 官方接口）
- 共享服务器时自动安装代理套件
- 开机器时不能超过所选机器的过期时间

## Impact
- Affected specs: 无（全新项目）
- Affected code: 全新代码库

## ADDED Requirements

### Requirement: 用户 OAuth 登录
系统 SHALL 仅通过 LinuxDo Connect OAuth 进行用户登录，不提供密码登录方式。

#### Scenario: 用户点击登录
- **WHEN** 用户访问登录页面
- **THEN** 系统仅显示 "通过 LinuxDo Connect 登录" 按钮，跳转至 LinuxDo OAuth 授权页面

#### Scenario: OAuth 回调成功
- **WHEN** 用户在 LinuxDo 完成授权后回调到平台
- **THEN** 系统创建或更新用户记录，设置会话，跳转到首页

### Requirement: 管理员登录
系统 SHALL 通过 `/admin-login/?username=xxx&password=xxxx` 路径提供管理员登录。

#### Scenario: 管理员使用正确凭据登录
- **WHEN** 管理员访问 `/admin-login/?username=admin&password=correct_password`
- **THEN** 系统验证凭据，设置管理员会话，跳转到管理后台

#### Scenario: 管理员使用错误凭据
- **WHEN** 管理员访问 `/admin-login/?username=admin&password=wrong`
- **THEN** 系统返回 401 或错误提示

### Requirement: 服务器贡献
用户 SHALL 能够贡献服务器，提供 IP 地址、SSH 密钥等信息。

#### Scenario: 用户提交服务器贡献
- **WHEN** 已登录用户填写服务器 IP、SSH 密钥、选择是否使用赠金、选择核时倍率、选择过期时间后提交
- **THEN** 系统保存服务器信息，后台自动安装代理套件，计算核时并发放给用户

### Requirement: 核时计算
系统 SHALL 按照公式计算核时：CPU核心数 × CPU倍率 × 全局CPU倍率 + 内存GB × 内存倍率 × 全局内存倍率 + 宽带Mbps × 宽带倍率 × 全局宽带倍率 + 磁盘GB × 磁盘倍率 × 全局磁盘倍率。

#### Scenario: 计算贡献服务器核时
- **WHEN** 用户贡献一台 4核CPU/8GB内存/100Mbps宽带/50GB磁盘 的服务器，CPU倍率1.0/内存倍率0.5/宽带倍率0.1/磁盘倍率0.2，全局倍率均为1.0
- **THEN** 核时 = 4×1.0×1.0 + 8×0.5×1.0 + 100×0.1×1.0 + 50×0.2×1.0 = 4 + 4 + 10 + 10 = 28 核时/小时

### Requirement: SSH 端口转发
平台 SHALL 通过 SSH 端口转发代理用户连接，不暴露原始服务器 IP。

#### Scenario: 用户连接虚拟机
- **WHEN** 用户请求连接其创建的虚拟机
- **THEN** 系统分配平台转发端口，用户通过该端口连接，平台内部转发到实际服务器，用户无法获知原始服务器 IP

### Requirement: 管理后台全局设置
管理员 SHALL 能够配置平台全局参数。

#### Scenario: 管理员修改站点名称
- **WHEN** 管理员在后台修改站点名称为新名称
- **THEN** 全站页面标题更新为新名称

#### Scenario: 管理员开关签到/免费套餐
- **WHEN** 管理员切换签到功能开关
- **THEN** 前端签到入口相应显示或隐藏

#### Scenario: 管理员开关注册
- **WHEN** 管理员关闭注册开关
- **THEN** 新用户无法注册，登录后提示注册已关闭

#### Scenario: 管理员设置邀请码要求
- **WHEN** 管理员开启邀请码注册要求
- **THEN** 新用户注册时必须提供有效邀请码

#### Scenario: 管理员设置充值倍率和手续费
- **WHEN** 管理员设置充值倍率为 1.2，手续费为 5%
- **THEN** 用户充值 100 LDC 时，实际到账 120 核时，平台收取 5% 手续费

#### Scenario: 管理员设置虚拟化方式
- **WHEN** 管理员在后台勾选虚拟化方式（LXD、KVM，可多选，至少勾选一项）
- **THEN** 用户贡献服务器时只能从管理员启用的虚拟化方式中选择

#### Scenario: 管理员设置选机模式
- **WHEN** 管理员设置为"系统自动选机"
- **THEN** 用户开机器时系统自动分配最优服务器
- **WHEN** 管理员设置为"机器广场"
- **THEN** 用户可在机器广场浏览所有可用服务器并自行选择

### Requirement: 核时码与订阅码
管理员 SHALL 能够生成核时码（一次性兑换）和订阅码（周期性发放）。

#### Scenario: 管理员生成核时码
- **WHEN** 管理员设置核时数量和有效期限并生成核时码
- **THEN** 系统生成唯一兑换码，用户输入后可兑换对应核时

#### Scenario: 管理员生成订阅码
- **WHEN** 管理员设置每日核时数量和有效天数并生成订阅码
- **THEN** 系统生成唯一订阅码，用户输入后每日自动获得核时

### Requirement: 核时套餐
管理员 SHALL 能够创建核时套餐（时长套餐、累计时长套餐）。

#### Scenario: 创建时长套餐
- **WHEN** 管理员创建 30 天 1000 核时的套餐
- **THEN** 用户可购买该套餐，获得 30 天内有效的 1000 核时

#### Scenario: 创建累计时长套餐
- **WHEN** 管理员创建累计 100 小时 500 核时的套餐
- **THEN** 用户可购买该套餐，获得累计 100 小时使用时间的 500 核时

### Requirement: 新用户赠送核时
系统 SHALL 在新用户注册后自动赠送管理员设定的核时数量。

#### Scenario: 新用户首次登录
- **WHEN** 新用户通过 LinuxDo Connect 首次登录
- **THEN** 系统自动赠送管理员设定的初始核时数量

### Requirement: LDC 支付集成
系统 SHALL 集成 LinuxDo Credit 支付，支持易支付兼容接口（MD5 签名）和官方接口（Ed25519 签名）。

#### Scenario: 用户充值（易支付模式）
- **WHEN** 用户发起充值请求
- **THEN** 系统调用 `/epay/pay/submit.php` 创建订单，用户跳转至 LinuxDo 认证页面完成支付

#### Scenario: 支付回调处理
- **WHEN** LinuxDo 发送异步支付成功通知
- **THEN** 系统验签后更新用户核时余额

#### Scenario: 管理员分发 LDC
- **WHEN** 管理员通过商户分发接口 `/lpay/distribute` 向用户分发积分
- **THEN** 系统使用 Basic Auth 鉴权，调用接口完成分发

### Requirement: 代理套件自动安装
系统 SHALL 在用户贡献服务器后自动在目标服务器安装代理套件。

#### Scenario: 服务器贡献成功后自动安装
- **WHEN** 用户提交服务器贡献信息并验证通过
- **THEN** 系统通过 SSH 连接到目标服务器，自动安装代理套件（包含虚拟化管理、SSH转发等功能）

### Requirement: 机器创建时间限制
用户开机器时 SHALL 不能超过所选服务器的过期时间。

#### Scenario: 用户选择即将过期的服务器
- **WHEN** 用户尝试创建一台有效期超过服务器剩余时间的虚拟机
- **THEN** 系统拒绝创建，提示机器使用时间不能超过服务器过期时间