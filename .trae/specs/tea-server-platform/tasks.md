# Tasks

- [ ] Task 1: 项目初始化与环境搭建
  - [ ] 使用 Cargo 初始化 Rust 项目，配置 Actix-web 或 Axum 框架
  - [ ] 配置 SQLite 数据库（rusqlite 或 sqlx），创建基础数据库迁移脚本
  - [ ] 配置模板引擎（Tera 或 Askama），设置静态文件服务
  - [ ] 创建基础项目目录结构（routes, models, services, templates, static）
  - [ ] 配置 .env 环境变量文件和环境变量读取

- [ ] Task 2: 数据库模型设计与迁移
  - [ ] 设计并创建 users 表（id, linuxdo_id, username, email, core_hours, is_admin, created_at）
  - [ ] 设计并创建 servers 表（id, user_id, ip, ssh_port, ssh_key_encrypted, cpu_cores, memory_gb, bandwidth_mbps, disk_gb, cpu_multiplier, memory_multiplier, bandwidth_multiplier, disk_multiplier, use_bonus, virtualization_type, status, expires_at, created_at）
  - [ ] 设计并创建 vm_instances 表（id, user_id, server_id, cpu_cores, memory_gb, disk_gb, forwarded_port, status, expires_at, created_at）
  - [ ] 设计并创建 settings 表（key, value）
  - [ ] 设计并创建 invite_codes 表（id, code, is_used, used_by, created_at）
  - [ ] 设计并创建 core_hour_codes 表（id, code, amount, expires_at, is_used, used_by, type）
  - [ ] 设计并创建 core_hour_packages 表（id, name, duration_days, accumulated_hours, core_hours, price_ldc, is_active）
  - [ ] 设计并创建 recharge_orders 表（id, user_id, out_trade_no, trade_no, amount_ldc, core_hours, status, created_at）
  - [ ] 设计并创建 sign_in_records 表（id, user_id, date, core_hours_awarded）

- [ ] Task 3: LinuxDo Connect OAuth 登录
  - [ ] 实现 OAuth 配置（client_id, client_secret, redirect_uri）
  - [ ] 实现 /auth/login 路由，重定向到 LinuxDo OAuth 授权页
  - [ ] 实现 /auth/callback 路由，处理 OAuth 回调，获取用户信息
  - [ ] 实现用户创建/查找逻辑（首次登录自动注册）
  - [ ] 实现新用户赠送核时逻辑
  - [ ] 实现会话管理（Session/Cookie）
  - [ ] 实现登出功能
  - [ ] 前端登录页面仅显示 LinuxDo Connect 按钮，不显示密码登录

- [ ] Task 4: 管理员登录
  - [ ] 实现 /admin-login 路由（GET 方式，读取 username 和 password 参数）
  - [ ] 从环境变量/配置文件读取管理员凭据
  - [ ] 验证凭据并设置管理员会话

- [ ] Task 5: 用户前端页面
  - [ ] 首页：显示站点名称、核时余额、快捷入口
  - [ ] 服务器贡献页面：表单（IP、SSH端口、SSH密钥、CPU/内存/宽带/磁盘、赠金选择、倍率选择、过期时间、虚拟化方式）
  - [ ] 机器广场/开机器页面：根据选机模式显示可用服务器或自动分配
  - [ ] 我的机器页面：显示已创建的虚拟机列表、连接信息（转发端口）
  - [ ] 我的贡献页面：显示已贡献的服务器列表和状态
  - [ ] 充值页面：LDC 充值入口
  - [ ] 核时码兑换页面
  - [ ] 核时套餐购买页面
  - [ ] 签到页面（根据管理设置显示/隐藏）

- [ ] Task 6: 管理后台页面
  - [ ] 管理后台仪表盘
  - [ ] 站点设置页面（站点名称、注册开关、邀请码开关、签到开关、免费套餐开关）
  - [ ] 全局倍率设置页面（CPU/内存/宽带/磁盘全局倍率）
  - [ ] 充值设置页面（充值倍率、充值手续费、提现手续费）
  - [ ] 虚拟化方式设置页面（LXD/KVM）
  - [ ] 选机模式设置页面（自动选机/机器广场）
  - [ ] 核时码生成页面
  - [ ] 订阅码生成页面
  - [ ] 核时套餐管理页面（创建/编辑/删除套餐）
  - [ ] 新用户赠送核时设置页面
  - [ ] 邀请码管理页面（生成/查看/禁用邀请码）
  - [ ] 用户管理页面（查看用户列表、核时余额）
  - [ ] 服务器管理页面（查看/审核/下线服务器）
  - [ ] 虚拟机管理页面（查看/强制关闭虚拟机）

- [ ] Task 7: 服务器贡献与核时计算
  - [ ] 实现服务器贡献提交接口
  - [ ] 实现核时计算函数（按公式）
  - [ ] 实现 SSH 密钥加密存储
  - [ ] 实现服务器状态管理（待审核/运行中/已过期/已下线）
  - [ ] 实现过期定时检查与状态更新

- [ ] Task 8: SSH 代理与端口转发
  - [ ] 实现端口分配管理器（分配可用转发端口）
  - [ ] 实现 SSH 隧道建立（平台到目标服务器）
  - [ ] 实现用户连接转发（用户连接到转发端口 → 转发到目标服务器）
  - [ ] 实现端口回收（虚拟机过期后释放端口）

- [ ] Task 9: 代理套件自动安装
  - [ ] 编写代理套件安装脚本
  - [ ] 实现服务器贡献后通过 SSH 远程执行安装脚本
  - [ ] 安装完成后更新服务器状态为运行中

- [ ] Task 10: 虚拟机管理
  - [ ] 实现开机器接口（选择服务器、配置规格、设置时长）
  - [ ] 验证机器时长不超过服务器过期时间
  - [ ] 实现虚拟机创建（通过代理套件在目标服务器上创建 LXD/KVM 容器/虚拟机）
  - [ ] 实现虚拟机连接信息展示（转发端口）
  - [ ] 实现虚拟机过期自动回收
  - [ ] 实现用户手动关闭/重启虚拟机

- [ ] Task 11: LDC 支付集成
  - [ ] 实现易支付兼容接口（MD5 签名、订单创建）
  - [ ] 实现官方接口（Ed25519 签名支持）
  - [ ] 实现支付回调处理（验签、更新核时余额）
  - [ ] 实现订单查询接口
  - [ ] 实现商户分发接口调用（管理员向用户分发 LDC）
  - [ ] 实现充值页面和支付流程

- [ ] Task 12: 核时码/订阅码/套餐/签到系统
  - [ ] 实现核时码生成算法（随机唯一码）
  - [ ] 实现核时码兑换逻辑
  - [ ] 实现订阅码生成与每日自动发放（定时任务）
  - [ ] 实现核时套餐购买逻辑
  - [ ] 实现签到系统（每日签到赠送核时）
  - [ ] 实现免费套餐系统

- [ ] Task 13: 邀请码系统
  - [ ] 实现邀请码生成（管理后台）
  - [ ] 实现邀请码验证（注册时）
  - [ ] 实现邀请码状态管理（已使用/未使用）

- [ ] Task 14: 定时任务
  - [ ] 服务器过期检查与状态更新
  - [ ] 虚拟机过期检查与自动回收
  - [ ] 订阅码每日发放
  - [ ] 核时码过期清理

- [ ] Task 15: 部署与推送
  - [ ] 配置 Dockerfile 或编译脚本
  - [ ] 初始化 Git 仓库并推送到云端仓库
  - [ ] 编写 README 和部署说明

# Task Dependencies
- Task 2 依赖 Task 1（项目初始化后建表）
- Task 3 依赖 Task 2（用户表就绪后实现登录）
- Task 4 依赖 Task 2（设置表就绪）
- Task 5 依赖 Task 3（登录系统就绪后前端页面）
- Task 6 依赖 Task 4（管理员登录后管理后台）
- Task 7 依赖 Task 2, Task 3（数据库和认证就绪）
- Task 8 依赖 Task 7（服务器就绪后配置转发）
- Task 9 依赖 Task 7（服务器贡献后安装代理）
- Task 10 依赖 Task 7, Task 8, Task 9（服务器/代理/转发就绪后开虚拟机）
- Task 11 依赖 Task 3（用户系统就绪后支付）
- Task 12 依赖 Task 3, Task 6（用户和管理后台就绪）
- Task 13 依赖 Task 6（管理后台就绪）
- Task 14 依赖 Task 2, Task 7, Task 10, Task 12（数据库和各系统就绪后定时任务）
- Task 15 依赖所有前置任务