# ============================================
#  配置文件 — okp.ccwu.cc
#  TEA Server Platform
# ============================================

# ---- 数据库 ----
# SQLite 数据库文件路径
DATABASE_URL=sqlite:tea_platform.db?mode=rwc

# ---- 服务器监听 ----
# 监听所有网络接口，端口 3000
BIND_ADDR=0.0.0.0:3000

# ---- 会话安全 ----
# 签名 Cookie 用的会话密钥，请务必修改为随机字符串
# 可使用以下命令生成: openssl rand -hex 32
SESSION_SECRET=change-me-to-a-random-secret-key-at-least-32-chars

# ---- LinuxDo OAuth 登录 ----
# 在 https://connect.linux.do/ 注册应用后填入
LINUXDO_CLIENT_ID=your-linuxdo-client-id
LINUXDO_CLIENT_SECRET=your-linuxdo-client-secret
LINUXDO_REDIRECT_URI=https://okp.ccwu.cc/auth/callback
LINUXDO_AUTH_URL=https://connect.linux.do/oauth2/authorize
LINUXDO_TOKEN_URL=https://connect.linux.do/oauth2/token
LINUXDO_USER_INFO_URL=https://connect.linux.do/api/user

# ---- 平台域名 ----
# 完整的平台 URL（用于回调链接、邮件链接等）
PLATFORM_DOMAIN=https://okp.ccwu.cc

# ---- 管理员登录 ----
# 登录页面: https://okp.ccwu.cc/admin-login/ui
# 请务必修改默认密码！
ADMIN_USERNAME=admin
ADMIN_PASSWORD=change-me-to-a-strong-password

# ---- SSH 代理端口配置 ----
# 用于机器 SSH 连接的动态端口分配范围
SSH_PROXY_PORT_START=22000
SSH_PROXY_PORT_COUNT=100
