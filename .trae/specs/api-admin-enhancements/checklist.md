# Checklist: API 与管理增强

## SSH 端口可配置
- [ ] `SSH_PROXY_PORT_COUNT` 环境变量可读取，默认 100
- [ ] SSH 代理实际监听端口数由配置决定
- [ ] `.env.example` 和 `docker-compose.yml` 已更新

## 管理员权限授予
- [ ] 用户编辑 Modal 中有「设为管理员」选项
- [ ] 管理员可授予/撤销其他用户的管理员权限
- [ ] 管理员不能撤销自己的权限

## 赠金锁定
- [ ] 后台配置页面有赠金锁定模式选项（unlocked/enabled/disabled）
- [ ] unlocked 模式：赠金复选框可自由勾选
- [ ] enabled 模式：赠金复选框强制勾选且不可取消
- [ ] disabled 模式：赠金复选框强制取消且不可勾选

## API 接口
- [ ] API 认证中间件正确验证 Bearer token
- [ ] 用户端 API 端点全部可用（/me, /machines, /servers, /checkin, /redeem, /packages, /recharge）
- [ ] 管理端 API 端点全部可用（/users, /servers, /machines, /config, /codes, /invites, /orders）
- [ ] 用户可在个人中心查看/生成 API Key
- [ ] 管理员可在后台配置 Admin API Key

## 编译与推送
- [ ] `cargo check` 编译通过
- [ ] 代码推送到远程仓库