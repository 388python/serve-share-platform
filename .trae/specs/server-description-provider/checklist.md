# Checklist: 服务器名称、介绍与供应商

## 数据库与模型
- [x] `servers` 表有 `description` 和 `provider` 字段
- [x] `Server` 结构体有 `description` 和 `provider` 字段

## 贡献页面
- [x] 贡献页面有「机器介绍」多行文本框
- [x] 贡献页面有「供应商」输入框
- [x] `contribute_server_submit` 保存 `description` 和 `provider`
- [x] API `ContributeServerRequest` 支持 `description` 和 `provider`

## 机器广场展示
- [x] 每张卡片显示供应商信息（有内容时显示）
- [x] 每张卡片显示机器介绍（有内容时显示，截断 80 字符）

## 编译验证
- [x] `cargo check` 编译通过
- [x] 无新增编译错误