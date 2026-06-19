# Tasks: 服务器名称、介绍与供应商

- [x] Task 1: 数据库与模型变更
  - [x] 1.1 在 `db.rs` 的 `servers` 表 ALTER TABLE 添加 `description`（TEXT DEFAULT ''）和 `provider`（TEXT DEFAULT ''）字段
  - [x] 1.2 在 `models/mod.rs` 的 `Server` 结构体添加 `pub description: String` 和 `pub provider: String` 字段

- [x] Task 2: 贡献页面新增字段
  - [x] 2.1 修改 `templates/user/contribute.html`，在服务器名称下方添加「机器介绍」多行文本框和「供应商」输入框
  - [x] 2.2 修改 `ContributeServerForm` 结构体和 `contribute_server_submit` handler，读取并保存 `description` 和 `provider`
  - [x] 2.3 修改 `handlers/api.rs` 的 `ContributeServerRequest` 和 INSERT，添加 `description` 和 `provider`

- [x] Task 3: 机器广场展示
  - [x] 3.1 修改 `templates/user/market.html`，每张卡片显示供应商和机器介绍

- [x] Task 4: 验证
  - [x] 4.1 `cargo check` 编译通过
  - [x] 4.2 贡献页面输入介绍和供应商可正常保存
  - [x] 4.3 机器广场显示介绍和供应商