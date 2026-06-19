# 服务器名称、介绍与供应商 Spec

## Why
当前贡献服务器时仅有基础名称，缺少机器介绍和供应商信息，用户在选择服务器时无法了解机器的详细背景和来源。增加介绍和供应商字段可提升机器广场的信息透明度，帮助用户做出更好的选机决策。

## What Changes
- `servers` 表新增 `description`（机器介绍）和 `provider`（供应商）字段
- 贡献服务器页面新增「机器介绍」多行文本框和「供应商」下拉/输入框
- 机器广场每张卡片显示机器介绍和供应商信息
- API 贡献端点同步支持 `description` 和 `provider` 字段

## Impact
- Affected specs: tea-server-platform, premium-package-server-info
- Affected code: `src/db.rs`, `src/models/mod.rs`, `src/handlers/mod.rs`, `src/handlers/api.rs`, `templates/user/contribute.html`, `templates/user/market.html`

---

## ADDED Requirements

### Requirement: 服务器介绍字段
贡献者 SHALL 可在贡献服务器时填写机器介绍（多行文本，可选），描述机器的用途、配置特点等。

#### Scenario: 填写机器介绍
- **WHEN** 贡献者在表单中填写机器介绍
- **THEN** 介绍内容保存到 `servers.description` 字段

#### Scenario: 不填写介绍
- **WHEN** 贡献者留空机器介绍
- **THEN** 字段默认为空字符串，机器广场不显示介绍区域

### Requirement: 供应商字段
贡献者 SHALL 可在贡献服务器时选择或输入供应商信息（如 "阿里云"、"腾讯云"、"AWS"、"自建机房" 等）。

#### Scenario: 选择供应商
- **WHEN** 贡献者在表单中输入供应商
- **THEN** 供应商信息保存到 `servers.provider` 字段

### Requirement: 机器广场展示介绍和供应商
机器广场每张服务器卡片 SHALL 显示机器介绍（如有）和供应商信息。

#### Scenario: 查看服务器详情
- **WHEN** 用户浏览机器广场
- **THEN** 每张卡片显示供应商（如有）和机器介绍摘要（如有）