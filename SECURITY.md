# Security Policy

## Supported Versions

目前仅支持最新版本接收安全更新。

| Version | Supported          |
| ------- | ------------------ |
| 0.1.x   | :white_check_mark: |
| < 0.1   | :x:                |

## Reporting a Vulnerability

如果你发现了安全漏洞，请**不要**直接提交公开 Issue。
请通过以下方式联系我们：

- 发送邮件至: security@example.com (请替换为实际邮箱，或者仅说明通过 GitHub Security Advisory 提交)
- 或者在 GitHub 上创建一个 Private Vulnerability Report。

我们会尽快评估并修复漏洞。

## Security Features

本项目包含以下安全特性：
- **SSRF 防护**: 自动检测并阻断对内网 IP 的请求。
- **JWT 鉴权**: 所有管理接口均需严格鉴权。
- **输入清洗**: 防止注入攻击。
- **速率限制**: 防止暴力破解和 DoS 攻击。
