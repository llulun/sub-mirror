# SubMirror

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](https://opensource.org/licenses/MIT)
[![Node.js Version](https://img.shields.io/badge/node-%3E%3D18-brightgreen.svg)](https://nodejs.org/)
[![Docker Image](https://img.shields.io/badge/docker-ready-blue.svg)](https://www.docker.com/)

**SubMirror** 是一个现代化的配置订阅管理与分发工具。它专为解决配置订阅源（如各类服务配置）访问不稳定、网络连接超时或内容需要二次处理的场景而设计。

它能够将远程订阅源进行镜像缓存、内容清洗（正则过滤）与统一分发，确保多端配置同步的高可用性与稳定性。内置美观的移动端优先（Mobile-First）管理界面。

---

## ✨ 核心特性

- **多源管理**：支持添加多个上游订阅源，独立配置刷新策略。
- **安全访问**：
  - 基于 Token 的访问控制，防止未授权访问。
  - 支持 Token 轮换，随时重置泄露链接。
  - 完善的 SSRF 防护与内网 IP 阻断。
- **内容处理**：
  - **正则过滤**：支持对内容进行行级正则包含（Include）与排除（Exclude）。
  - **历史回滚**：自动保存历史快照，支持一键回滚到任意版本。
  - **自定义 UA**：支持为每个订阅源单独设置 User-Agent，或使用内置随机 UA 池。
- **监控与日志**：
  - 实时访问日志监控。
  - IP 与 User-Agent 访问统计。
  - 安全警报（暴力破解、频率限制触发）。
  - 支持 Webhook 通知（钉钉/企业微信/Slack 等）。
- **现代化 UI**：
  - 响应式设计，完美适配移动端与桌面端。
  - 深色模式（Dark Mode）支持。
  - 流畅的单页应用（SPA）体验。

## 🚀 快速开始

### 1. 环境要求
- Node.js >= 18.0.0
- NPM 或 Yarn

### 2. 本地运行

```bash
# 克隆仓库
git clone https://github.com/llulun/sub-mirror.git
cd sub-mirror

# 安装依赖
npm install

# 启动开发服务器
npm run dev

# 生产环境启动
npm start
```

服务默认运行在 `http://localhost:8080`。首次启动会自动生成管理员密码并打印在日志中（如果未通过环境变量设置）。

### 3. Docker 部署

```bash
docker run -d \
  -p 8080:8080 \
  -v $(pwd)/data:/app/data \
  -e ADMIN_USER=admin \
  -e ADMIN_PASS=your_secure_password \
  --name sub-mirror \
  ghcr.io/llulun/sub-mirror:latest
```

> **注意**：如果您在拉取镜像时遇到 `denied` 错误，请前往 GitHub Packages 页面将镜像包的可见性设置为 **Public**。
>
> 默认端口映射为 `8080:8080`，如需修改外部访问端口（例如 8050），请使用 `-p 8050:8080`。

## ⚙️ 配置说明

可以通过环境变量进行配置：

| 环境变量 | 说明 | 默认值 |
| :--- | :--- | :--- |
| `PORT` | 服务监听端口 | `8080` |
| `ADMIN_USER` | 管理员用户名 | `admin` (首次启动生成) |
| `ADMIN_PASS` | 管理员密码 | (首次启动生成随机密码) |
| `CF_SECRET_KEY` | Cloudflare Turnstile 密钥 | (可选) |
| `ALLOWED_ORIGINS` | 允许的 CORS 域名 | `*` |
| `REFRESH_INTERVAL_MINUTES` | 默认刷新间隔(分钟) | `30` |

## 📦 API 文档

### 订阅访问
- **获取订阅内容**: `GET /sub/:id?token=YOUR_TOKEN`
- **获取最新内容(强制)**: `GET /sub/:id?token=YOUR_TOKEN&force=true`

### 管理接口 (需鉴权)
所有管理接口需在 Header 中携带 `Authorization: Bearer <LOGIN_TOKEN>`。

- `GET /sources`: 获取订阅源列表
- `POST /sources`: 创建新订阅源
- `PUT /sources/:id`: 更新订阅源配置
- `DELETE /sources/:id`: 删除订阅源
- `POST /sources/:id/sync`: 立即同步指定源
- `GET /sources/:id/history`: 获取历史版本列表
- `POST /sources/:id/rollback`: 回滚到指定历史版本

## 🛡️ 安全特性

- **CSRF 防护**: 严格的 SameSite Cookie 策略。
- **速率限制**: 针对登录接口和 API 接口的精细化限流。
- **暴力破解防护**: 连续登录失败自动封禁 IP。
- **输入清洗**: 严格的 URL 校验与参数清洗，防止注入攻击。

## 🤝 贡献指南

欢迎提交 Issue 和 Pull Request！在提交代码前，请确保通过了 lint 检查：

```bash
npm run lint
npm run format
```

## 📄 许可证

本项目采用 [MIT 许可证](LICENSE) 开源。
