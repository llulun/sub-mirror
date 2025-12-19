# SubMirror

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](https://opensource.org/licenses/MIT)
[![Node.js Version](https://img.shields.io/badge/node-%3E%3D18-brightgreen.svg)](https://nodejs.org/)
[![Docker Image](https://img.shields.io/badge/docker-ready-blue.svg)](https://github.com/llulun/sub-mirror/pkgs/container/sub-mirror)
[![Build Status](https://github.com/llulun/sub-mirror/actions/workflows/docker-publish.yml/badge.svg)](https://github.com/llulun/sub-mirror/actions)

**SubMirror** 是一个现代化的配置订阅镜像与管理工具。它专为解决跨网络环境下的配置同步难题而设计，提供稳定的订阅源缓存、内容清洗与高速分发服务。

无论是个人多设备同步，还是团队配置统一管理，SubMirror 都能提供高可用、安全且易用的解决方案。

---

## ✨ 核心特性

- **🚀 高速镜像缓存**
  - 自动定时同步上游订阅源，解决源站访问不稳定或超时问题。
  - 支持内存缓存与持久化存储，确保 100% 的可用性。

- **🛡️ 企业级安全**
  - **访问控制**：基于 JWT 的 Token 鉴权，支持一键轮换 Token。
  - **SSRF 防护**：内置严格的内网 IP 阻断与 DNS 校验机制。
  - **WAF 集成**：原生支持 Cloudflare Schema Validation，提供 OpenAPI 3.0 规范文档。

- **⚡️ 智能内容处理**
  - **正则清洗**：支持行级正则包含（Include）与排除（Exclude），精准控制下发内容。
  - **User-Agent 伪装**：支持自定义或随机化 UA，模拟真实客户端请求。

- **📦 历史版本回滚**
  - 自动保存每次同步的快照。
  - 误操作或上游污染时，支持一键回滚到任意历史版本。

- **📊 监控与告警**
  - 实时仪表盘：展示今日访问量、Top IP、Top UA 等关键指标。
  - 异常告警：支持通过 Webhook（钉钉、飞书、Telegram）推送同步失败或安全警报。

- **🎨 现代化管理界面**
  - 移动端优先（Mobile-First）设计，手机管理同样流畅。
  - 自动适配深色模式（Dark Mode）。

---

## 📸 界面预览

> *（此处建议上传管理界面截图）*

---

## 🚀 快速部署

### 方式一：Docker (推荐)

我们提供开箱即用的 Docker 镜像，支持 `amd64` 和 `arm64` 架构。

```bash
docker run -d \
  --name sub-mirror \
  --restart always \
  -p 8080:8080 \
  -v $(pwd)/data:/app/data \
  -e ADMIN_USER=admin \
  -e ADMIN_PASS=your_secure_password \
  -e CF_SITE_KEY=your_site_key \
  -e CF_SECRET_KEY=your_secret_key \
  ghcr.io/llulun/sub-mirror:latest
```

> **注意**：如果拉取镜像时提示 `denied`，请确保您已登录 GitHub Container Registry 或该镜像包已设置为 **Public**。

### 方式二：Docker Compose

创建 `docker-compose.yml`：

```yaml
version: '3'
services:
  sub-mirror:
    image: ghcr.io/llulun/sub-mirror:latest
    container_name: sub-mirror
    restart: always
    ports:
      - "8080:8080"
    volumes:
      - ./data:/app/data
    environment:
      - ADMIN_USER=admin
      - ADMIN_PASS=change_me_please
      - REFRESH_INTERVAL_MINUTES=30
      - CF_SITE_KEY=your_turnstile_site_key
      - CF_SECRET_KEY=your_turnstile_secret_key
```

运行：
```bash
docker-compose up -d
```

### 方式三：源码运行

```bash
# 克隆仓库
git clone https://github.com/llulun/sub-mirror.git
cd sub-mirror

# 安装依赖
npm install

# 生产环境启动
npm start
```

---

## ⚙️ 配置说明

您可以通过环境变量或 Web 界面（`/api/settings`）进行配置。推荐使用环境变量进行初始化配置。

| 环境变量 | 说明 | 默认值 |
| :--- | :--- | :--- |
| `PORT` | 服务监听端口 | `8080` |
| `ADMIN_USER` | 管理员账号 | `admin` |
| `ADMIN_PASS` | 管理员密码 | *(随机生成)* |
| `REFRESH_INTERVAL_MINUTES` | 默认自动同步间隔（分钟） | `30` |
| `CF_SITE_KEY` | Cloudflare Turnstile 站点密钥 | *(可选)* |
| `CF_SECRET_KEY` | Cloudflare Turnstile 密钥 | *(可选)* |
| `ALLOWED_ORIGINS` | CORS 允许域名（逗号分隔） | `*` |

---

## ☁️ Cloudflare 集成

SubMirror 完美支持配合 Cloudflare 使用，以获得最佳的安全性和性能。

### 1. 架构验证 (Schema Validation)
为了防止恶意请求攻击您的源站，建议在 Cloudflare 中启用 API Schema Validation。
本项目根目录提供了标准的 [openapi.yaml](./openapi.yaml) 文件。

1. 在 Cloudflare Dashboard 中进入 **Security** > **API Shield**。
2. 添加新的 Endpoint，上传本项目提供的 `openapi.yaml`。
3. 启用 **Schema Validation**，Cloudflare 将自动拦截不符合规范的请求。

### 2. Turnstile 验证码
在登录页面启用 Cloudflare Turnstile 人机验证：
1. 在 Cloudflare 申请 Turnstile Site Key 和 Secret Key。
2. 设置环境变量 `CF_SITE_KEY` 和 `CF_SECRET_KEY`。
3. 重启容器即可生效。

---

## 📦 API 文档

SubMirror 提供 RESTful API 用于自动化管理。

- **Base URL**: `/`
- **Authentication**: `Authorization: Bearer <TOKEN>`

| 方法 | 路径 | 描述 |
| :--- | :--- | :--- |
| GET | `/sub/:id` | 获取订阅内容 (无需 Bearer Token, 需 query token) |
| GET | `/sources` | 获取订阅源列表 |
| POST | `/sources` | 创建新订阅 |
| POST | `/sources/:id/sync` | 立即触发同步 |
| GET | `/sources/:id/history` | 获取历史版本 |
| POST | `/sources/:id/rollback` | 版本回滚 |

详细接口定义请参考 [openapi.yaml](./openapi.yaml)。

---

## 🤝 贡献与支持

- 遇到问题？请提交 [Issue](https://github.com/llulun/sub-mirror/issues)。
- 觉得好用？请给项目点个 Star ⭐️！

## 📄 许可证

本项目采用 [MIT 许可证](LICENSE) 开源。
