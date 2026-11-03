# 🔐 Nginx Secure HLS Module

> 为 HLS 播放列表和媒体资源提供逐 URL 鉴权的 Nginx / OpenResty 原生 C 模块。

业务端只需签发一个 `.m3u8` 地址。模块会验证入口请求，并在返回播放列表时，为子列表、媒体分片、密钥和初始化资源生成独立 Token。无需修改源文件，也无需改造播放器。

[快速开始](#-快速开始) · [工作原理](#-工作原理) · [反向代理](#-反向代理) · [配置参考](#️-配置参考)

## ✨ 特性

- **逐资源签名**：每个 TS、子列表、密钥和初始化资源使用自己的完整路径生成 Token
- **防盗链与防复用**：Token 与路径、用户和时间绑定，复制到其他资源后立即失效
- **实时改写 M3U8**：保留原有查询参数，并自动追加鉴权参数
- **多种签名方案**：支持 MD5、SHA-256、HMAC-SHA256，以及 hex、Base64、Base64URL 编码
- **静态与代理兼容**：可保护本地文件，也可部署在 HLS 源站前方
- **低侵入**：Nginx C 模块直接处理请求和响应，源文件与播放器保持原样

## 🚀 快速开始

下面用静态 HLS 文件演示完整流程。媒体目录为 `/srv/media/upload/hls/`，示例签发脚本需要 PHP 8+。

### 1. 加载模块

动态模块需要与目标 Nginx / OpenResty 的版本和构建参数匹配。将 `.so` 放入模块目录，并在 `nginx.conf` 顶层加载：

```nginx
load_module modules/ngx_http_secure_hls_module.so;
```

<details>
<summary><strong>从源码编译</strong></summary>

模块依赖 OpenSSL `libcrypto`。准备好 Nginx 构建依赖和 OpenSSL 开发库后，在匹配版本的 Nginx 源码目录执行：

```bash
./configure \
  --with-compat \
  --add-dynamic-module=/path/to/nginx-secure-hls-module

make modules
```

编译产物位于 `objs/ngx_http_secure_hls_module.so`。

静态编译时，将 `--add-dynamic-module` 换成 `--add-module`，然后执行 `make`。仓库中的 [build.sh](scripts/build.sh) 也支持 Nginx / OpenResty 的静态和动态构建。

</details>

### 2. 配置鉴权

复制示例配置：

```bash
sudo install -D -m 600 \
  examples/auth.conf \
  /etc/nginx/secure-hls/auth.conf
```

打开 `/etc/nginx/secure-hls/auth.conf`，替换演示密钥：

```nginx
secure_hls_hmac_key "replace-with-a-strong-secret";
```

签发端必须使用同一个密钥。

### 3. 保护 HLS 目录

将下面的 `location` 放入现有的 `server {}`：

```nginx
location ^~ /upload/hls/ {
    root /srv/media;
    include /etc/nginx/secure-hls/auth.conf;

    location ~ \.m3u8$ {
        secure_hls_rewrite on;
        secure_hls_resign on;
    }
}
```

父级 `location` 负责校验播放列表和所有媒体资源。子级 `location` 只负责改写 M3U8 响应。

```bash
sudo nginx -t && sudo nginx -s reload
```

### 4. 生成播放链接

仓库提供了配套的 [PHP 签发脚本](examples/sign.php)：

```bash
SIGNED_URL=$(HLS_SECRET='replace-with-a-strong-secret' \
  php examples/sign.php \
    'https://media.example.com/upload/hls/demo/index.m3u8' \
    42)

echo "$SIGNED_URL"
```

参数 `42` 是用户 ID。脚本会输出可直接交给播放器的完整地址：

```text
https://media.example.com/upload/hls/demo/index.m3u8
  ?token=...
  &ukey=42
  &t=1793692800
```

### 5. 验证

```bash
# 正确签名，预期 200，响应中的资源均带鉴权参数
curl -i "$SIGNED_URL"

# 缺少签名，预期 403
curl -i 'https://media.example.com/upload/hls/demo/index.m3u8'
```

| 场景 | 预期结果 |
| --- | --- |
| 正确签名访问 M3U8 | `200`，列表内资源已追加 Token |
| 访问列表中的已签名分片 | `200`，Range 请求可返回 `206` |
| Token 缺失、错误或过期 | `403` |
| 将 Token 复制到另一个资源 | `403` |

## 🔄 工作原理

```text
业务服务                     Nginx Secure HLS                    播放器
   │                               │                               │
   │  签发入口 M3U8 URL            │                               │
   ├──────────────────────────────►│                               │
   │                               │  校验 Token、用户、时间和路径  │
   │                               │  改写 M3U8 中的每个资源 URL    │
   │                               ├──────────────────────────────►│
   │                               │                               │
   │                               │◄──── 请求已签名的 TS / Key ───┤
   │                               │  按资源完整路径再次校验         │
   │                               ├────────── 返回资源 ───────────►│
```

原始播放列表：

```m3u8
#EXTM3U
#EXTINF:6.0,
segment-01.ts?quality=hd
#EXT-X-KEY:METHOD=AES-128,URI="key.bin"
```

返回给播放器的内容：

```m3u8
#EXTM3U
#EXTINF:6.0,
segment-01.ts?quality=hd&ukey=42&t=1793692800&token=...
#EXT-X-KEY:METHOD=AES-128,URI="key.bin?ukey=42&t=1793692800&token=..."
```

`quality=hd` 会被保留。分片与密钥使用各自的完整路径计算签名，因此 Token 不能跨文件复用。

## 🔑 签名规则

默认示例使用 **HMAC-SHA256 + hex**，有效期为 **2 小时**，允许 **30 秒**时钟偏差：

```php
$message = $userid . "\n" . $time . "\n" . $path;
$token = hash_hmac('sha256', $message, $secret);
```

| 参数 | 含义 |
| --- | --- |
| `token` | 当前资源的 64 位十六进制签名 |
| `ukey` | 用户 ID |
| `t` | 签发时间，Unix 秒 |
| `pkey` | 可选 IP 字段，示例配置仅透传 |

`$path` 必须与 Nginx 的 `$uri` 一致，例如 `/upload/hls/demo/segment-01.ts`。协议、域名、查询参数和 fragment 不参与示例签名。

## 🌐 反向代理

HLS 文件位于上游服务时，使用仓库中的完整示例：

- [nginx-proxy.conf](examples/nginx-proxy.conf) 提供代理与改写配置
- [proxy-playlist.conf](examples/proxy-playlist.conf) 清除压缩、Range 和条件请求头，让模块获得完整的原始播放列表
- [auth.conf](examples/auth.conf) 提供统一的鉴权与签名规则

最小配置如下：

```nginx
location ^~ /upload/hls/ {
    include /etc/nginx/secure-hls/auth.conf;
    proxy_pass http://hls_origin;

    location ~ \.m3u8$ {
        proxy_pass http://hls_origin;
        include /etc/nginx/secure-hls/proxy-playlist.conf;
        secure_hls_rewrite on;
        secure_hls_resign on;
    }
}
```

已经写入个人 Token 的播放列表不适合在 CDN 中跨用户共享缓存。若源播放列表对所有用户相同，可以缓存改写前的上游响应。

## ⚙️ 配置参考

所有指令均可用于 `http`、`server` 和 `location` 作用域。

### 核心指令

| 指令 | 作用 |
| --- | --- |
| `secure_hls_auth` | 开启请求鉴权 |
| `secure_hls_rewrite` | 开启 M3U8 内容改写 |
| `secure_hls_resign` | 为列表中的每个资源重新生成签名 |
| `secure_hls_algorithm` | 选择 `md5`、`sha256` 或 `hmac_sha256` |
| `secure_hls_encoding` | 选择 `hex`、`base64` 或 `base64url` |
| `secure_hls_hmac_key` | 设置 HMAC-SHA256 密钥 |
| `secure_hls_ttl` | 设置签发时间模式下的有效期，默认 `2h` |
| `secure_hls_clock_skew` | 设置允许的时钟偏差，默认 `30s` |

<details>
<summary><strong>高级指令</strong></summary>

| 指令 | 作用 |
| --- | --- |
| `secure_hls_token` | 指定用于校验的 Token 值 |
| `secure_hls_message` | 定义当前请求的签名原文 |
| `secure_hls_sign_param` | 指定自动生成的签名参数名 |
| `secure_hls_sign_message` | 定义媒体资源的签名原文 |
| `secure_hls_sign_playlist_message` | 定义子播放列表的签名原文 |
| `secure_hls_timestamp` | 指定时间戳值 |
| `secure_hls_time_mode` | 选择 `off`、`issued` 或 `expires` 时间模式 |
| `secure_hls_require_args` | 声明请求必须包含的参数 |
| `secure_hls_param` | 向资源 URL 追加或透传参数 |
| `secure_hls_bind_ip` | 将鉴权绑定到指定参数中的 IP |
| `secure_hls_allowed_origin` | 允许指定跨域资源携带签名 |
| `secure_hls_public_origin` | 设置生成资源 URL 时使用的公开源地址 |
| `secure_hls_resources` | 选择要改写的资源类型 |
| `secure_hls_types` | 自定义需要处理的响应 Content-Type |
| `secure_hls_max_line` | 设置播放列表单行长度上限，默认 `64k` |

</details>

更改算法、编码、参数名或签名原文时，必须同步修改业务签发端。

## 🧭 排查问题

将模块状态加入访问日志：

```nginx
log_format hls '$remote_addr $request $status $secure_hls_status';
access_log /var/log/nginx/hls-access.log hls;
```

如果错误 Token 仍然返回 `200`，依次检查模块是否已加载、请求是否命中鉴权 `location`，以及 CDN 是否直接返回了缓存。

## 📚 示例文件

| 文件 | 用途 |
| --- | --- |
| [examples/nginx-static.conf](examples/nginx-static.conf) | 静态 HLS 完整配置 |
| [examples/nginx-proxy.conf](examples/nginx-proxy.conf) | 反向代理完整配置 |
| [examples/auth.conf](examples/auth.conf) | HMAC-SHA256 鉴权规则 |
| [examples/auth-legacy.conf](examples/auth-legacy.conf) | 旧版 MD5 兼容配置 |
| [examples/sign.php](examples/sign.php) | PHP 签发实现 |
| [examples/generate.php](examples/generate.php) | 接入现有业务函数的示例 |
