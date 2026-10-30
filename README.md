# Secure HLS

**m3u8 鉴权 · 逐资源签名 · Nginx / OpenResty 原生 C 模块**

校验播放列表请求，为 TS、子列表、密钥和初始化资源生成独立 token。支持静态文件与反向代理。

[启用模块](#1-启用模块) · [配置资源](#2-配置资源) · [生成链接](#3-生成链接) · [验证](#4-验证) · [自定义](#自定义)

## 1. 启用模块

动态模块在 `nginx.conf` 顶层加载，与 `http {}` 同级；静态编译时跳过这一步。`.so` 必须匹配目标 Nginx / OpenResty 版本和构建参数。

```nginx
load_module modules/ngx_http_secure_hls_module.so;
```

将 [auth.conf](examples/auth.conf) 保存为 `/etc/nginx/secure-hls/auth.conf`，修改密钥：

```nginx
secure_hls_hmac_key "your-secret";
```

该配置使用 **HMAC-SHA256 / hex**，签入 **完整 path＋userid＋t**，有效期 **2 小时**，时钟偏差 **30 秒**。PHP 使用相同密钥。

## 2. 配置资源

以下 `location` 放入已有的 `server {}`，路径按实际环境调整。

### 静态文件

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

请求 `/upload/hls/video/hls.m3u8` 对应 `/srv/media/upload/hls/video/hls.m3u8`。整个目录执行鉴权，仅播放列表开启改写。

<details>
<summary><strong>反向代理配置</strong></summary>

将 [proxy-playlist.conf](examples/proxy-playlist.conf) 保存到同一配置目录，用下面的 `location` 替换静态文件配置：

```nginx
location ^~ /upload/hls/ {
    include /etc/nginx/secure-hls/auth.conf;
    proxy_pass http://127.0.0.1:9000;

    location ~ \.m3u8$ {
        proxy_pass http://127.0.0.1:9000;
        include /etc/nginx/secure-hls/proxy-playlist.conf;
        secure_hls_rewrite on;
        secure_hls_resign on;
    }
}
```

`proxy-playlist.conf` 清除压缩、Range 和条件请求头，获取完整原始列表。改写后的列表可由 Nginx gzip 压缩；外层 CDN 不应缓存携带个人 token 的列表。

</details>

检查配置并重载：

```sh
nginx -t && nginx -s reload
```

## 3. 生成链接

PHP 签名公式：

```php
$token = hash_hmac('sha256', $userid . "\n" . $time . "\n" . $path, $secret);
```

`$path` 与 Nginx 的 `$uri` 一致：解码一次、合并连续斜杠、处理 `.` 和 `..`，不包含协议、域名、查询参数或 fragment。已有发链函数可保留接口和 URL 拼接，只替换签名计算。

| 参数 | 内容 |
| --- | --- |
| `token` | 签名，64 位十六进制字符串 |
| `ukey` | userid |
| `t` | 签发时间，Unix 秒 |
| `pkey` | 可选 IP，默认仅透传 |

使用内置 [sign.php](examples/sign.php) 生成链接（PHP 8+）：

```sh
SIGNED_URL=$(HLS_SECRET='your-secret' php examples/sign.php \
  'https://media.example.com/upload/hls/video/hls.m3u8' 1)
```

播放列表返回后，资源地址自动变为：

```text
segment.ts?quality=hd
→ segment.ts?quality=hd&ukey=1&t=...&token=...
```

每个资源按自己的完整 path 签名，沿用入口的 userid 和时间。跨目录同名文件不能复用 token；旧的无路径签名需要重新生成。

## 4. 验证

```sh
# 正确签名：200，列表中的资源应带有 token
curl -i "$SIGNED_URL"

# 不带凭据：403
curl -i 'https://media.example.com/upload/hls/video/hls.m3u8'
```

| 检查 | 预期 |
| --- | --- |
| 正确签名请求 m3u8 | `200`，资源地址已追加参数 |
| 访问列表中带签名的 TS | `200`；Range 请求可返回 `206` |
| 删除、改错 token，或签名过期 | `403` |
| 保留 token，改为另一个文件路径 | `403` |

**错误 token 仍返回 `200`，不代表校验通过。** 检查模块是否加载、请求是否命中上述 `location`，以及 CDN 是否直接返回缓存。可将 `$secure_hls_status` 加入访问日志定位失败原因。

## 自定义

在 `auth.conf` 或对应 `location` 中调整：

| 需求 | 配置 |
| --- | --- |
| 修改有效期 | `secure_hls_ttl 30m;` |
| 修改时钟偏差 | `secure_hls_clock_skew 10s;` |
| 更换算法 | `secure_hls_algorithm`：`md5`、`sha256`、`hmac_sha256` |
| 更换编码 | `secure_hls_encoding`：`hex`、`base64`、`base64url` |
| 追加字段 | `secure_hls_param uid $secure_hls_arg_ukey;` |
| 允许其他 CDN 地址携带签名 | `secure_hls_allowed_origin https://cdn.example.com;` |

更改算法、字段或模板时，同步调整 PHP 和以下配置：

| 配置 | 用途 |
| --- | --- |
| `secure_hls_token` / `secure_hls_sign_param` | 读取 / 输出签名参数 |
| `secure_hls_message` | 校验当前请求，路径使用 `$uri` |
| `secure_hls_sign_message` | 签名分片、密钥等，路径使用 `$secure_hls_target_path` |
| `secure_hls_sign_playlist_message` | 签名子列表，路径使用 `$secure_hls_target_path` |
| `secure_hls_require_args` / `secure_hls_timestamp` | 必填字段 / 时间来源 |

`secure_hls_param` 用于透传字段，自动生成的 token 由 `secure_hls_sign_param` 指定。跨域资源的接收端也须配置同样的鉴权规则。

完整示例：[静态文件](examples/nginx-static.conf) · [反向代理](examples/nginx-proxy.conf) · [鉴权配置](examples/auth.conf)
