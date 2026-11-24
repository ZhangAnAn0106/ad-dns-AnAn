# ad-dns-rules

自用广告域名拦截规则，AdGuard / AdGuard Home 用。

## 订阅地址

**黑名单（拦截）**

```
https://raw.githubusercontent.com/ZhangAnAn0106/ad-dns-rules/main/blacklist.txt
```

**白名单（例外）**

```
https://raw.githubusercontent.com/ZhangAnAn0106/ad-dns-rules/main/whitelist.txt
```

## 导入

AdGuard Home 里：过滤器 → DNS 黑名单 → 添加黑名单，填黑名单地址；
再添加黑名单一次，填白名单地址（白名单用的是 `@@` 例外语法，按黑名单加就能生效）。

## 规则语法

| 写法 | 含义 |
| --- | --- |
| `||domain^` | 拦截这个域名及子域 |
| `@@||domain^` | 放行这个域名及子域 |
| `! 文字` | 注释，不生效 |

未启用的规则统一用 `!` 注释保留，想开启就把行首的 `!` 删掉。

## 现有内容

| App | 版本 | 拦截规则 |
| --- | --- | --- |
| 酷安 CoolApk | 16.6.4 | 47 条 |
| 今日水印相机 | 3.0.465.8 | 9 条 |
| 红果免费短剧 | 7.2.5.32 | 10 条 |
| 微信 WeChat | 8.0.79 | 3 条 + 9 条通用第三方 |
| 番茄小说 | 12 条启用 + 11 条注释 | |
| 饿了么 / 淘宝闪购 | 7 条 | |

## 已知边界

- App 自营广告拦不住：走的是和业务接口同一个域名，DNS 层无法区分。
- 拦广告 SDK 有副作用：激励视频、看广告得积分这类功能会直接报错或黑屏。
- 规则只做域名层拦截，不做 HTTPS 内容过滤。
