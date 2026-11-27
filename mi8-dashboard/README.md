# 小米8 监控面板

一个网页同时看两样东西：**网关代理流量**（Xray）和 **AdGuard Home 广告拦截**。跑在小米8上，局域网内用手机或电脑浏览器打开就能看。

## 文件

- `server.py` — 面板服务（Python 标准库，不用装任何包）
- `index.html` — 面板页面（单文件，内联 CSS/JS，不联网也能打开）
- `README.md` — 本说明

## 传到小米8

在小米8 Termux 里建目录并下载这三个文件（把下面链接换成实际的下载地址）：

```
mkdir -p ~/mi8-dashboard
```

```
curl -L -o ~/mi8-dashboard/server.py '<server.py 下载链接>'
```

```
curl -L -o ~/mi8-dashboard/index.html '<index.html 下载链接>'
```

## 启动

```
python3 ~/mi8-dashboard/server.py
```

看到 `Mi8 dashboard listening on http://0.0.0.0:8080` 就是起来了。

用手机或电脑浏览器打开：

```
http://192.168.5.200:8080
```

## 面板内容

- **代理（网关 Xray）**：Xray 运行状态、两个日本节点（AWS01、东京02）、最近 30 条连接（时间、来源 IP、域名、走线：直连 / 日本-AWS01 / 日本-东京02 / 拦截），以及直连和走日本的数量统计。
- **AdGuard Home**：先输入 AGH 管理密码点“连接”（密码只存在浏览器会话里，不写进任何文件），连接后显示总查询数、拦截数、拦截率、拦截最多的域名、查询最多的域名和最近查询记录。没连接时也可以点链接直接打开 AGH 管理页面。

## 开机自启

新建自启脚本（一条命令）：

```
su -c 'printf "%s\n" "#!/system/bin/sh" "while [ \"$(getprop sys.boot_completed)\" != \"1\" ]; do sleep 2; done" "sleep 15" "while true; do" "  /data/data/com.termux/files/usr/bin/python3 /data/data/com.termux/files/home/mi8-dashboard/server.py" "  sleep 5" "done" > /data/adb/service.d/mi8-dashboard.sh'
```

给执行权限：

```
su -c 'chmod +x /data/adb/service.d/mi8-dashboard.sh'
```

## 停止

前台运行时按 `Ctrl+C` 即可停止。

如果已加开机自启，删掉自启脚本并重启小米8，或直接杀掉进程：

```
su -c 'pkill -f mi8-dashboard/server.py'
```

## 说明

- 只读网关日志 `~/xray/gw.log`，不改 Xray 配置；只调 AGH 的查询接口，不改 AGH 配置。
- 面板本身不存任何密码。AGH 密码由你在浏览器里输入，只存在浏览器会话里，关掉页面就没了。
- 端口 8080，普通 Termux 用户就能跑，不需要 root。
