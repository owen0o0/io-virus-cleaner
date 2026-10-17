<?php
/**
 * 木马特征和判定
 *
 * IO_Virus_Cleaner 的一部分，按功能拆出来；方法之间仍然用 self:: 互相调用。
 */

if (!defined('ABSPATH')) {
    exit;
}

trait IO_VC_Signatures {
    private static function names() {
        return array(
            'io-cache-helper.php',
            'io-perf-helper.php',
            'io-perf-monitor.php',
            'io-assets-cache.php',
            'io-thumb-cache.php',
            'gen_x.php',
            'gen_wlb.php',
            'c2io.php',
            'io-sh.php',
            'pwn.so',
            'wlb_run.php',
            'wlb_cmd.txt',
            'wlb_probe.php',
            'wlb_xff_probe.php',
            'wlb_users.txt',
            'wlb_wpc_orig.bak',
        );
    }

    private static function markers() {
        static $list = null;
        if ($list !== null) {
            return $list;
        }
        return $list = array(
            'IO_HEAL_BOOT',
            'IO_AGENT_BOOT',
            'xxnkey2026',
            'xxn12026k',
            'xxngen12026',
            'wqdc2key2026',
            'wlbgen20',
            'plugin_binalar_eski',
            '216.167.81.141',
            'ai.025gl.com',
            'IOOK_AIDHB',
            '/etc/ld.so.preload',
            '/tmp/rootbash',
            '/tmp/pwn_done',
            'IO Cache Helper -',
            'IO Perf Monitor -',
        );
    }

    private static function normalize_name($name) {
        return str_replace(array("\u{2010}", "\u{2011}", "\u{2012}", "\u{2013}", "\u{2212}"), '-', (string) $name);
    }

    private static function name_matches($basename) {
        $name = self::normalize_name($basename);
        if (in_array($name, self::names(), true)) {
            return '文件名';
        }
        if (preg_match('/_io_[cx]\.php$/i', $name)) {
            return '头像目录木马文件名';
        }
        if (preg_match('/^\.io_agent_[a-f0-9]{8}$/', $name)) {
            return '临时锁文件';
        }
        if (preg_match('/^ovd-\d{4}-\d{2}-\d{2}-\d+\.log$/', $name)) {
            return '远控键盘记录';
        }
        if (preg_match('/^wlb_.*\.(php|txt|bak|log)$/i', $name)) {
            return '临时目录入侵文件';
        }
        return '';
    }

    private static function path_name_matches($path) {
        $base   = basename($path);
        $parent = basename(dirname($path));
        if ($parent === '.data' && (self::under_upload($path) || self::under_temp($path))) {
            return '远控记录 .data';
        }
        // 上传目录里不会有正常的 PHP；文件名是公开流传的 WebShell 名字，直接算高可信
        if (preg_match('/^(?:c99|c100|r57|wso\d*|b374k|indoxploit|p0wny(?:shell)?|alfa-?shell|webshell|filesman)\.(?:php\d?|phtml|pht|phar)$/i', $base) && self::under_upload($path)) {
            return '上传目录里的常见 WebShell 文件名';
        }
        if (!self::under_temp($path)) {
            return '';
        }
        if ($base === 'ant.log' && self::file_has_marker($path, array('ai.025gl.com', '[purgatory]', '[keylogger]'))) {
            return '远控日志';
        }
        if ($base === 'ant') {
            $size = @filesize($path);
            if (($size !== false && $size > 1048576) || self::file_has_marker($path, array('ai.025gl.com', 'purgatory'))) {
                return '远控程序';
            }
        }
        if (in_array($base, array('rootbash', 'pwn_done'), true)) {
            return '提权后门留下的文件';
        }
        return '';
    }

    private static function under_temp($path) {
        return self::under_root($path, self::temp_roots());
    }

    private static function under_upload($path) {
        if (self::under_root($path, self::upload_roots())) {
            return true;
        }
        // 额外扫描的其他站点：它们的上传目录不在本站的上传根目录里
        $real = self::real($path);
        $real = str_replace('\\', '/', $real === false ? $path : $real);
        return strpos($real, '/wp-content/uploads/') !== false;
    }

    /**
     * realpath 带一条缓存：同一个文件在一轮判断里会被问好几次。
     */
    private static function real($path) {
        static $last_path = null, $last_real = null;
        if ($path === $last_path) {
            return $last_real;
        }
        $last_path = $path;
        return $last_real = realpath($path);
    }

    /**
     * 小文件只读一次：content_matches 和 generic_matches 共用。
     */
    private static function read_small($path, $max = 1048576) {
        static $last_path = null, $last_data = '';
        if ($path === $last_path) {
            return $last_data;
        }
        $last_path = $path;
        $size = @filesize($path);
        if ($size === false || $size < 1 || $size > $max) {
            return $last_data = '';
        }
        $data = @file_get_contents($path);
        return $last_data = is_string($data) ? $data : '';
    }

    private static function under_root($path, $roots) {
        $real = self::real($path);
        if ($real === false) {
            $real = $path;
        }
        foreach ($roots as $root) {
            if (!$root) {
                continue;
            }
            $prefix = rtrim($root, DIRECTORY_SEPARATOR) . DIRECTORY_SEPARATOR;
            if (strpos($real, $prefix) === 0 || strpos($path, $prefix) === 0) {
                return true;
            }
        }
        return false;
    }

    private static function file_has_marker($path, $markers) {
        $data = @file_get_contents($path, false, null, 0, 65536);
        if (!is_string($data) || $data === '') {
            return false;
        }
        foreach ($markers as $marker) {
            if (strpos($data, $marker) !== false) {
                return true;
            }
        }
        return false;
    }

    private static function content_matches($path) {
        $size = @filesize($path);
        if ($size === false || $size < 1 || !self::should_read_content($path, $size)) {
            return '';
        }
        if ($size <= 524288) {
            $data = self::read_small($path);
            if ($data === '') {
                return '';
            }
            foreach (self::markers() as $marker) {
                if (strpos($data, $marker) !== false) {
                    return '内容特征';
                }
            }
            return '';
        }
        // 大文件分段读，段与段之间留一小段重叠，避免特征正好被切开
        $fh = @fopen($path, 'rb');
        if (!$fh) {
            return '';
        }
        $window = (int) min($size, 16777216);
        $read   = 0;
        $carry  = '';
        $found  = false;
        while ($read < $window && !feof($fh)) {
            $chunk = fread($fh, 131072);
            if (!is_string($chunk) || $chunk === '') {
                break;
            }
            $read += strlen($chunk);
            $data  = $carry . $chunk;
            foreach (self::markers() as $marker) {
                if (strpos($data, $marker) !== false) {
                    $found = true;
                    break 2;
                }
            }
            $carry = substr($chunk, -32);
        }
        fclose($fh);
        return $found ? '内容特征' : '';
    }

    private static function should_read_content($path, $size) {
        // 主题、插件里的图片、字体、样式、脚本、翻译文件不会放这次入侵的内容特征，不用逐个读取。
        // 上传目录、临时目录和 .data 里的文件照常查。图片里夹带 PHP 由 image_php_matches 单独处理。
        $ext = strtolower((string) pathinfo($path, PATHINFO_EXTENSION));
        if (isset(self::asset_exts()[$ext])
            && basename(dirname($path)) !== '.data'
            && !self::under_upload($path)
            && !self::under_temp($path)) {
            return false;
        }
        if ($size <= 524288) {
            return true;
        }
        if (basename(dirname($path)) === '.data' || self::under_temp($path)) {
            return $size <= 16777216;
        }
        $ext = strtolower((string) pathinfo($path, PATHINFO_EXTENSION));
        if (in_array($ext, array('php', 'phtml', 'php3', 'php4', 'php5', 'php7', 'pht', 'phar', 'inc', 'log', 'txt', 'bak', 'j', 'json'), true)) {
            return $size <= 2097152;
        }
        $head = @file_get_contents($path, false, null, 0, 5);
        return (is_string($head) && strncmp($head, "\x7fELF", 4) === 0)
            || (is_string($head) && strncmp($head, '<?php', 5) === 0);
    }

    private static function is_threat($path) {
        $real = realpath($path);
        if ($real === false || !is_file($real)) {
            return false;
        }
        if (!self::path_allowed($real)) {
            return false;
        }
        return self::threat_reason($real) !== '';
    }

    private static function threat_reason($real) {
        $reason = self::name_matches(basename($real));
        if ($reason === '') {
            $reason = self::path_name_matches($real);
        }
        if ($reason === '') {
            $reason = self::content_matches($real);
        }
        if ($reason === '') {
            $reason = self::behavior_matches($real);
        }
        if ($reason === '') {
            $reason = self::preload_matches($real);
        }
        if ($reason === '') {
            $reason = self::generic_matches($real);
        }
        return $reason;
    }

    private static function asset_exts() {
        static $set = null;
        if ($set === null) {
            $set = array_fill_keys(array(
                'jpg', 'jpeg', 'png', 'gif', 'webp', 'ico', 'bmp', 'svg', 'avif',
                'css', 'scss', 'less', 'map', 'js', 'mjs',
                'woff', 'woff2', 'ttf', 'eot', 'otf',
                'mo', 'po', 'pot', 'md', 'mp3', 'mp4', 'webm', 'ogg', 'pdf', 'ds_store',
            ), true);
        }
        return $set;
    }

    private static function php_exts() {
        return array('php', 'phtml', 'php3', 'php4', 'php5', 'php7', 'pht', 'phar', 'inc');
    }

    private static function image_exts() {
        return array('jpg', 'jpeg', 'png', 'gif', 'webp', 'ico', 'bmp');
    }

    /**
     * 高可信：请求参数直接进入执行函数，或已知 WebShell 的写法。几乎不会出现在正常代码里。
     */
    private static function high_patterns() {
        static $list = null;
        if ($list !== null) {
            return $list;
        }
        $sg   = '\$_(?:GET|POST|REQUEST|COOKIE)';
        $wrap = '(?:(?:base64_decode|gzinflate|gzuncompress|gzdecode|str_rot13|rawurldecode|urldecode|stripslashes|trim)\s*\(\s*)*';
        return $list = array(
            'eval/assert 直接执行请求参数' => '/\b(?:eval|assert)\s*\(\s*@?\s*' . $wrap . '@?' . $sg . '\b/i',
            // 先把请求参数放进变量，稍后再 eval：$b=substr($_POST['s'],1); eval(base64_decode($b));
            '请求参数经变量传给 eval/assert' => '/\$(\w+)\s*=\s*[^;\'"]{0,100}' . $sg . '\b[^;]*;[\s\S]{0,300}?\b(?:eval|assert)\s*\(\s*@?\s*(?:[a-z_0-9]+\s*\(\s*)*@?\$\1\b/i',
            '系统命令直接执行请求参数'     => '/\b(?:system|exec|shell_exec|passthru|popen|proc_open|pcntl_exec)\s*\(\s*@?' . $sg . '\b/i',
            '请求参数当函数名调用'         => '/' . $sg . '\s*\[[^\]]{1,40}\]\s*\(\s*' . $sg . '\s*\[/i',
            '回调函数由请求参数指定'       => '/\b(?:call_user_func(?:_array)?|array_map|array_filter|usort|uasort|uksort)\s*\(\s*@?' . $sg . '\b/i',
            'preg_replace /e 执行请求参数' => '/preg_replace\s*\(\s*[\'"]\/[^\'"]*\/[a-z]*e[a-z]*[\'"]\s*,\s*' . $sg . '/i',
            'eval 执行 php://input'        => '/\beval\s*\(\s*@?\s*file_get_contents\s*\(\s*[\'"]php:\/\/input/i',
            'create_function 接收请求参数' => '/create_function\s*\([^;]{0,80}' . $sg . '/i',
            'include 请求参数指定的文件'   => '/\b(?:include|require)(?:_once)?\s*\(?\s*@?' . $sg . '\s*\[/i',
            '按请求参数写文件'             => '/file_put_contents\s*\(\s*@?' . $sg . '\s*\[/i',
            '函数名用 base64 藏起来'       => '/[\'"](?:ZXZhbA==|YXNzZXJ0|c3lzdGVt|ZXhlYw==|c2hlbGxfZXhlYw==|cGFzc3RocnU=|cG9wZW4=|cHJvY19vcGVu)[\'"]/',
            // 后门不走 GET/POST，改从请求头里取代码：eval($_SERVER['HTTP_X_CMD'])
            '请求头内容直接执行'           => '/\b(?:eval|assert|system|exec|shell_exec|passthru|popen)\s*\(\s*@?\s*' . $wrap . '@?\$_SERVER\s*\[\s*[\'"]HTTP_/i',
            // array_map('assert', $_POST) 这类：危险函数名写死，参数是请求内容，两种先后顺序都认
            '危险函数当回调处理请求参数'   => '/\b(?:array_map|array_filter|array_walk|array_reduce|usort|uasort|uksort|call_user_func(?:_array)?)\s*\((?:[^;]{0,200}[\'"](?:assert|system|exec|shell_exec|passthru|popen|proc_open)[\'"][^;]{0,200}' . $sg . '\b|[^;]{0,200}' . $sg . '\b[^;]{0,200}[\'"](?:assert|system|exec|shell_exec|passthru|popen|proc_open)[\'"])/i',
            // $f = $_POST['f']; $f($_POST['x']);
            '请求参数存进变量再当函数调用' => '/\$(\w+)\s*=\s*@?' . $sg . '\s*\[[^\]]{1,40}\]\s*;[\s\S]{0,200}?\$\1\s*\(\s*@?' . $sg . '\b/i',
            // 用请求里的用户 ID 直接签发登录 Cookie，等于免密码登录任意账号
            '请求参数直接决定登录用户'     => '/\bwp_(?:set_auth_cookie|set_current_user)\s*\(\s*(?:\(\s*int\s*\)\s*|intval\s*\(\s*)?@?' . $sg . '\b/i',
            // 下面三条是反弹 shell，不需要请求参数，扫描时按关键字单独放行
            '反弹 shell（/dev/tcp）'       => '/\/dev\/tcp\/\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\/\d+|bash\s+-i\s*>&?\s*\/dev\/tcp\//i',
            '反弹 shell（nc 或 mkfifo）'   => '/\bnc(?:at)?\s+(?:-\w+\s+)*-e\s+\/bin\/(?:ba)?sh|\bmkfifo\s+\/tmp\/\w+[\s\S]{0,80}\/bin\/(?:ba)?sh\s+-i/i',
            '反弹 shell（fsockopen 配合 /bin/sh）' => '/\bfsockopen\s*\([^;]{0,200}\)\s*;[\s\S]{0,600}?\b(?:proc_open|popen|exec|shell_exec|system|passthru)\s*\([^;]{0,120}\/bin\/(?:ba)?sh/i',
        );
    }

    /**
     * 可疑：写法和木马相似，但正常的老插件、加密主题偶尔也会用。
     */
    private static function suspect_patterns() {
        return array(
            '可疑：eval 解码后执行'        => '/\beval\s*\(\s*@?\s*(?:gzinflate|gzuncompress|gzdecode|str_rot13|base64_decode)\s*\(/i',
            '可疑：用 chr 拼出函数名'      => '/(?:chr\s*\(\s*\d+\s*\)\s*\.\s*){6,}/i',
            '可疑：遍历目录批量改文件时间' => '/function\s+\w+\s*\([^)]*\)\s*\{[^}]{0,300}scandir[\s\S]{0,400}@?touch\s*\(/i',
            '可疑：用客户端文件名保存上传' => '/move_uploaded_file\s*\([^;]*\$_FILES\s*\[[^\]]+\]\s*\[\s*[\'"]name[\'"]\s*\]/i',
            // 后门常在这里悄悄加一个管理员；正常的安装向导、会员插件也可能这样写，所以只算可疑
            '可疑：代码里直接创建管理员' => '/\b(?:wp_create_user|wp_insert_user|wp_update_user)\s*\([^;]{0,300}[\'"]administrator[\'"]/i',
        );
    }

    /**
     * 统计文件里有多少个「用十六进制写出来的函数名」，例如 '7068705f756e616d65' 就是 php_uname。
     * 正常代码里几乎不会出现，WebShell 常用它躲开关键字搜索。
     */
    private static function hex_function_names($data) {
        static $set = null;
        if ($set === null) {
            $set = array();
            foreach (array(
                'php_uname', 'file_get_contents', 'base64_decode', 'assert', 'eval', 'system', 'exec',
                'shell_exec', 'passthru', 'popen', 'proc_open', 'unlink', 'fwrite', 'fopen', 'scandir',
                'chmod', 'readfile', 'rename', 'mkdir', 'rmdir', 'copy', 'touch', 'chdir', 'getcwd',
            ) as $fn) {
                $set[bin2hex($fn)] = true;
            }
        }
        // 先用便宜的查找挡掉绝大多数文件
        if (stripos($data, '617373657274') === false
            && stripos($data, '6576616c') === false
            && stripos($data, '73797374656d') === false
            && stripos($data, '6261736536345f') === false
            && stripos($data, '7068705f756e616d65') === false) {
            return 0;
        }
        if (!preg_match_all('/[\'"]((?:[0-9a-f]{2}){2,20})[\'"]/i', $data, $m)) {
            return 0;
        }
        $hit = array();
        foreach ($m[1] as $hex) {
            $hex = strtolower($hex);
            if (isset($set[$hex])) {
                $hit[$hex] = true;
            }
        }
        return count($hit);
    }

    /**
     * "\x63\x72\x65\x61\x74\x65\x5f\x66\x75\x6e\x63\x74\x69\x6f\x6e" 这种写法，解出来是危险函数名。
     */
    private static function escaped_dangerous_name($data) {
        if (strpos($data, '\\x') === false && strpos($data, '\\X') === false) {
            return false;
        }
        if (!preg_match_all('/["\']((?:\\\\x[0-9a-f]{2}){4,40})["\']/i', $data, $m)) {
            return false;
        }
        $bad = array('create_function', 'eval', 'assert', 'system', 'exec', 'shell_exec', 'passthru',
            'popen', 'proc_open', 'base64_decode', 'file_put_contents', 'call_user_func', 'preg_replace');
        foreach ($m[1] as $esc) {
            $plain = strtolower(preg_replace_callback('/\\\\x([0-9a-f]{2})/i', function ($x) {
                return chr(hexdec($x[1]));
            }, $esc));
            if (in_array($plain, $bad, true)) {
                return true;
            }
        }
        return false;
    }

    private static function known_shell_pattern() {
        return '/\b(?:FilesMan|c99shell|c99_sess|r57shell|b374k|wso_version|IndoXploit|Weevely|China\s*Chopper|PHPSpy|p0wny|Ani-Shell|Safe0ver|ALFA\s*TEaM)\b/i';
    }

    private static function generic_matches($path) {
        $size = @filesize($path);
        if ($size === false || $size < 1) {
            return '';
        }
        $name = strtolower(basename($path));
        $ext  = strtolower((string) pathinfo($path, PATHINFO_EXTENSION));

        if ($name === '.htaccess' || $name === '.user.ini') {
            return self::config_matches($path, $size);
        }
        if (in_array($ext, self::image_exts(), true)) {
            return self::image_php_matches($path, $size);
        }
        if (!in_array($ext, self::php_exts(), true) || $size > 1048576) {
            return '';
        }
        $data = self::read_small($path);
        if ($data === '') {
            return '';
        }

        // 先用便宜的字符串查找挡掉绝大多数正常文件，再跑正则
        $has_req = strpos($data, '$_') !== false;
        $no_req  = array(
            'eval 执行 php://input'                => 'php://input',
            '函数名用 base64 藏起来'               => '',
            '反弹 shell（/dev/tcp）'               => '/dev/tcp/',
            '反弹 shell（nc 或 mkfifo）'           => '/bin/',
            '反弹 shell（fsockopen 配合 /bin/sh）' => 'fsockopen',
        );
        foreach (self::high_patterns() as $label => $re) {
            if (!$has_req) {
                if (!isset($no_req[$label])) {
                    continue;
                }
                if ($no_req[$label] !== '' && stripos($data, $no_req[$label]) === false) {
                    continue;
                }
            }
            if (preg_match($re, $data)) {
                return $label;
            }
        }
        if (self::hex_function_names($data) >= 6) {
            return '函数名整批用十六进制藏起来';
        }
        if (self::escaped_dangerous_name($data)) {
            return '函数名用 \\x 转义藏起来';
        }
        if (stripos($data, 'MARIJuANA') !== false && preg_match('/\$_(?:FILES|GET|POST)\b/', $data)) {
            return '已知 WebShell：MARIJuANA 文件管理器';
        }
        if (preg_match(self::known_shell_pattern(), $data)
            && preg_match('/\b(?:eval|system|exec|passthru|shell_exec|base64_decode)\s*\(/i', $data)) {
            return '已知 WebShell 特征';
        }
        if ((stripos($data, 'hex2bin') !== false || strpos($data, 'H*') !== false)
            && preg_match('/[\'"][0-9a-f]{120,}[\'"]/i', $data)
            && preg_match('/\bhex2bin\s*\(|pack\s*\(\s*[\'"]H\*[\'"]/i', $data)) {
            return '十六进制字符串还原代码';
        }
        $gate = array(
            '可疑：eval 解码后执行'        => 'eval',
            '可疑：用 chr 拼出函数名'      => 'chr',
            '可疑：用客户端文件名保存上传' => 'move_uploaded_file',
            '可疑：遍历目录批量改文件时间' => 'touch',
            '可疑：代码里直接创建管理员'   => 'administrator',
        );
        $suspect = '';
        foreach (self::suspect_patterns() as $label => $re) {
            if (isset($gate[$label]) && stripos($data, $gate[$label]) === false) {
                continue;
            }
            if (preg_match($re, $data)) {
                $suspect = $label;
                break;
            }
        }
        if ($suspect !== '' && self::is_theme_encrypted($path, $data)) {
            return '';
        }
        if ($suspect !== '') {
            return $suspect;
        }
        if (self::under_upload($path) && !self::is_silence_index($name, $data)) {
            return '可疑：上传目录中的 PHP 文件';
        }
        return '';
    }

    /**
     * 一主题的 OneNav、Swallow 主题和 ioTab 插件自带的加密文件，只用来排除「可疑」类的结果。
     * 要同时满足：文件在对应主题或插件目录里（主题看 style.css 的 Theme Name，插件看顶层 PHP 的 Plugin Name）；
     * 文件开头是加密工具生成的固定外壳。高可信特征和本次入侵的特征不受影响。
     */
    private static function is_theme_encrypted($path, $data) {
        $stubs = array(
            // 加密外壳：可带 namespace Z5Encrypt\xxx;，可带 eval(
            '/^<\?php\s*(?:namespace Z5Encrypt\\\\[^;]{1,120};)?\s*function&[^(]{1,120}\(\)\{static \$a=NULL;if\(\$a===NULL\)\{\$a=(?:eval\()?(?:gzinflate|gzuncompress)\(/',
            // ioTab 里另一种加密文件的版权头
            '/^<\?php\s*\/\*\s*--Copyright:https:\/\/www\.phpcodejm\.com/',
        );
        $matched = false;
        foreach ($stubs as $re) {
            if (preg_match($re, $data)) {
                $matched = true;
                break;
            }
        }
        if (!$matched) {
            return false;
        }
        $real = realpath($path);
        if (!$real) {
            return false;
        }
        $real = str_replace('\\', '/', $real);

        // 按路径里的 wp-content/themes/<名>/ 或 wp-content/plugins/<名>/ 判断，
        // 这样扫描 /www/wwwroot 下其他站点时，也能认出它们自带的加密文件
        if (!preg_match('#^(.*/wp-content)/(themes|plugins)/([^/]+)/#', $real, $m)) {
            return false;
        }
        $base = $m[1] . '/' . $m[2] . '/' . $m[3];
        if ($m[2] === 'themes') {
            // 主题：style.css 的 Theme Name 在白名单里
            $head = (string) @file_get_contents($base . '/style.css', false, null, 0, 4096);
            return (bool) preg_match('/Theme Name:\s*(?:OneNav|Swallow)\b/i', $head);
        }
        // 插件：插件目录顶层某个 PHP 文件头部的 Plugin Name 在白名单里
        foreach ((array) glob($base . '/*.php') as $main) {
            $head = (string) @file_get_contents($main, false, null, 0, 4096);
            if (preg_match('/Plugin Name:\s*ioTab\b/i', $head)) {
                return true;
            }
        }
        return false;
    }

    private static function is_silence_index($name, $data) {
        return $name === 'index.php' && strlen($data) < 200 && stripos($data, 'silence is golden') !== false;
    }

    private static function config_matches($path, $size) {
        if ($size > 65536) {
            return '';
        }
        $data = @file_get_contents($path);
        if (!is_string($data) || $data === '') {
            return '';
        }
        $in_upload = self::under_upload($path);
        if ($in_upload && preg_match('/^\s*(?:AddType|AddHandler|SetHandler|ForceType)\b[^\n]*php/im', $data)) {
            return '上传目录里让图片或文本按 PHP 执行';
        }
        if (preg_match('/^\s*(?:php_value\s+)?auto_(?:prepend|append)_file\b/im', $data)) {
            return $in_upload ? '上传目录里自动包含 PHP 文件' : '可疑：自动包含 PHP 文件（auto_prepend_file）';
        }
        return '';
    }

    private static function image_php_matches($path, $size) {
        $fh = @fopen($path, 'rb');
        if (!$fh) {
            return '';
        }
        $head = (string) fread($fh, 8192);
        $tail = '';
        if ($size > 16384) {
            fseek($fh, -8192, SEEK_END);
            $tail = (string) fread($fh, 8192);
        }
        fclose($fh);
        $data = $head . "\n" . $tail;
        if (stripos($data, '<?php') === false && strpos($data, '<?=') === false) {
            return '';
        }
        if (preg_match('/\b(?:eval|assert|system|exec|shell_exec|passthru|popen|proc_open|base64_decode|file_put_contents|include|require)\b|\$_(?:GET|POST|REQUEST|COOKIE|FILES)\b/i', $data)) {
            return '图片里夹带 PHP 代码';
        }
        return '';
    }

    /**
     * 是否 ELF。小文件已经读进缓存的，直接用缓存，不再打开一次。
     */
    private static function is_elf($path) {
        static $last_path = null, $last = false;
        if ($path === $last_path) {
            return $last;
        }
        $last_path = $path;
        $size = @filesize($path);
        if ($size === false || $size < 64) {
            return $last = false;
        }
        $data = $size <= 524288 ? self::read_small($path) : '';
        $head = $data !== '' ? substr($data, 0, 4) : @file_get_contents($path, false, null, 0, 4);
        return $last = (is_string($head) && strncmp($head, "\x7fELF", 4) === 0);
    }

    private static function preload_matches($path) {
        if (!self::is_elf($path)) {
            return '';
        }
        $hits = self::scan_indicator_groups($path, array(
            'preload' => array('/etc/ld.so.preload'),
            'mark'    => array('/tmp/rootbash', '/tmp/pwn_done', 'pwn_done'),
        ));
        if (empty($hits['preload']) || empty($hits['mark'])) {
            return '';
        }
        return '动态库提权后门';
    }

    private static function behavior_matches($path) {
        if (!self::is_elf($path) || self::elf_link_type($path) !== 'static') {
            return '';
        }
        $hits = self::scan_indicator_groups($path, array(
            'net'  => array('wss://', 'websocket', 'WebSocket'),
            'dns'  => array('LookupHost', 'LookupIP'),
            'file' => array('MkdirAll', 'os.Create', 'CreateTemp'),
        ));
        if (empty($hits['net']) || empty($hits['dns']) || empty($hits['file'])) {
            return '';
        }
        return '静态链接 ELF；含 WebSocket 与 DNS 解析；会创建文件';
    }

    private static function elf_link_type($path) {
        $head = @file_get_contents($path, false, null, 0, 64);
        if (!is_string($head) || strlen($head) < 64 || strncmp($head, "\x7fELF", 4) !== 0 || ord($head[5]) !== 1) {
            return '';
        }
        $class = ord($head[4]);
        if ($class === 2) {
            $phoff     = self::u64le(substr($head, 32, 8));
            $phentsize = unpack('v', substr($head, 54, 2))[1];
            $phnum     = unpack('v', substr($head, 56, 2))[1];
        } elseif ($class === 1) {
            $phoff     = unpack('V', substr($head, 28, 4))[1];
            $phentsize = unpack('v', substr($head, 42, 2))[1];
            $phnum     = unpack('v', substr($head, 44, 2))[1];
        } else {
            return '';
        }
        if ($phnum < 1 || $phnum > 512 || $phentsize < 32 || $phentsize > 1024) {
            return '';
        }
        $table = @file_get_contents($path, false, null, $phoff, $phentsize * $phnum);
        if (!is_string($table) || strlen($table) < $phentsize) {
            return '';
        }
        for ($i = 0; $i < $phnum; $i++) {
            $type = unpack('V', substr($table, $i * $phentsize, 4))[1];
            if ($type === 3) {
                return 'dynamic';
            }
        }
        return 'static';
    }

    private static function u64le($bytes) {
        if (strlen($bytes) < 8) {
            return 0;
        }
        $lo = unpack('V', substr($bytes, 0, 4))[1];
        $hi = unpack('V', substr($bytes, 4, 4))[1];
        return $hi * 4294967296 + $lo;
    }

    private static function scan_indicator_groups($path, $groups) {
        $found  = array();
        $size   = @filesize($path);
        $window = (int) min($size === false ? 0 : $size, 16777216);
        $offset = 0;
        $carry  = '';
        while ($offset < $window) {
            $chunk = @file_get_contents($path, false, null, $offset, 131072);
            if (!is_string($chunk) || $chunk === '') {
                break;
            }
            $data = $carry . $chunk;
            foreach ($groups as $name => $needles) {
                if (!empty($found[$name])) {
                    continue;
                }
                foreach ($needles as $needle) {
                    if (strpos($data, $needle) !== false) {
                        $found[$name] = true;
                        break;
                    }
                }
            }
            if (count($found) === count($groups)) {
                break;
            }
            $carry   = substr($chunk, -32);
            $offset += 131072;
        }
        return $found;
    }
}
