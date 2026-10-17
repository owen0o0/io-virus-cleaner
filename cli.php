<?php
/**
 * 命令行扫描，不需要打开 WordPress，也不受网站 open_basedir（防跨站攻击）限制。
 *
 * 用法（在服务器上用 SSH 执行，建议用 root 或网站运行用户）：
 *
 *   php cli.php                                  只扫本站
 *   php cli.php --dir=/www/wwwroot               连同 /www/wwwroot 下所有站点一起扫
 *   php cli.php --dir=/www/wwwroot,/data/other   多个目录用逗号隔开
 *   php cli.php --dir=/www/wwwroot --exclude=/www/wwwroot/backup,wp-content/uploads/2020,test
 *       --exclude 的写法：绝对路径或相对本站根目录的路径（带 /）排除整个目录；
 *       只写目录名（不带 /）排除任何位置同名的目录。多个用逗号隔开。
 *
 * 只列出结果，不删除、不隔离。确认后到站点后台「工具 → 木马清理」或手动处理。
 * 有「高可信」命中时退出码为 1，只有「可疑」或没有命中时为 0。
 */

if (PHP_SAPI !== 'cli') {
    http_response_code(404);
    exit;
}

// 本文件在 wp-content/plugins/io-virus-cleaner/ 下
define('WP_PLUGIN_DIR', dirname(__DIR__));
define('WP_CONTENT_DIR', dirname(__DIR__, 2));
define('ABSPATH', dirname(__DIR__, 3) . '/');

// 主文件只用到这几个 WordPress 函数，命令行下给个最简版本
function is_admin() { return false; }
function wp_upload_dir() { return array('basedir' => WP_CONTENT_DIR . '/uploads'); }
function get_temp_dir() { return sys_get_temp_dir() . '/'; }
function get_option($name, $default = false) { return $default; }

require __DIR__ . '/io-virus-cleaner.php';

$dirs    = array();
$exclude = array();
foreach (array_slice($argv, 1) as $arg) {
    if (strpos($arg, '--dir=') === 0) {
        $dirs = array_merge($dirs, explode(',', substr($arg, 6)));
    } elseif (strpos($arg, '--exclude=') === 0) {
        $exclude = array_merge($exclude, explode(',', substr($arg, 10)));
    } elseif ($arg === '-h' || $arg === '--help') {
        echo "用法：php cli.php [--dir=/www/wwwroot[,/其他目录]] [--exclude=/绝对路径,相对路径,目录名]\n";
        exit(0);
    }
}

exit(IO_Virus_Cleaner::cli_standalone($dirs, $exclude));
