<?php
/**
 * 自动更新（自建更新源）
 *
 * IO_Virus_Cleaner 的一部分，按功能拆出来；方法之间仍然用 self:: 互相调用。
 */

if (!defined('ABSPATH')) {
    exit;
}

trait IO_VC_Updater {
    /**
     * 取 info.json 并检查格式。不合格（不是 HTTPS、下载地址不在更新目录下、没有 sha256 等）一律当作没有更新。
     * 缓存 1 小时，$fresh 为真时不用缓存（下载更新包前要拿最新的哈希）。
     */
    private static function update_info($fresh = false) {
        $key = 'io_vc_update_info';
        if (!$fresh) {
            $cached = get_transient($key);
            if (is_array($cached)) {
                return $cached ?: null;
            }
        }
        $info = null;
        $res  = wp_remote_get(self::UPDATE_INFO, array('timeout' => 8, 'redirection' => 2));
        if (!is_wp_error($res) && wp_remote_retrieve_response_code($res) === 200) {
            $data = json_decode(wp_remote_retrieve_body($res), true);
            if (is_array($data)
                && isset($data['version'], $data['download'], $data['sha256'])
                && preg_match('/^\d+(\.\d+){1,3}([-.\w]*)?$/', (string) $data['version'])
                && preg_match('/^[a-f0-9]{64}$/i', (string) $data['sha256'])
                && is_string($data['download'])
                && strpos($data['download'], self::UPDATE_URI) === 0
                && strpos($data['download'], '..') === false
                && substr($data['download'], -4) === '.zip'
            ) {
                $info = $data;
            }
        }
        set_transient($key, $info ?: array(), $info ? HOUR_IN_SECONDS : 10 * MINUTE_IN_SECONDS);
        return $info;
    }

    /**
     * WordPress 检查插件更新时调用（Update URI 的主机名对应的过滤器）。
     * 返回的 version 比本地大，后台就会出现「有新版本」。
     */
    public static function check_update($update, $plugin_data, $plugin_file, $locales) {
        if ($plugin_file !== plugin_basename(IO_VC_FILE)) {
            return $update;
        }
        $info = self::update_info();
        if (!$info) {
            return $update;
        }
        $out = array(
            'slug'    => self::SLUG,
            'version' => (string) $info['version'],
            'url'     => isset($info['homepage']) ? (string) $info['homepage'] : 'https://www.iotheme.cn/',
            'package' => (string) $info['download'],
        );
        foreach (array('requires', 'requires_php', 'tested') as $k) {
            if (!empty($info[$k])) {
                $out[$k] = (string) $info[$k];
            }
        }
        return $out;
    }

    /**
     * 「查看版本详情」弹窗。
     */
    public static function plugin_info($result, $action, $args) {
        if ($action !== 'plugin_information' || empty($args->slug) || $args->slug !== self::SLUG) {
            return $result;
        }
        $info = self::update_info();
        if (!$info) {
            return $result;
        }
        $log = isset($info['changelog']) ? (string) $info['changelog'] : '';
        return (object) array(
            'name'          => 'IO Virus Cleaner',
            'slug'          => self::SLUG,
            'version'       => (string) $info['version'],
            'author'        => '一为',
            'homepage'      => isset($info['homepage']) ? (string) $info['homepage'] : 'https://www.iotheme.cn/',
            'requires'      => isset($info['requires']) ? (string) $info['requires'] : '5.8',
            'requires_php'  => isset($info['requires_php']) ? (string) $info['requires_php'] : '7.4',
            'download_link' => (string) $info['download'],
            'sections'      => array(
                'description' => 'WordPress 病毒和木马扫描清理：按文件名、内容特征和通用 webshell 写法识别，可以扫描整个 wwwroot，支持命令行。',
                'changelog'   => $log !== '' ? nl2br(esc_html($log)) : '无',
            ),
        );
    }

    /**
     * 自己下载更新包并校验 sha256，对不上就不装。
     * 更新包会直接覆盖插件文件，源站或传输被动了手脚，这里是最后一道关。
     */
    public static function verify_package($reply, $package, $upgrader) {
        if ($reply !== false || !is_string($package) || strpos($package, self::UPDATE_URI) !== 0) {
            return $reply;
        }
        $info = self::update_info(true);
        if (!$info || $info['download'] !== $package) {
            return new WP_Error('io_vc_update_info', '更新信息无效，已取消更新。');
        }
        if (!function_exists('download_url')) {
            require_once ABSPATH . 'wp-admin/includes/file.php';
        }
        $tmp = download_url($package, 300);
        if (is_wp_error($tmp)) {
            return $tmp;
        }
        $hash = (string) @hash_file('sha256', $tmp);
        if ($hash === '' || !hash_equals(strtolower((string) $info['sha256']), $hash)) {
            @unlink($tmp);
            return new WP_Error('io_vc_update_hash', '更新包的 sha256 校验失败，已取消更新。');
        }
        return $tmp;
    }
}
