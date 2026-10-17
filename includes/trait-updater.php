<?php
/**
 * 自动更新（从 GitHub Releases 取）
 *
 * IO_Virus_Cleaner 的一部分，按功能拆出来；方法之间仍然用 self:: 互相调用。
 */

if (!defined('ABSPATH')) {
    exit;
}

trait IO_VC_Updater {
    /**
     * 取 GitHub 最新的 Release 并检查格式，整理成统一的数组（version、download、sha256、homepage、changelog……）。
     * 不合格（没有同名 zip 附件、下载地址不在本仓库的 Release 下、拿不到 sha256 等）一律当作没有更新。
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
        $ttl  = 10 * MINUTE_IN_SECONDS;
        $res  = wp_remote_get(self::UPDATE_API, array(
            'timeout'     => 8,
            'redirection' => 2,
            'headers'     => array('Accept' => 'application/vnd.github+json', 'X-GitHub-Api-Version' => '2022-11-28'),
        ));
        if (!is_wp_error($res)) {
            $code = (int) wp_remote_retrieve_response_code($res);
            if ($code === 200) {
                $info = self::update_from_release(json_decode(wp_remote_retrieve_body($res), true));
            } elseif ($code === 403 || $code === 429) {
                // 未登录的 API 每个 IP 每小时只有 60 次，撞上限额就先歇一小时
                $ttl = HOUR_IN_SECONDS;
            }
        }
        set_transient($key, $info ?: array(), $info ? HOUR_IN_SECONDS : $ttl);
        return $info;
    }

    /**
     * 把 Release 的 JSON 整理成更新信息。只认两个东西：
     * 版本号来自 tag（v1.2.1 或 1.2.1），zip 必须是附件里叫 io-virus-cleaner-<版本>.zip 的那个，
     * 地址必须正好是 https://github.com/<本仓库>/releases/download/<tag>/<文件名>。
     * sha256 优先用 GitHub 给附件算的 digest，没有就读同名的 .sha256 附件。拿不到一律不更新。
     */
    private static function update_from_release($rel) {
        if (!is_array($rel) || !empty($rel['draft']) || !empty($rel['prerelease'])
            || empty($rel['tag_name']) || !is_string($rel['tag_name']) || !isset($rel['assets']) || !is_array($rel['assets'])) {
            return null;
        }
        $tag     = $rel['tag_name'];
        $version = ltrim($tag, 'vV');
        if (!preg_match('/^\d+(\.\d+){1,3}$/', $version) || !preg_match('/^[vV]?[0-9.]+$/', $tag)) {
            return null;
        }
        $zip_name = 'io-virus-cleaner-' . $version . '.zip';
        $download = self::DOWNLOAD_PREFIX . $tag . '/' . $zip_name;
        $zip      = null;
        $sum_url  = '';
        foreach ($rel['assets'] as $asset) {
            if (!is_array($asset) || !isset($asset['name'], $asset['browser_download_url'])) {
                continue;
            }
            if ($asset['name'] === $zip_name && $asset['browser_download_url'] === $download) {
                $zip = $asset;
            } elseif ($asset['name'] === $zip_name . '.sha256' && $asset['browser_download_url'] === $download . '.sha256') {
                $sum_url = $asset['browser_download_url'];
            }
        }
        if (!$zip) {
            return null;
        }
        $sha = '';
        if (isset($zip['digest']) && is_string($zip['digest']) && preg_match('/^sha256:([a-f0-9]{64})$/i', $zip['digest'], $m)) {
            $sha = strtolower($m[1]);
        } elseif ($sum_url !== '') {
            $res = wp_remote_get($sum_url, array('timeout' => 8, 'redirection' => 3));
            if (!is_wp_error($res) && (int) wp_remote_retrieve_response_code($res) === 200
                && preg_match('/^\s*([a-f0-9]{64})\b/i', (string) wp_remote_retrieve_body($res), $m)) {
                $sha = strtolower($m[1]);
            }
        }
        if ($sha === '') {
            return null;
        }
        return array(
            'version'      => $version,
            'download'     => $download,
            'sha256'       => $sha,
            'homepage'     => self::UPDATE_URI,
            'requires'     => '5.8',
            'requires_php' => '7.4',
            'changelog'    => isset($rel['body']) && is_string($rel['body']) ? $rel['body'] : '',
        );
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
            'url'     => isset($info['homepage']) ? (string) $info['homepage'] : self::UPDATE_URI,
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
            'homepage'      => isset($info['homepage']) ? (string) $info['homepage'] : self::UPDATE_URI,
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
        if ($reply !== false || !is_string($package) || strpos($package, self::DOWNLOAD_PREFIX) !== 0) {
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
