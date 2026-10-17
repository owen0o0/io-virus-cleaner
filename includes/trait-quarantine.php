<?php
/**
 * 隔离区
 *
 * IO_Virus_Cleaner 的一部分，按功能拆出来；方法之间仍然用 self:: 互相调用。
 */

if (!defined('ABSPATH')) {
    exit;
}

trait IO_VC_Quarantine {
    private static function render_quarantine_notice() {
        $files = self::quarantine_files();
        $count = count($files);
        if($count <= 0) { 
            return;
        }
        echo '<div class="notice notice-info"><p>';
        echo '隔离不会改文件内容，只是把文件移到 <code>wp-content/io-virus-quarantine/</code>，并在原文件名后加上 <code>.txt</code>，避免再被网站执行。';
        if ($count > 0) {
            echo '当前有 <strong>' . (int) $count . '</strong> 个隔离文件。';
        } else {
            echo '当前没有隔离文件。';
        }
        echo '</p>';
        if ($count > 0) {
            echo '<form method="post" action="' . esc_url(admin_url('admin-post.php')) . '" style="margin:0 0 8px 0;">';
            wp_nonce_field('io_vc_purge_quarantine');
            echo '<input type="hidden" name="action" value="io_vc_purge_quarantine">';
            submit_button('删除隔离文件', 'delete', 'submit', false);
            echo '</form>';
        }
        echo '</div>';
    }

    public static function handle_purge_quarantine() {
        self::guard('io_vc_purge_quarantine');
        $deleted  = 0;
        $failed   = 0;
        $failures = array();
        foreach (self::quarantine_files() as $path) {
            if (@unlink($path)) {
                $deleted++;
            } else {
                $failed++;
                $failures[$path] = self::delete_failure_reason($path);
            }
        }
        self::remove_empty_quarantine_dirs();
        if ($failures) {
            set_transient(self::failed_key(), $failures, 10 * MINUTE_IN_SECONDS);
        }
        $notice = sprintf('已删除 %d 个隔离文件', $deleted);
        if ($failed) {
            $notice .= sprintf('，%d 个失败（需要手动删除，见下方说明）', $failed);
        }
        wp_safe_redirect(add_query_arg('io_vc_notice', $notice, admin_url('tools.php?page=' . self::SLUG)));
        exit;
    }

    private static function quarantine_root() {
        return WP_CONTENT_DIR . '/io-virus-quarantine';
    }

    private static function quarantine_files() {
        $root = realpath(self::quarantine_root());
        if (!$root || !is_dir($root)) {
            return array();
        }
        $files = array();
        try {
            $iterator = new RecursiveIteratorIterator(
                new RecursiveDirectoryIterator($root, FilesystemIterator::SKIP_DOTS),
                RecursiveIteratorIterator::LEAVES_ONLY,
                RecursiveIteratorIterator::CATCH_GET_CHILD
            );
            foreach ($iterator as $file) {
                if (!$file->isFile()) {
                    continue;
                }
                $path = $file->getPathname();
                $real = realpath($path);
                if ($real === false || strpos($real, $root . DIRECTORY_SEPARATOR) !== 0) {
                    continue;
                }
                $base = basename($real);
                if ($base === 'index.php' || $base === '.htaccess') {
                    continue;
                }
                $files[] = $real;
            }
        } catch (Exception $e) {
            return array();
        }
        return $files;
    }

    private static function remove_empty_quarantine_dirs() {
        $root = realpath(self::quarantine_root());
        if (!$root || !is_dir($root)) {
            return;
        }
        $dirs = array($root);
        try {
            $iterator = new RecursiveIteratorIterator(
                new RecursiveDirectoryIterator($root, FilesystemIterator::SKIP_DOTS),
                RecursiveIteratorIterator::CHILD_FIRST,
                RecursiveIteratorIterator::CATCH_GET_CHILD
            );
            foreach ($iterator as $item) {
                if ($item->isDir()) {
                    $dirs[] = $item->getPathname();
                }
            }
        } catch (Exception $e) {
            return;
        }
        usort($dirs, function ($a, $b) {
            return strlen($b) - strlen($a);
        });
        foreach ($dirs as $dir) {
            $real = realpath($dir);
            if (!$real || ($real !== $root && strpos($real, $root . DIRECTORY_SEPARATOR) !== 0)) {
                continue;
            }
            $list = @scandir($real);
            if (!is_array($list)) {
                continue;
            }
            $left = array();
            foreach ($list as $name) {
                if ($name !== '.' && $name !== '..') {
                    $left[] = $name;
                }
            }
            $only_guards = true;
            foreach ($left as $name) {
                if (!in_array($name, array('index.php', '.htaccess'), true)) {
                    $only_guards = false;
                    break;
                }
            }
            if (!$only_guards) {
                continue;
            }
            foreach ($left as $name) {
                @unlink($real . DIRECTORY_SEPARATOR . $name);
            }
            if ($real !== $root) {
                @rmdir($real);
            }
        }
        @rmdir($root);
    }

    private static function quarantine($path) {
        $dir = WP_CONTENT_DIR . '/io-virus-quarantine/' . gmdate('Ymd-His');
        if (!wp_mkdir_p($dir)) {
            return false;
        }
        if (!file_exists($dir . '/index.php')) {
            file_put_contents($dir . '/index.php', "<?php\nhttp_response_code(403);\nexit;\n");
        }
        if (!file_exists($dir . '/.htaccess')) {
            file_put_contents($dir . '/.htaccess', "Require all denied\nDeny from all\n");
        }
        $dest = $dir . '/' . self::normalize_name(basename($path)) . '.txt';
        if (file_exists($dest)) {
            $dest = $dir . '/' . md5($path) . '-' . self::normalize_name(basename($path)) . '.txt';
        }
        if (@rename($path, $dest)) {
            return true;
        }
        if (!@copy($path, $dest)) {
            return false;
        }
        if (@unlink($path)) {
            return true;
        }
        // 原文件删不掉：把刚复制的副本也删了，不要在隔离区里留下一份、原处还有一份
        @unlink($dest);
        return false;
    }
}
