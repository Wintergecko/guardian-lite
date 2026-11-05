<?php
/** Management authorization, stdin-secret handling and real partial rendering. */
error_reporting(E_ALL);
set_error_handler(static function ($severity, $message, $file, $line) { throw new ErrorException($message, 0, $severity, $file, $line); });
class pm_Exception extends RuntimeException {}
class ManagementRedirect extends RuntimeException {}
class pm_Context {
    public static function getBaseUrl() { return '/modules/guardian-lite/'; }
    public static function getActionUrl($controller, $action = 'index') { return self::getBaseUrl() . $controller . '/' . $action; }
}
class pm_Settings {
    public static $data = [];
    public static function get($key) { return self::$data[$key] ?? ''; }
    public static function set($key, $value) { self::$data[$key] = $value; }
}
class pm_Session {
    public static $admin = true;
    public static $impersonated = false;
    public static function getClient() { return new class { public function isAdmin() { return pm_Session::$admin; } }; }
    public static function isImpersonated() { return self::$impersonated; }
}
class pm_Domain {
    public static function getAllDomains() { return [new class {
        public function getName() { return 'example.com'; }
        public function hasHosting() { return true; }
    }]; }
}
class pm_ApiCli {
    const RESULT_FULL = 1;
    public static $calls = [];
    public static function callSbin($command, $args, $mode, $env = [], $stdin = '') {
        self::$calls[] = [$command, $args, $env, $stdin];
        return ['code' => 0, 'stdout' => json_encode(['ok' => true, 'result' => ['message' => 'Saved']])];
    }
}
class ManagementRequest {
    public $post = [];
    public function isPost() { return true; }
    public function getPost($key, $fallback = '') { return $this->post[$key] ?? $fallback; }
}
class ManagementStatus {
    public function addMessage($type, $message) {}
}
class pm_Controller_Action {
    public $request;
    public $view;
    protected $_status;
    public function __construct() { $this->request = new ManagementRequest(); $this->view = new stdClass(); $this->_status = new ManagementStatus(); }
    public function init() {}
    public function getRequest() { return $this->request; }
    public function redirect($url) { throw new ManagementRedirect($url); }
}
require dirname(__DIR__) . '/plib/controllers/IndexController.php';
function checkManagement($condition, $message) { if (!$condition) { throw new RuntimeException($message); } }

$_SESSION['guardian_lite_csrf'] = 'test-token';
$controller = new IndexController();
$controller->request->post = ['csrf' => 'test-token', 'operation' => 'cloud-save',
    'abuseipdb_key' => 'PRIVATE_API_SECRET', 'turnstile_secret' => 'PRIVATE_TURNSTILE_SECRET', 'consent' => '1'];
try { $controller->manageAction(); } catch (ManagementRedirect $e) { checkManagement(strpos($e->getMessage(), '#guardian-tab-management') !== false, 'Wrong management redirect'); }
[$command, $args, $env, $stdin] = pm_ApiCli::$calls[0];
checkManagement($command === 'guardian-manager' && $args === ['request'] && $env === [], 'Secrets must use stdin, not arguments/environment');
$request = json_decode($stdin, true);
checkManagement($request['abuseipdb_key'] === 'PRIVATE_API_SECRET' && $request['consent'] === true, 'Secret or checkbox lost');
checkManagement(strpos(json_encode(pm_Settings::$data), 'PRIVATE_') === false, 'Request secret leaked into settings feedback');

$controller->request->post = ['csrf' => 'test-token', 'operation' => 'ignore-add',
    'domain' => 'example.com', 'sha256' => str_repeat('a', 64)];
try { $controller->manageAction(); } catch (ManagementRedirect $e) {}
$request = json_decode(pm_ApiCli::$calls[1][3], true);
checkManagement(($request['action'] ?? '') === 'ignore-add' && $request['sha256'] === str_repeat('a', 64), 'Ignore action did not reach fixed manager API');

$_SERVER['REMOTE_ADDR'] = '198.51.100.4';
$controller->request->post = ['csrf' => 'test-token', 'operation' => 'ban', 'network' => '203.0.113.9'];
try { $controller->firewallAction(); } catch (ManagementRedirect $e) {}
$firewallCall = pm_ApiCli::$calls[2];
checkManagement($firewallCall[0] === 'guardian-helper' &&
    $firewallCall[1] === ['firewall-action', 'ban', '203.0.113.9', '198.51.100.4', '0'],
    'Plesk firewall action did not use the fixed helper, socket peer address and default TTL');

$controller->request->post = ['csrf' => 'test-token', 'operation' => 'ban', 'network' => '203.0.113.10', 'ttl' => '3600'];
try { $controller->firewallAction(); } catch (ManagementRedirect $e) {}
checkManagement(pm_ApiCli::$calls[3][1] === ['firewall-action', 'ban', '203.0.113.10', '198.51.100.4', '3600'],
    'Firewall TTL was not passed through the fixed helper interface');

$controller->request->post = ['csrf' => 'test-token', 'operation' => 'port-allow',
    'network' => '203.0.113.25', 'port' => '2222', 'protocol' => 'tcp'];
try { $controller->firewallAction(); } catch (ManagementRedirect $e) {}
checkManagement(pm_ApiCli::$calls[4][1] === ['firewall-action', 'port-allow', '203.0.113.25',
    '198.51.100.4', '2222', 'tcp'], 'Port allow rule did not use the fixed helper interface');

$controller->request->post = ['csrf' => 'test-token', 'operation' => 'port-remove', 'rule_id' => '77'];
try { $controller->firewallAction(); } catch (ManagementRedirect $e) {}
checkManagement(pm_ApiCli::$calls[5][1] === ['firewall-action', 'port-remove', '77'],
    'Port rule removal did not pass only a numeric Guardian-owned rule identifier');

$controller->request->post = ['csrf' => 'test-token', 'operation' => 'allowlist-add',
    'network' => '203.0.113.50', 'comment' => 'Admin VPN'];
try { $controller->firewallAction(); } catch (ManagementRedirect $e) {}
checkManagement(pm_ApiCli::$calls[6][1] === ['firewall-action', 'allowlist-add', '203.0.113.50', 'Admin VPN'],
    'Guardian IP exception did not pass through the fixed helper interface');

$controller->request->post = ['csrf' => 'test-token', 'operation' => 'allowlist-remove', 'network' => '203.0.113.50'];
try { $controller->firewallAction(); } catch (ManagementRedirect $e) {}
checkManagement(pm_ApiCli::$calls[7][1] === ['firewall-action', 'allowlist-remove', '203.0.113.50'],
    'Guardian IP exception removal did not pass through the fixed helper interface');

$before = count(pm_ApiCli::$calls);
$controller->request->post = ['csrf' => 'test-token', 'operation' => 'port-deny',
    'network' => '203.0.113.25', 'port' => '70000', 'protocol' => 'tcp'];
try { $controller->firewallAction(); throw new RuntimeException('Invalid firewall port was accepted'); }
catch (pm_Exception $e) {}
checkManagement(count(pm_ApiCli::$calls) === $before, 'Invalid firewall port reached privileged helper');

$before = count(pm_ApiCli::$calls);
$controller->request->post = ['csrf' => 'test-token', 'operation' => 'ban', 'network' => '203.0.113.11', 'ttl' => '999'];
try { $controller->firewallAction(); throw new RuntimeException('Invalid firewall TTL was accepted'); }
catch (pm_Exception $e) {}
checkManagement(count(pm_ApiCli::$calls) === $before, 'Invalid firewall TTL reached privileged helper');

$before = count(pm_ApiCli::$calls);
$controller->request->post = ['csrf' => 'test-token', 'operation' => 'confirm'];
try { $controller->firewallAction(); throw new RuntimeException('Firewall change was confirmed without a connection test'); }
catch (pm_Exception $e) {}
checkManagement(count(pm_ApiCli::$calls) === $before, 'Firewall confirmation without a separate connection test reached helper');

$controller->request->post = ['csrf' => 'test-token', 'operation' => 'confirm', 'tested' => '1'];
try { $controller->firewallAction(); } catch (ManagementRedirect $e) {}
checkManagement(pm_ApiCli::$calls[8][1] === ['firewall-action', 'confirm'], 'Firewall confirmation action not routed correctly');

$controller->request->post = ['csrf' => 'test-token', 'operation' => 'debug-on'];
try { $controller->firewallAction(); } catch (ManagementRedirect $e) {}
checkManagement(pm_ApiCli::$calls[9][1] === ['firewall-debug-set', 'on'],
    'Firewall debug activation did not reach the fixed helper action');
$controller->request->post = ['csrf' => 'test-token', 'operation' => 'debug-off'];
try { $controller->firewallAction(); } catch (ManagementRedirect $e) {}
checkManagement(pm_ApiCli::$calls[10][1] === ['firewall-debug-set', 'off'],
    'Firewall debug deactivation did not reach the fixed helper action');

$controller->request->post = ['csrf' => 'test-token', 'operation' => 'baseline-delete',
    'baseline_id' => str_repeat('a', 32), 'domain' => 'example.com'];
try { $controller->manageAction(); } catch (ManagementRedirect $e) {}
$baselineCall = pm_ApiCli::$calls[count(pm_ApiCli::$calls) - 1];
$baselineRequest = json_decode($baselineCall[3], true);
checkManagement(($baselineRequest['action'] ?? '') === 'baseline-delete' &&
    $baselineRequest['baseline_id'] === str_repeat('a', 32) && $baselineRequest['domain'] === 'example.com',
    'Baseline deletion did not reach the fixed manager request');

$controller->request->post = ['csrf' => 'test-token', 'operation' => 'backup-delete', 'backup' => str_repeat('b', 32)];
try { $controller->manageAction(); } catch (ManagementRedirect $e) {}
$backupCall = pm_ApiCli::$calls[count(pm_ApiCli::$calls) - 1];
$backupRequest = json_decode($backupCall[3], true);
checkManagement(($backupRequest['action'] ?? '') === 'backup-delete' &&
    $backupRequest['backup'] === str_repeat('b', 32), 'Backup deletion did not reach the fixed manager request');

$controller->request->post = ['csrf' => 'test-token', 'operation' => 'global-ignore-add',
    'sha256' => str_repeat('d', 64)];
try { $controller->manageAction(); } catch (ManagementRedirect $e) {}
$globalIgnoreCall = pm_ApiCli::$calls[count(pm_ApiCli::$calls) - 1];
$globalIgnoreRequest = json_decode($globalIgnoreCall[3], true);
checkManagement(($globalIgnoreRequest['action'] ?? '') === 'global-ignore-add' &&
    $globalIgnoreRequest['sha256'] === str_repeat('d', 64), 'Global ignore action did not reach the fixed manager API');

$controller->request->post = ['csrf' => 'test-token', 'operation' => 'wp-db-scan', 'domain' => 'example.com'];
try { $controller->manageAction(); } catch (ManagementRedirect $e) {}
$wpDbScanCall = pm_ApiCli::$calls[count(pm_ApiCli::$calls) - 1];
$wpDbScanRequest = json_decode($wpDbScanCall[3], true);
checkManagement(($wpDbScanRequest['action'] ?? '') === 'wp-db-scan' &&
    $wpDbScanRequest['domain'] === 'example.com', 'WordPress DB scan did not reach the fixed manager request');

foreach ([['csrf' => 'wrong', 'operation' => 'cloud-save'],
          ['csrf' => 'test-token', 'operation' => 'shell'],
          ['csrf' => 'test-token', 'operation' => 'diagnostics', 'domain' => 'unknown.com'],
          ['csrf' => 'test-token', 'operation' => 'repair', 'index' => '-1']] as $post) {
    $before = count(pm_ApiCli::$calls);
    $controller->request->post = $post;
    try { $controller->manageAction(); throw new RuntimeException('Invalid request was accepted'); }
    catch (pm_Exception $e) {}
    checkManagement(count(pm_ApiCli::$calls) === $before, 'Invalid request reached privileged helper');
}
pm_Session::$impersonated = true;
try { $controller->init(); throw new RuntimeException('Impersonated admin accepted'); } catch (pm_Exception $e) {}
pm_Session::$impersonated = false;
pm_Session::$admin = false;
try { $controller->init(); throw new RuntimeException('Non-admin accepted'); } catch (pm_Exception $e) {}

class ManagementView extends stdClass {}
$view = new ManagementView();
$view->management = ['handlers' => [['version' => '8.3', 'sha256' => str_repeat('a', 64),
    'module' => true, 'managed' => false, 'build_missing' => ['phpize']]], 'cloud' => [],
    'ignore_hashes' => ['example.com' => [str_repeat('c', 64)]],
    'global_ignore_hashes' => [str_repeat('d', 64)],
    'backups' => [['kind' => 'php', 'identity' => '8.3', 'id' => str_repeat('b', 32), 'created_at' => 'test'],
                  ['kind' => 'waf', 'id' => str_repeat('c', 32), 'created_at' => 'test']],
    'waf_sha256' => str_repeat('d', 64), 'waf' => [],
    'crs' => ['active_version' => '', 'active_sha256' => '', 'managed' => false,
        'staged' => [['version' => '4.30.0', 'archive_sha256' => str_repeat('c', 64), 'files' => 42,
            'staged_at' => '2026-11-05T00:00:00Z']]],
    'storage' => ['areas' => ['backups' => ['bytes' => 1, 'files' => 2], 'baselines' => ['bytes' => 3, 'files' => 1],
        'repair-journals' => ['bytes' => 0, 'files' => 0], 'jobs' => ['bytes' => 4, 'files' => 3]],
        'managed_bytes' => 8, 'baseline_quota_bytes' => 536870912, 'backup_quota_bytes' => 268435456,
        'disk' => ['free_bytes' => 1000]],
    'baseline_inventory' => [['id' => str_repeat('d', 32), 'domain' => 'example.com', 'created_at' => 'test',
        'files' => 1, 'bytes' => 3, 'incomplete' => false, 'active' => true, 'autorepair' => false]]];
$view->managementError = '';
$view->managementResult = [];
$view->domains = ['example.com'];
$view->csrf = 'test-token';
$view->overview = ['firewall' => ['debug_enabled' => false, 'debug_log_bytes' => 0,
    'debug_log_limit_bytes' => 262144, 'debug_events' => []]];
$view->scan = ['id' => str_repeat('e', 32), 'domain' => 'example.com', 'findings' => [
    ['path' => '<script>test</script>.php', 'state' => 'found', 'fingerprint' => ['sha256' => str_repeat('f', 64)]],
    ['path' => 'global-cache.php', 'state' => 'found', 'ignore_scope' => 'global', 'ignored' => true,
        'fingerprint' => ['sha256' => str_repeat('d', 64)]],
    ['path' => 'index.php', 'state' => 'repaired']]];
$render = function () {
    $esc = static function ($value) { return htmlspecialchars((string)$value, ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8'); };
    $fw = $this->overview['firewall'] ?? [];
    ob_start();
    include dirname(__DIR__) . '/plib/views/scripts/index/management.phtml';
    return ob_get_clean();
};
$html = $render->call($view);
checkManagement(strpos($html, 'guardian-management') !== false, 'Management partial did not render');
checkManagement(strpos($html, 'Guardian-Moduldiagnose') !== false, 'Management tab lacks module-wide debug controls');
checkManagement(strpos($html, 'Guardian-Debugging einschalten') !== false, 'Management tab lacks global debug toggle');
checkManagement(strpos($html, 'Keine Guardian-Regel konfiguriert') !== false, 'WAF state is not human readable');
checkManagement(strpos($html, 'Aktuell: []') === false, 'WAF state leaks raw empty JSON');
checkManagement(strpos($html, 'OWASP Core Rule Set') !== false, 'Management tab lacks OWASP CRS controls');
checkManagement(strpos($html, 'crs-activate') !== false, 'Management tab lacks staged CRS activation');
checkManagement(strpos($html, 'name="operation" value="debug-on"') !== false, 'Management debug toggle uses wrong operation');
checkManagement(strpos($html, 'name="csrf"') !== false, 'Management forms lack CSRF');
checkManagement(strpos($html, '<script>test</script>') === false, 'Finding path was not escaped');
checkManagement(strpos($html, 'ignore-add') !== false, 'Malware ignore action not rendered');
checkManagement(strpos($html, 'ignore-remove') !== false, 'Malware ignore removal not rendered');
checkManagement(strpos($html, 'global-ignore-add') !== false, 'Global malware ignore action not rendered');
checkManagement(strpos($html, 'global-ignore-remove') !== false, 'Global malware ignore removal not rendered');
checkManagement(strpos($html, 'Global ignoriert') !== false, 'Global ignore scope is not visible');
checkManagement(strpos($html, 'Speicher und Wiederherstellungspunkte') !== false, 'Storage overview not rendered');
checkManagement(strpos($html, 'backup-delete') !== false, 'Backup retention action not rendered');
$beforeRetryCsrf = count(pm_ApiCli::$calls);
$controller->request->post = ['csrf' => 'wrong-token'];
try { $controller->alertsRetryAction(); throw new RuntimeException('Alert retry accepted invalid CSRF'); }
catch (pm_Exception $e) {}
checkManagement(count(pm_ApiCli::$calls) === $beforeRetryCsrf, 'Alert retry with invalid CSRF reached privileged helper');
$controller->request->post = ['csrf' => 'test-token'];
try { $controller->alertsRetryAction(); } catch (ManagementRedirect $e) {}
$retryCall = pm_ApiCli::$calls[count(pm_ApiCli::$calls) - 1];
checkManagement($retryCall[0] === 'guardian-helper' && $retryCall[1] === ['alerts-retry'],
    'Alert retry did not reach the fixed helper action');
echo "Management controller and template smoke: OK\n";
