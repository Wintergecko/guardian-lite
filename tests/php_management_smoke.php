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
class pm_Controller_Action {
    public $request;
    public $view;
    public function __construct() { $this->request = new ManagementRequest(); $this->view = new stdClass(); }
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
$view->management = ['handlers' => [], 'cloud' => [], 'backups' => []];
$view->managementError = '';
$view->managementResult = [];
$view->domains = ['example.com'];
$view->csrf = 'test-token';
$view->scan = null;
$render = function () {
    $esc = static function ($value) { return htmlspecialchars((string)$value, ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8'); };
    ob_start();
    include dirname(__DIR__) . '/plib/views/scripts/index/management.phtml';
    return ob_get_clean();
};
$html = $render->call($view);
checkManagement(strpos($html, 'guardian-management') !== false, 'Management partial did not render');
checkManagement(strpos($html, 'name="csrf"') !== false, 'Management forms lack CSRF');
echo "Management controller and template smoke: OK\n";
