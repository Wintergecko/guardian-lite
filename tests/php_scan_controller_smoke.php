<?php
/** PHPUnit-free smoke test for Guardian Lite scan scheduler controller. No Plesk required. */
error_reporting(E_ALL);
if (getenv('GITHUB_ACTIONS') === 'true') {
    set_exception_handler(static function (Throwable $error) {
        fwrite(STDERR, '::error::' . str_replace(["\r", "\n"], ' ', (string)$error) . "\n");
        exit(1);
    });
}

class pm_Exception extends Exception {}
class RedirectForTest extends Exception {}
class pm_Context {
    public static function getBaseUrl() { return '/modules/guardian-lite/index.php/'; }
    public static function getActionUrl($controller, $action = 'index') {
        return self::getBaseUrl() . $controller . '/' . $action;
    }
}
class pm_Settings {
    public static $values = [];
    public static function get($key) { return self::$values[$key] ?? ''; }
    public static function set($key, $val) { self::$values[$key] = $val; }
}
class pm_DomainItem {
    public function getName() { return 'example.com'; }
    public function hasHosting() { return true; }
}
class pm_Domain {
    public static function getAllDomains() { return [new pm_DomainItem()]; }
}
class pm_ApiCli {
    const RESULT_FULL = 1;
    public static $fail = false;
    public static $lastArgs = null;
    public static function callSbin($cmd, $args, $mode) {
        self::$lastArgs = $args;
        if ($cmd !== 'guardian-helper' || $args[0] !== 'schedule-set') {
            return ['code' => 1, 'stdout' => '{"ok":false,"error":"Unknown action"}'];
        }
        if (self::$fail) {
            return ['code' => 1, 'stdout' => '{"ok":false,"error":"Berechtigung verweigert"}'];
        }
        return ['code' => 0, 'stdout' => json_encode([
            'ok' => true, 'domain' => $args[1], 'enabled' => $args[2] === 'on',
        ])];
    }
}
class FakeRequest {
    public $post = [];
    public function isPost() { return true; }
    public function getPost($key, $fallback = null) { return $this->post[$key] ?? $fallback; }
}
class FakeStatus {
    public $messages = [];
    public function addMessage($type, $message) { $this->messages[] = [$type, $message]; }
}
class pm_Controller_Action {
    protected $_status;
    public $request;
    public $lastRedirect = '';
    public function __construct() { $this->_status = new FakeStatus(); $this->request = new FakeRequest(); }
    public function getRequest() { return $this->request; }
    public function redirect($url) { $this->lastRedirect = $url; throw new RedirectForTest($url); }
}
require __DIR__ . '/../plib/controllers/IndexController.php';

function check($expression, $message) {
    if (!$expression) { throw new RuntimeException($message); }
}

$_SESSION['guardian_lite_csrf'] = str_repeat('a', 64);
$controller = new IndexController();
$controller->request->post = ['csrf' => str_repeat('a', 64), 'domain' => 'example.com', 'mode' => 'on'];
try { $controller->scheduleAction(); } catch (RedirectForTest $e) {}
check(pm_ApiCli::$lastArgs === ['schedule-set', 'example.com', 'on'], 'schedule-set was not called');
check($controller->lastRedirect === pm_Context::getBaseUrl() . '#guardian-tab-malware', 'wrong redirect');
$record = json_decode(pm_Settings::get('guardian_malware_last_action_v1'), true);
check(is_array($record) && $record['ok'] === true && $record['domain'] === 'example.com', 'success not persisted');

$controller = new IndexController();
pm_ApiCli::$fail = true;
$controller->request->post = ['csrf' => str_repeat('a', 64), 'domain' => 'example.com', 'mode' => 'off'];
try { $controller->scheduleAction(); } catch (RedirectForTest $e) {}
$record = json_decode(pm_Settings::get('guardian_malware_last_action_v1'), true);
check(is_array($record) && $record['ok'] === false, 'failure not persisted');
check(strpos($record['message'], 'Berechtigung verweigert') !== false, 'failure reason hidden');
check($controller->lastRedirect === pm_Context::getBaseUrl() . '#guardian-tab-malware', 'failure redirect wrong');

echo "PHP scan controller smoke: success and helper failure passed\n";
