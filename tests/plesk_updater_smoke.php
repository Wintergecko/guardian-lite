<?php
error_reporting(E_ALL);
class RedirectProbe extends RuntimeException {}
class FakeRequest {
    private $post;
    public function __construct($post=[]) { $this->post=$post; }
    public function isPost() { return true; }
    public function getPost($key, $default='') { return $this->post[$key] ?? $default; }
    public function getQuery($key, $default='') { return $default; }
}
class FakeStatus { public function addMessage($type,$message) {} }
class pm_Controller_Action {
    protected $_status;
    public $view;
    private $req;
    public function __construct() { $this->view=new stdClass(); $this->_status=new FakeStatus(); }
    public function init() {}
    public function setRequest($req) { $this->req=$req; }
    public function getRequest() { return $this->req; }
    public function redirect($url) { throw new RedirectProbe($url); }
}
class pm_Context {
    public static function getBaseUrl() { return '/modules/guardian-lite/index.php/'; }
}
class pm_Settings {
    public static $data=[];
    public static function get($key) { return self::$data[$key] ?? ''; }
    public static function set($key,$value) { self::$data[$key]=$value; }
}
class pm_ApiCli {
    const RESULT_FULL=1;
    public static $fail=false;
    public static function callSbin($name,$args,$flag) {
        if ($name==='guardian-updater' && $args[0]==='check') {
            if (self::$fail) return ['code'=>1,'stdout'=>json_encode(['ok'=>false,'error'=>'Simulierter GitHub-Fehler'])];
            return ['code'=>0,'stdout'=>json_encode(['ok'=>true,'repo'=>$args[1],'current'=>$args[2],
                'latest'=>'0.6.2','newer'=>true,'sha256'=>str_repeat('a',64),
                'asset'=>'guardian-lite-0.6.2.zip'])];
        }
        return ['code'=>0,'stdout'=>json_encode(['ok'=>true,'state'=>[]])];
    }
    public static function call($name,$args,$flag) { return ['code'=>0,'stdout'=>'','stderr'=>'']; }
}
class pm_Domain { public static function getAllDomains() { return []; } }
class pm_Exception extends RuntimeException {}
class pm_Session {
    public static function getClient() { return new class { public function isAdmin() { return true; } }; }
    public static function isImpersonated() { return false; }
}
require dirname(__DIR__) . '/plib/controllers/IndexController.php';
function check($ok,$why) { if (!$ok) throw new RuntimeException($why); }
function runCheck() {
    $_SESSION['guardian_lite_csrf']='local-test';
    $controller=new IndexController();
    $controller->setRequest(new FakeRequest(['csrf'=>'local-test']));
    try { $controller->updateCheckAction(); } catch (RedirectProbe $e) {
        check(strpos($e->getMessage(),'#guardian-tab-updates')!==false,'Update tab was lost');
        return;
    }
    throw new RuntimeException('No redirect');
}
$_SESSION=[];
runCheck();
$state=json_decode(pm_Settings::get('guardian_update_last_check_v1'),true);
check($state['status']==='checked','Successful check is missing');
check($state['result']['latest']==='0.6.2','Latest release not saved');
$_SESSION=[];
$c=new IndexController();
$c->setRequest(new FakeRequest());
$c->indexAction();
check($c->view->updateResult['latest']==='0.6.2','Status lost after redirect/session reset');
pm_ApiCli::$fail=true;
runCheck();
$state=json_decode(pm_Settings::get('guardian_update_last_check_v1'),true);
check($state['status']==='error' && strpos($state['error'],'GitHub-Fehler')!==false,'Errors are not preserved');
echo "Plesk updater UI smoke: OK\n";
