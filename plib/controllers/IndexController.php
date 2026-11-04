<?php
/** Guardian Lite: Plesk administrator-only actions with CSRF checks. */
class IndexController extends pm_Controller_Action
{
    protected $_accessLevel = 'admin';
    private const GUARDIAN_VERSION = '0.4.0';

    public function init()
    {
        parent::init();
        if (!pm_Session::getClient()->isAdmin() || pm_Session::isImpersonated()) {
            throw new pm_Exception('Nur direkte Plesk-Administrator-Sitzungen sind erlaubt.');
        }
        $this->view->pageTitle = 'Guardian Lite | Sicherheitszentrale';
    }

    private function csrfToken()
    {
        if (!isset($_SESSION['guardian_lite_csrf']) || !is_string($_SESSION['guardian_lite_csrf'])) {
            $_SESSION['guardian_lite_csrf'] = bin2hex(random_bytes(32));
        }
        return $_SESSION['guardian_lite_csrf'];
    }

    private function verifyPost()
    {
        if (!$this->getRequest()->isPost()) {
            throw new pm_Exception('POST erforderlich.');
        }
        $token = (string)$this->getRequest()->getPost('csrf', '');
        if (!hash_equals($this->csrfToken(), $token)) {
            throw new pm_Exception('CSRF-Token ungueltig. Seite erneut laden.');
        }
    }

    private function isDomainKnown($name)
    {
        foreach (pm_Domain::getAllDomains() as $domain) {
            if ($domain->getName() === $name) {
                return true;
            }
        }
        return false;
    }

    private function helper(array $args)
    {
        $result = pm_ApiCli::callSbin('guardian-helper', $args, pm_ApiCli::RESULT_FULL);
        $data = json_decode(isset($result['stdout']) ? $result['stdout'] : '', true);
        if (!is_array($data)) {
            throw new RuntimeException('Ungueltige Antwort des Guardian-Helfers.');
        }
        if (!empty($result['code']) || empty($data['ok'])) {
            throw new RuntimeException(isset($data['error']) ? $data['error'] : 'Guardian-Helfer konnte den Auftrag nicht ausfuehren.');
        }
        return $data;
    }

    private function updater(array $args)
    {
        $result = pm_ApiCli::callSbin('guardian-updater', $args, pm_ApiCli::RESULT_FULL);
        $data = json_decode(isset($result['stdout']) ? $result['stdout'] : '', true);
        if (!is_array($data) || !empty($result['code']) || empty($data['ok'])) {
            throw new RuntimeException(is_array($data) && !empty($data['error'])
                ? (string)$data['error'] : 'Guardian-Updater nicht erreichbar.');
        }
        return $data;
    }

    public function updateRepoAction()
    {
        $this->verifyPost();
        $repo = trim((string)$this->getRequest()->getPost('repo', ''));
        if ($repo !== '' && (!preg_match('/^[A-Za-z0-9][A-Za-z0-9-]{0,38}\/[A-Za-z0-9_.-]{1,100}$/D', $repo)
            || strpos($repo, '..') !== false || strpos($repo, '/.') !== false)) {
            throw new pm_Exception('Repository bitte im Format owner/repo angeben.');
        }
        pm_Settings::set('guardian_update_repo', $repo);
        unset($_SESSION['guardian_update_result']);
        $this->_status->addMessage('info', 'GitHub-Repository fuer Updates gespeichert.');
        $this->redirect(pm_Context::getBaseUrl());
    }

    public function updateCheckAction()
    {
        $this->verifyPost();
        $repo = (string)pm_Settings::get('guardian_update_repo');
        if ($repo === '') {
            throw new pm_Exception('Zuerst ein GitHub-Repository festlegen.');
        }
        unset($_SESSION['guardian_update_result']);
        try {
            $_SESSION['guardian_update_result'] = $this->updater(['check', $repo, self::GUARDIAN_VERSION]);
            $this->_status->addMessage('info', 'GitHub-Release geprueft.');
        } catch (Exception $e) {
            $this->_status->addMessage('error', $e->getMessage());
        }
        $this->redirect(pm_Context::getBaseUrl());
    }

    public function updateApplyAction()
    {
        $this->verifyPost();
        $repo = (string)pm_Settings::get('guardian_update_repo');
        $result = isset($_SESSION['guardian_update_result']) ? $_SESSION['guardian_update_result'] : null;
        if (!is_array($result) || empty($result['newer']) || $repo !== ($result['repo'] ?? '')
            || !preg_match('/^\d+\.\d+\.\d+$/D', (string)($result['latest'] ?? ''))
            || !preg_match('/^[a-f0-9]{64}$/D', (string)($result['sha256'] ?? ''))) {
            throw new pm_Exception('Zuerst erneut nach Updates suchen.');
        }
        try {
            $this->updater(['apply', $repo, self::GUARDIAN_VERSION,
                (string)$result['latest'], (string)$result['sha256']]);
            unset($_SESSION['guardian_update_result']);
            $this->_status->addMessage('info', 'Plesk-Upgrade wurde gestartet. Status im Updater pruefen.');
        } catch (Exception $e) {
            $this->_status->addMessage('error', $e->getMessage());
        }
        $this->redirect(pm_Context::getBaseUrl());
    }

    public function indexAction()
    {
        $this->view->csrf = $this->csrfToken();
        $this->view->baseUrl = pm_Context::getBaseUrl();
        $this->view->helperError = null;
        $this->view->overview = [];
        $this->view->scan = null;
        $this->view->history = [];
        $this->view->schedules = [];
        $this->view->watch = [];
        $this->view->waf = [];
        $this->view->wafError = null;
        $this->view->domains = [];
        $this->view->updateRepo = (string)pm_Settings::get('guardian_update_repo');
        $this->view->updateResult = isset($_SESSION['guardian_update_result'])
            ? $_SESSION['guardian_update_result'] : null;
        $this->view->updateState = [];
        $this->view->updateError = null;
        try {
            $updateStatus = $this->updater(['status']);
            $this->view->updateState = isset($updateStatus['state']) ? $updateStatus['state'] : [];
        } catch (Exception $e) {
            $this->view->updateError = $e->getMessage();
        }

        try {
            $status = $this->helper(['status']);
            $this->view->overview = isset($status['services']) ? $status['services'] : [];
            $this->view->scan = isset($status['scan']) ? $status['scan'] : null;
            $this->view->history = isset($status['history']) ? $status['history'] : [];
            $this->view->schedules = isset($status['schedules']) ? $status['schedules'] : [];
            $this->view->watch = isset($status['watch']) ? $status['watch'] : [];
            $reportId = (string)$this->getRequest()->getQuery('report', '');
            if (preg_match('/^[a-f0-9]{32}$/', $reportId)) {
                $report = $this->helper(['report', $reportId]);
                $this->view->scan = isset($report['report']) ? $report['report'] : null;
            }
        } catch (Exception $e) {
            $this->view->helperError = $e->getMessage();
        }
        try {
            $result = pm_ApiCli::call('server_pref', ['--show-web-app-firewall'], pm_ApiCli::RESULT_FULL);
            if (!empty($result['code'])) {
                throw new RuntimeException(trim((string)$result['stderr']));
            }
            $output = trim((string)$result['stdout']);
            $this->view->waf = ['detail' => $output, 'mode' => 'unknown'];
            if (preg_match('/(?:waf[-_ ]rule[-_ ]engine|rule[-_ ]engine)\s*[:=]\s*(on|off|detectiononly)/i', $output, $m)) {
                $this->view->waf['mode'] = strtolower($m[1]);
            }
        } catch (Exception $e) {
            $this->view->wafError = $e->getMessage();
        }
        try {
            foreach (pm_Domain::getAllDomains() as $domain) {
                $name = $domain->getName();
                if (is_string($name) && strlen($name) <= 253 &&
                    preg_match('/^[a-z0-9](?:[a-z0-9-]*[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]*[a-z0-9])?)+$/i', $name)) {
                    $this->view->domains[] = $name;
                }
            }
            $this->view->domains = array_values(array_unique($this->view->domains));
            sort($this->view->domains, SORT_NATURAL | SORT_FLAG_CASE);
        } catch (Exception $e) {
            $this->view->helperError = 'Domainliste konnte nicht gelesen werden: ' . $e->getMessage();
        }
    }

    private function finishAction($args, $message)
    {
        try {
            $this->helper($args);
            $this->_status->addMessage('info', $message);
        } catch (Exception $e) {
            $this->_status->addMessage('error', $e->getMessage());
        }
        $this->redirect(pm_Context::getBaseUrl());
    }

    public function scanAction()
    {
        $this->verifyPost();
        $domain = (string)$this->getRequest()->getPost('domain', '');
        if (!$this->isDomainKnown($domain)) {
            throw new pm_Exception('Unbekannte Domain.');
        }
        $this->finishAction(['scan-start', $domain], 'Malware-Scan fuer ' . $domain . ' gestartet.');
    }

    public function scheduleAction()
    {
        $this->verifyPost();
        $domain = (string)$this->getRequest()->getPost('domain', '');
        $mode = (string)$this->getRequest()->getPost('mode', '');
        if (!$this->isDomainKnown($domain) || !in_array($mode, ['on', 'off'], true)) {
            throw new pm_Exception('Ungueltige Scan-Planung.');
        }
        $this->finishAction(['schedule-set', $domain, $mode], 'Scan-Planung aktualisiert.');
    }

    public function quarantineAction()
    {
        $this->verifyPost();
        $this->findingAction('quarantine', 'Datei wurde in die Quarantaene verschoben.');
    }

    public function restoreAction()
    {
        $this->verifyPost();
        $this->findingAction('restore', 'Datei wiederhergestellt. Achtung: moeglicherweise infiziert!');
    }

    private function findingAction($command, $message)
    {
        $jobid = (string)$this->getRequest()->getPost('jobid', '');
        $index = (string)$this->getRequest()->getPost('index', '');
        if (!preg_match('/^[a-f0-9]{32}$/', $jobid) || !preg_match('/^\d{1,3}$/', $index)) {
            throw new pm_Exception('Ungueltiger Scan-Fund.');
        }
        $this->finishAction([$command, $jobid, $index], $message);
    }

    public function ipAction()
    {
        $this->verifyPost();
        $jail = (string)$this->getRequest()->getPost('jail', '');
        $ip = (string)$this->getRequest()->getPost('ip', '');
        $operation = (string)$this->getRequest()->getPost('operation', '');
        if (!preg_match('/^[A-Za-z0-9_.-]{1,80}$/', $jail) ||
            !filter_var($ip, FILTER_VALIDATE_IP) || !in_array($operation, ['ban', 'unban'], true)) {
            throw new pm_Exception('Ungueltige IP-Sperraktion.');
        }
        $this->finishAction(['ip-action', $jail, $ip, $operation], 'Fail2Ban-IP-Aktion bearbeitet.');
    }
}
