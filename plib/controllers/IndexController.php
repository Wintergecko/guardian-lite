<?php
/** Guardian Lite: Plesk administrator-only actions with CSRF checks. */
class IndexController extends pm_Controller_Action
{
    protected $_accessLevel = 'admin';
    private const GUARDIAN_VERSION = '0.6.4';
    private const LAST_MALWARE_ACTION_KEY = 'guardian_malware_last_action_v1';
    private const DEFAULT_UPDATE_REPO = 'Wintergecko/guardian-lite';
    private const LAST_UPDATE_KEY = 'guardian_update_last_check_v1';

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
            if ($domain->getName() === $name && $domain->hasHosting()) {
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

    private function updateRepository()
    {
        $saved = trim((string)pm_Settings::get('guardian_update_repo'));
        return $saved !== '' ? $saved : self::DEFAULT_UPDATE_REPO;
    }

    // Keep the last check visible after Plesk redirects or a PHP session renewal.
    // No access tokens are stored: these are public GitHub release metadata only.
    private function getLastUpdateCheck()
    {
        $raw = (string)pm_Settings::get(self::LAST_UPDATE_KEY);
        if ($raw === '' || strlen($raw) > 4096) {
            return [];
        }
        $record = json_decode($raw, true);
        return is_array($record) && isset($record['checked_at']) && is_int($record['checked_at'])
            ? $record : [];
    }

    private function storeUpdateCheck($repo, $status, $result = null, $error = '')
    {
        $record = [
            'repo' => $repo,
            'checked_at' => time(),
            'status' => $status,
            'result' => is_array($result) ? $result : null,
            'error' => substr((string)$error, 0, 300),
        ];
        $data = json_encode($record, JSON_UNESCAPED_SLASHES | JSON_INVALID_UTF8_SUBSTITUTE);
        if (!is_string($data) || strlen($data) > 4096) {
            throw new pm_Exception('Updater-Pruefergebnis konnte nicht gespeichert werden.');
        }
        pm_Settings::set(self::LAST_UPDATE_KEY, $data);
    }

    private function redirectToUpdates()
    {
        $this->redirect(pm_Context::getBaseUrl() . '#guardian-tab-updates');
    }

    public function updateRepoAction()
    {
        $this->verifyPost();
        $repo = trim((string)$this->getRequest()->getPost('repo', ''));
        // Accept a GitHub repository URL as well as owner/repo. Never accept arbitrary hosts.
        if (preg_match('~^https://github\\.com/~i', $repo)) {
            $parts = parse_url($repo);
            if (!is_array($parts) || strcasecmp((string)($parts['host'] ?? ''), 'github.com') !== 0
                || isset($parts['user']) || isset($parts['pass']) || isset($parts['port'])
                || isset($parts['query']) || isset($parts['fragment'])) {
                throw new pm_Exception('Bitte eine reine GitHub-Repository-URL ohne Parameter verwenden.');
            }
            $repo = trim((string)($parts['path'] ?? ''), '/');
            if (substr($repo, -4) === '.git') {
                $repo = substr($repo, 0, -4);
            }
        }
        if ($repo === '' || !preg_match('~^[A-Za-z0-9][A-Za-z0-9-]{0,38}/[A-Za-z0-9_.-]{1,100}$~D', $repo)
            || strpos($repo, '..') !== false || strpos($repo, '/.') !== false
            || substr($repo, -1) === '.') {
            throw new pm_Exception('Bitte Wintergecko/guardian-lite oder https://github.com/Wintergecko/guardian-lite eingeben.');
        }
        pm_Settings::set('guardian_update_repo', $repo);
        if ((string)pm_Settings::get('guardian_update_repo') !== $repo) {
            throw new pm_Exception('Updater-Repository konnte nicht gespeichert werden. Bitte Plesk-Protokoll pruefen.');
        }
        pm_Settings::set(self::LAST_UPDATE_KEY, '');
        $this->_status->addMessage('info', 'GitHub-Repository fuer Updates gespeichert.');
        $this->redirectToUpdates();
    }

    public function updateCheckAction()
    {
        $this->verifyPost();
        $repo = $this->updateRepository();
        try {
            $result = $this->updater(['check', $repo, self::GUARDIAN_VERSION]);
            $this->storeUpdateCheck($repo, 'checked', $result);
        } catch (\Throwable $e) {
            // Show the actual network, GitHub or helper error in the Updates tab.
            $this->storeUpdateCheck($repo, 'error', null, $e->getMessage());
        }
        $this->redirectToUpdates();
    }

    public function updateApplyAction()
    {
        $this->verifyPost();
        $repo = $this->updateRepository();
        $check = $this->getLastUpdateCheck();
        $result = isset($check['result']) ? $check['result'] : null;
        // Re-check the release before applying; stale checks cannot trigger an update.
        if (($check['status'] ?? '') !== 'checked' || ($check['repo'] ?? '') !== $repo
            || time() - (int)($check['checked_at'] ?? 0) > 1800
            || !is_array($result) || empty($result['newer']) || $repo !== ($result['repo'] ?? '')
            || !preg_match('/^\d+\.\d+\.\d+$/D', (string)($result['latest'] ?? ''))
            || !preg_match('/^[a-f0-9]{64}$/D', (string)($result['sha256'] ?? ''))) {
            throw new pm_Exception('Zuerst erneut nach Updates suchen (Pruefung maximal 30 Minuten alt).');
        }
        try {
            $this->updater(['apply', $repo, self::GUARDIAN_VERSION,
                (string)$result['latest'], (string)$result['sha256']]);
            $this->storeUpdateCheck($repo, 'installing');
        } catch (\Throwable $e) {
            $this->storeUpdateCheck($repo, 'error', null, 'Update konnte nicht gestartet werden: ' . $e->getMessage());
        }
        $this->redirectToUpdates();
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
        $this->view->malwareAction = null;
        $lastAction = json_decode((string)pm_Settings::get(self::LAST_MALWARE_ACTION_KEY), true);
        if (is_array($lastAction) && isset($lastAction['at']) && is_numeric($lastAction['at'])
            && time() - (int)$lastAction['at'] < 86400) {
            $this->view->malwareAction = $lastAction;
        }
        $this->view->watch = [];
        $this->view->realtime = [];
        $this->view->incidents = [];
        $this->view->alerts = ['enabled' => false, 'recipient' => ''];
        $this->view->waf = [];
        $this->view->wafError = null;
        $this->view->domains = [];
        $this->view->scanSelectedDomain = '';
        $this->view->updateRepo = $this->updateRepository();
        $this->view->updateResult = null;
        $this->view->updateCheckAt = null;
        $this->view->updateCheckStatus = '';
        $this->view->updateCheckError = '';
        $lastCheck = $this->getLastUpdateCheck();
        if (($lastCheck['repo'] ?? '') === $this->view->updateRepo
            && time() - (int)$lastCheck['checked_at'] < 86400) {
            $this->view->updateCheckAt = (int)$lastCheck['checked_at'];
            $this->view->updateCheckStatus = (string)($lastCheck['status'] ?? '');
            $this->view->updateCheckError = (string)($lastCheck['error'] ?? '');
            $this->view->updateResult = isset($lastCheck['result']) && is_array($lastCheck['result'])
                ? $lastCheck['result'] : null;
        }
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
            $this->view->realtime = isset($status['realtime']) ? $status['realtime'] : [];
            $this->view->incidents = isset($status['incidents']) ? $status['incidents'] : [];
            $this->view->alerts = isset($status['alerts']) ? $status['alerts'] : ['enabled' => false, 'recipient' => ''];
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
                if (!$domain->hasHosting()) {
                    continue;
                }
                $name = $domain->getName();
                if (is_string($name) && strlen($name) <= 253 &&
                    preg_match('/^[a-z0-9](?:[a-z0-9-]*[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]*[a-z0-9])?)+$/i', $name)) {
                    $this->view->domains[] = $name;
                }
            }
            $this->view->domains = array_values(array_unique($this->view->domains));
            sort($this->view->domains, SORT_NATURAL | SORT_FLAG_CASE);
            $remembered = (string)pm_Settings::get('guardian_scan_selected_domain');
            $this->view->scanSelectedDomain = in_array($remembered, $this->view->domains, true) ? $remembered : '';
        } catch (Exception $e) {
            $this->view->helperError = 'Domainliste konnte nicht gelesen werden: ' . $e->getMessage();
        }
    }

    // Persist the most recent scan/schedule result because Plesk may not show
    // global status messages after a redirect into a JavaScript tab.
    private function storeMalwareAction($operation, $domain, $ok, $message)
    {
        $record = [
            'operation' => $operation,
            'domain' => $domain,
            'ok' => (bool)$ok,
            'message' => substr((string)$message, 0, 240),
            'at' => time(),
        ];
        pm_Settings::set(self::LAST_MALWARE_ACTION_KEY,
            json_encode($record, JSON_UNESCAPED_UNICODE | JSON_INVALID_UTF8_SUBSTITUTE));
    }

    private function redirectToMalware()
    {
        $this->redirect(pm_Context::getBaseUrl() . '#guardian-tab-malware');
    }

    private function finishMalwareAction($operation, $domain, $args, $message)
    {
        try {
            $result = $this->helper($args);
            if ($operation === 'schedule') {
                // Do not claim success if the helper acknowledged a different domain/state.
                $expected = $args[2] === 'on';
                if (($result['domain'] ?? '') !== $domain
                    || !isset($result['enabled']) || (bool)$result['enabled'] !== $expected) {
                    throw new RuntimeException('Scan-Planung konnte nicht bestaetigt werden.');
                }
            }
            $this->storeMalwareAction($operation, $domain, true, $message);
            $this->_status->addMessage('info', $message);
        } catch (Exception $e) {
            $error = $e->getMessage();
            $this->storeMalwareAction($operation, $domain, false, $error);
            $this->_status->addMessage('error', $error);
        }
        $this->redirectToMalware();
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
        pm_Settings::set('guardian_scan_selected_domain', $domain);
        $this->finishMalwareAction('scan', $domain, ['scan-start', $domain], 'Malware-Scan fuer ' . $domain . ' gestartet.');
    }

    public function scheduleAction()
    {
        $this->verifyPost();
        $domain = (string)$this->getRequest()->getPost('domain', '');
        $mode = (string)$this->getRequest()->getPost('mode', '');
        if (!$this->isDomainKnown($domain) || !in_array($mode, ['on', 'off'], true)) {
            throw new pm_Exception('Ungueltige Scan-Planung.');
        }
        pm_Settings::set('guardian_scan_selected_domain', $domain);
        $this->finishMalwareAction('schedule', $domain, ['schedule-set', $domain, $mode], 'Scan-Planung fuer ' . $domain . ' ' . ($mode === 'on' ? 'aktiviert.' : 'deaktiviert.'));
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

    public function monitorAction()
    {
        $this->verifyPost();
        $domain = (string)$this->getRequest()->getPost('domain', '');
        $mode = (string)$this->getRequest()->getPost('mode', '');
        if (!$this->isDomainKnown($domain) || !in_array($mode, ['on', 'off'], true)) {
            throw new pm_Exception('Ungueltige Echtzeit-Ueberwachungseinstellung.');
        }
        $this->finishAction(['monitor-set', $domain, $mode], 'Echtzeit-Ueberwachung aktualisiert.');
    }

    public function alertsAction()
    {
        $this->verifyPost();
        $mode = (string)$this->getRequest()->getPost('mode', '');
        $recipient = trim((string)$this->getRequest()->getPost('recipient', ''));
        if (!in_array($mode, ['on', 'off'], true) || strlen($recipient) > 254 ||
            preg_match('/[\r\n]/', $recipient)) {
            throw new pm_Exception('Ungueltige Benachrichtigungseinstellung.');
        }
        $this->finishAction(['alerts-set', $recipient, $mode], 'E-Mail-Einstellungen aktualisiert.');
    }

    public function alertsTestAction()
    {
        $this->verifyPost();
        $this->finishAction(['alerts-test'], 'Testmail an den lokalen Mail-Transport uebergeben.');
    }

    public function incidentsExportAction()
    {
        // Admin-only GET; export contains only sanitized incident metadata.
        $data = $this->helper(['incidents']);
        $items = isset($data['incidents']) && is_array($data['incidents']) ? $data['incidents'] : [];
        $body = json_encode(['exported_at' => gmdate('c'), 'incidents' => $items],
                            JSON_UNESCAPED_UNICODE | JSON_PRETTY_PRINT | JSON_INVALID_UTF8_SUBSTITUTE);
        if ($body === false || strlen($body) > 120000) {
            throw new pm_Exception('Export ist zu gross.');
        }
        $this->_helper->viewRenderer->setNoRender();
        $this->_helper->layout->disableLayout();
        $response = $this->getResponse();
        $response->setHeader('Content-Type', 'application/json; charset=UTF-8', true);
        $response->setHeader('Content-Disposition', 'attachment; filename="guardian-incidents.json"', true);
        $response->setHeader('Cache-Control', 'no-store', true);
        $response->setBody($body);
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
