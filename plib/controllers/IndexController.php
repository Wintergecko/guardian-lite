<?php
/** Guardian Lite: Plesk administrator-only actions with CSRF checks. */
class IndexController extends pm_Controller_Action
{
    protected $_accessLevel = 'admin';
    private const GUARDIAN_VERSION = '0.28.18';
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
        $started = microtime(true);
        $debugStage = isset($args[0]) && in_array($args[0], ['check', 'apply'], true)
            ? ($args[0] === 'check' ? 'check' : 'install') : '';
        try {
            $result = pm_ApiCli::callSbin('guardian-updater', $args, pm_ApiCli::RESULT_FULL);
        } catch (\Throwable $e) {
            if ($debugStage !== '') { $this->logUpdaterDebug($debugStage, true, $started); }
            throw $e;
        }
        $data = json_decode(isset($result['stdout']) ? $result['stdout'] : '', true);
        if (!is_array($data) || !empty($result['code']) || empty($data['ok'])) {
            if ($debugStage !== '') { $this->logUpdaterDebug($debugStage, true, $started); }
            throw new RuntimeException(is_array($data) && !empty($data['error'])
                ? (string)$data['error'] : 'Guardian-Updater nicht erreichbar.');
        }
        if ($debugStage !== '') { $this->logUpdaterDebug($debugStage, false, $started); }
        return $data;
    }

    private function logUpdaterDebug($stage, $failed, $started)
    {
        try {
            $elapsed = max(0, (int)round((microtime(true) - $started) * 1000));
            $this->helper(['debug-event', $stage, $failed ? '1' : '0', (string)$elapsed]);
        } catch (\Throwable $ignored) {
            // Diagnostics must never change the updater result.
        }
    }

    private function manager($request = null)
    {
        // Plesk >= 18.0.55 supports stdin; API secrets never enter process arguments.
        $stdin = $request === null ? '' : json_encode($request, JSON_INVALID_UTF8_SUBSTITUTE);
        if (!is_string($stdin) || strlen($stdin) > 16384) {
            throw new RuntimeException('Verwaltungsanfrage ungueltig oder zu gross.');
        }
        $result = pm_ApiCli::callSbin('guardian-manager', [$request === null ? 'status' : 'request'],
                                    pm_ApiCli::RESULT_FULL, [], $stdin);
        $data = json_decode($result['stdout'] ?? '', true);
        if (!is_array($data) || !empty($result['code']) || empty($data['ok'])) {
            throw new RuntimeException(is_array($data) ? ($data['error'] ?? 'Verwaltungsaktion fehlgeschlagen.') : 'Guardian-Verwaltung nicht erreichbar.');
        }
        return $data;
    }

    public function manageAction()
    {
        $this->verifyPost();
        $post = $this->getRequest();
        $operation = (string)$post->getPost('operation', '');
        $allowed = ['php-backup', 'php-restore', 'runtime-set', 'runtime-install', 'waf-preview',
                    'waf-set', 'waf-engine', 'waf-restore', 'cloud-save', 'reputation', 'ignore-add', 'ignore-remove',
                    'global-ignore-add', 'global-ignore-remove', 'baseline-create', 'baseline-delete',
                    'repair-set', 'repair', 'repair-rollback', 'bots-set', 'diagnostics', 'cron-audit',
                    'wp-checksum-audit', 'wp-plugin-checksum-audit', 'wp-db-scan', 'wp-db-clamav-scan', 'cms-db-clamav-scan',
                    'backup-delete', 'retention-preview', 'retention-prune'];
        $allowed = array_merge($allowed, ['wp-theme-checksum-audit', 'crs-stage', 'crs-activate', 'crs-rollback']);
        if (!in_array($operation, $allowed, true)) {
            throw new pm_Exception('Unbekannte Verwaltungsaktion.');
        }
        $request = ['action' => $operation];
        foreach (['domain', 'version', 'mode', 'sha256', 'backup', 'baseline_id', 'jobid', 'ip',
                  'abuseipdb_key', 'turnstile_sitekey', 'turnstile_secret'] as $key) {
            $value = $post->getPost($key, '');
            if (!is_string($value) || strlen($value) > 254) {
                throw new pm_Exception('Ungueltiges Eingabefeld.');
            }
            if ($value !== '') { $request[$key] = trim($value); }
        }
        if (isset($request['domain']) && !$this->isDomainKnown($request['domain'])) {
            throw new pm_Exception('Unbekannte gehostete Domain.');
        }
        foreach (['limit', 'index', 'days'] as $key) {
            $value = $post->getPost($key, '');
            if ($value !== '') {
                if (!is_string($value) || !preg_match('/^\d{1,5}$/D', $value)) {
                    throw new pm_Exception('Ungueltiger Zahlenwert.');
                }
                $request[$key] = (int)$value;
            }
        }
        if (isset($request['days']) && ($request['days'] < 30 || $request['days'] > 3650)) {
            throw new pm_Exception('Aufbewahrungsdauer muss zwischen 30 und 3650 Tagen liegen.');
        }
        foreach (['trusted', 'consent', 'clear', 'http_probe'] as $key) {
            $request[$key] = $post->getPost($key, '') === '1';
        }
        try {
            $result = $this->manager($request);
            $record = ['ok' => true, 'operation' => $operation, 'at' => time(), 'result' => $result['result'] ?? []];
        } catch (\Throwable $e) {
            $record = ['ok' => false, 'operation' => $operation, 'at' => time(), 'error' => substr($e->getMessage(), 0, 300)];
        }
        // Only the manager's sanitized response is persisted, never the request with keys.
        pm_Settings::set('guardian_management_result', json_encode($record, JSON_INVALID_UTF8_SUBSTITUTE));
        $this->redirect(pm_Context::getBaseUrl() . '#guardian-tab-management');
    }

    public function managementExportAction()
    {
        $data = $this->manager();
        $this->_helper->viewRenderer->setNoRender();
        $this->_helper->layout->disableLayout();
        $this->getResponse()->setHeader('Content-Type', 'application/json; charset=UTF-8', true)
            ->setHeader('Content-Disposition', 'attachment; filename="guardian-diagnostics.json"', true)
            ->setHeader('Cache-Control', 'no-store', true)
            ->setBody(json_encode($data['diagnostics'] ?? [], JSON_PRETTY_PRINT | JSON_INVALID_UTF8_SUBSTITUTE));
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
        $this->view->management = [];
        $this->view->managementError = '';
        $this->view->managementResult = json_decode((string)pm_Settings::get('guardian_management_result'), true) ?: [];
        try {
            $this->view->management = $this->manager();
        } catch (\Throwable $e) {
            $this->view->managementError = $e->getMessage();
        }
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
        $this->view->alertDelivery = ['pending' => 0, 'failed' => 0, 'error' => ''];
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
            $this->view->scanQueue = isset($status['scan_queue']) ? $status['scan_queue'] : ['count' => 0, 'jobs' => []];
            $this->view->history = isset($status['history']) ? $status['history'] : [];
            $this->view->schedules = isset($status['schedules']) ? $status['schedules'] : [];
            $this->view->watch = isset($status['watch']) ? $status['watch'] : [];
            $this->view->realtime = isset($status['realtime']) ? $status['realtime'] : [];
            $this->view->incidents = isset($status['incidents']) ? $status['incidents'] : [];
            $this->view->alerts = isset($status['alerts']) ? $status['alerts'] : ['enabled' => false, 'recipient' => ''];
            $this->view->alertDelivery = isset($status['alert_delivery']) ? $status['alert_delivery'] : $this->view->alertDelivery;
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
            if ($operation === 'scan') {
                if (!preg_match('/^[a-f0-9]{32}$/', (string)($result['id'] ?? ''))
                    || !in_array($result['status'] ?? '', ['queued', 'running'], true)) {
                    throw new RuntimeException('Scan-Auftrag konnte nicht bestaetigt werden.');
                }
                $message = ($result['status'] === 'queued')
                    ? 'Malware-Scan fuer ' . $domain . ' wurde in die FIFO-Warteschlange eingereiht.'
                    : 'Malware-Scan fuer ' . $domain . ' wurde gestartet.';
            }
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

    public function alertsRetryAction()
    {
        $this->verifyPost();
        $this->finishAction(['alerts-retry'], 'Ausstehende E-Mail-Warnungen werden erneut versucht.');
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
        if (!filter_var($ip, FILTER_VALIDATE_IP) ||
            !in_array($operation, ['ban', 'unban', 'permanent'], true) ||
            ($operation !== 'permanent' && !preg_match('/^[A-Za-z0-9_.-]{1,80}$/', $jail))) {
            throw new pm_Exception('Ungueltige IP-Sperraktion.');
        }
        if ($operation === 'permanent') {
            $remote = isset($_SERVER['REMOTE_ADDR']) && is_string($_SERVER['REMOTE_ADDR'])
                ? $_SERVER['REMOTE_ADDR'] : '';
            $this->finishAction(['firewall-action', 'ban', $ip, $remote, '0'],
                'Dauerhafte Plesk-Sperre vorbereitet. Separaten Zugriff testen und danach bestaetigen.');
            return;
        }
        $this->finishAction(['ip-action', $jail, $ip, $operation], 'Fail2Ban-IP-Aktion bearbeitet.');
    }

    public function firewallAction()
    {
        $this->verifyPost();
        $request = $this->getRequest();
        $operation = (string)$request->getPost('operation', '');
        if (!in_array($operation, ['ban', 'unban', 'port-allow', 'port-deny', 'port-remove',
            'debug-on', 'debug-off',
            'allowlist-add', 'allowlist-remove', 'confirm', 'cancel'], true)) {
            throw new pm_Exception('Ungueltige Plesk-Firewall-Aktion.');
        }
        if (in_array($operation, ['debug-on', 'debug-off'], true)) {
            $this->finishAction(['firewall-debug-set', $operation === 'debug-on' ? 'on' : 'off'],
                $operation === 'debug-on' ? 'Guardian-Moduldiagnose aktiviert.' : 'Guardian-Moduldiagnose deaktiviert.');
            return;
        }
        if ($operation === 'allowlist-add') {
            $network = trim((string)$request->getPost('network', ''));
            $comment = trim((string)$request->getPost('comment', ''));
            if ($network === '' || strlen($network) > 80 || $comment === '' || strlen($comment) > 120 ||
                preg_match('/[\x00-\x1F\x7F]/', $comment)) {
                throw new pm_Exception('IP-Netz und Kommentar (1 bis 120 druckbare Zeichen) erforderlich.');
            }
            $this->finishAction(['firewall-action', 'allowlist-add', $network, $comment],
                'Guardian-IP-Ausnahme hinzugefuegt.');
            return;
        }
        if ($operation === 'allowlist-remove') {
            $network = trim((string)$request->getPost('network', ''));
            if ($network === '' || strlen($network) > 80) {
                throw new pm_Exception('IP-Adresse oder CIDR erforderlich.');
            }
            $this->finishAction(['firewall-action', 'allowlist-remove', $network],
                'Guardian-IP-Ausnahme entfernt.');
            return;
        }
        if (in_array($operation, ['ban', 'unban', 'port-allow', 'port-deny'], true)) {
            $network = trim((string)$request->getPost('network', ''));
            if ($network === '' || strlen($network) > 80) {
                throw new pm_Exception('IPv4-/IPv6-Adresse oder CIDR erforderlich.');
            }
            // REMOTE_ADDR is the actual panel connection peer. Do not trust forwarded headers here.
            $remote = isset($_SERVER['REMOTE_ADDR']) && is_string($_SERVER['REMOTE_ADDR'])
                ? $_SERVER['REMOTE_ADDR'] : '';
            $arguments = ['firewall-action', $operation, $network, $remote];
            if ($operation === 'ban') {
                $ttl = (string)$request->getPost('ttl', '0');
                if (!in_array($ttl, ['0', '3600', '86400', '604800'], true)) {
                    throw new pm_Exception('Ungueltige Sperrdauer ausgewaehlt.');
                }
                $arguments[] = $ttl;
            } elseif (in_array($operation, ['port-allow', 'port-deny'], true)) {
                $port = (string)$request->getPost('port', '');
                $protocol = (string)$request->getPost('protocol', '');
                if (!preg_match('/^[1-9][0-9]{0,4}$/D', $port) || (int)$port > 65535 ||
                    !in_array($protocol, ['tcp', 'udp'], true)) {
                    throw new pm_Exception('Port oder Transportprotokoll ungueltig.');
                }
                $arguments[] = $port;
                $arguments[] = $protocol;
            }
            $this->finishAction($arguments,
                'Plesk-Firewall-Aenderung wurde gestartet.');
            return;
        }
        if ($operation === 'port-remove') {
            $ruleId = (string)$request->getPost('rule_id', '');
            if (!preg_match('/^[0-9]{1,12}$/D', $ruleId)) {
                throw new pm_Exception('Ungueltige Guardian-Firewall-Regel-ID.');
            }
            $this->finishAction(['firewall-action', 'port-remove', $ruleId],
                'Plesk-Firewall-Portregel wird entfernt.');
            return;
        }
        if ($operation === 'confirm' && $request->getPost('tested', '') !== '1') {
            throw new pm_Exception('Vor der Bestaetigung zuerst eine getrennte SSH- oder Admin-Verbindung testen.');
        }
        $this->finishAction(['firewall-action', $operation],
            $operation === 'confirm' ? 'Plesk-Firewall-Aenderung bestaetigt.' : 'Plesk-Firewall-Rollback angefordert.');
    }
}
