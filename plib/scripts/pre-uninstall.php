<?php
// Stop only the Guardian-owned scheduled task. Preserve reports/quarantine for recovery.
pm_Context::init('guardian-lite');
$cleanup = pm_ApiCli::callSbin('guardian-manager', ['uninstall'], pm_ApiCli::RESULT_FULL);
$cleanupData = json_decode($cleanup['stdout'] ?? '', true);
if (!empty($cleanup['code']) || !is_array($cleanupData) || empty($cleanupData['ok'])) {
    throw new pm_Exception('Guardian-Policies konnten nicht sicher deaktiviert werden. Vor Deinstallation unter Verwaltung deaktivieren und geaenderte Konfigurationen pruefen.');
}
$id = (string)pm_Settings::get('guardian_scheduler_task_id');
if ($id !== '') {
    try {
        $scheduler = pm_Scheduler::getInstance();
        $task = $scheduler->getTaskById($id);
        if ($task) {
            $scheduler->removeTask($task);
        }
    } catch (Exception $e) {
        error_log('Guardian Lite task removal: ' . substr($e->getMessage(), 0, 250));
    }
}
