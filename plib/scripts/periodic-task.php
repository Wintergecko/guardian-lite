<?php
// Runs from Plesk Scheduler. The privileged helper selects ONE due, enabled domain.
pm_Context::init('guardian-lite');
try {
    $result = pm_ApiCli::callSbin('guardian-helper', ['scheduled-tick'], pm_ApiCli::RESULT_FULL);
    if (!empty($result['code'])) {
        error_log('Guardian Lite scheduler: ' . substr((string)$result['stderr'], 0, 300));
    }
} catch (Exception $e) {
    error_log('Guardian Lite scheduler: ' . substr($e->getMessage(), 0, 300));
}
