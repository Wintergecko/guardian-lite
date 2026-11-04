<?php
// Stop only the Guardian-owned scheduled task. Preserve reports/quarantine for recovery.
pm_Context::init('guardian-lite');
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
