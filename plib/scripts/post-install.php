<?php
// Plesk-managed hourly cron task. Existing manual installs are not modified.
pm_Context::init('guardian-lite');
$scheduler = pm_Scheduler::getInstance();
$taskId = (string)pm_Settings::get('guardian_scheduler_task_id');
$exists = false;
if ($taskId !== '') {
    try {
        $exists = (bool)$scheduler->getTaskById($taskId);
    } catch (Exception $e) {
        $exists = false;
    }
}
if (!$exists) {
    $task = new pm_Scheduler_Task();
    $task->setSchedule(pm_Scheduler::$EVERY_HOUR);
    $task->setCmd('periodic-task.php');
    $scheduler->putTask($task);
    pm_Settings::set('guardian_scheduler_task_id', $task->getId());
}
