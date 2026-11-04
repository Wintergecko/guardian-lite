<?php
// Plesk authenticated extension entry point. Never expose an unauthenticated API.
(new pm_Application())->run();
