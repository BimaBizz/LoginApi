<?php

$this->helpers['system']    = 'System\\Helper\\System';
$this->helpers['api']       = 'System\\Helper\\Api';

// load api request related code
$this->on('app.api.request', function() {
    include(__DIR__.'/api.php');
});
