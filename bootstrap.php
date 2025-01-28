<?php

$this->helpers['system']    = 'System\\Helper\\System';
$this->helpers['api']       = 'System\\Helper\\Api';

$this->on('app.permissions.collect', function($permissions) {

    $permissions['LoginApi'] = [
        'loginapi/api/auth' => 'API access for authentication',
        'loginapi/api/register' => 'API access for registration',
        'loginapi/api/list' => 'API access for listing users',
        'loginapi/api/get' => 'API access for getting user by ID',
    ];
});

// load api request related code
$this->on('app.api.request', function() {
    include(__DIR__.'/api.php');
});
