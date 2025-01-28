<?php

/**
 *
 * @OA\Tag(
 *   name="user",
 *   description="User authentication and registration",
 * )
 */

$this->on('restApi.config', function($restApi) {

    // Endpoint untuk autentikasi user berdasarkan email dan password
    $restApi->addEndPoint('/user/auth', [

        /**
         * @OA\Post(
         *     path="/user/auth",
         *     tags={"user"},
         *     @OA\Parameter(
         *         name="email",
         *         in="query",
         *         required=true,
         *         description="email user",
         *         @OA\Schema(type="email")
         *     ),
         *     @OA\Parameter(
         *         name="password",
         *         in="query",
         *         required=true,
         *         description="password user",
         *         @OA\Schema(type="string")
         *     ),
         *     @OA\Response(response="200", description="User authenticated, user data returned"),
         *     @OA\Response(response="412", description="Email or password missing or authentication failed"),
         * )
         */
        'POST' => function($params, $app) {

            // Check permission
            if (!$app->helper('acl')->isAllowed('loginapi/api/auth', $app->helper('auth')->getUser('role'))) {
                $app->response->status = 403;
                return ['error' => 'Permission denied'];
            }

            $email = $app->param('email');
            $password = $app->param('password');

            if (!$email || !$password) {
                return $app->stop(['error' => 'Email and password are required'], 412);
            }

            // Authenticate user based on email and password
            $user = $app->dataStorage->findOne('system/users', ['email' => $email]);

            if (!$user || !$app->helper('auth')->verifyPassword($password, $user['password'])) {
                return $app->stop(['error' => 'Authentication failed!'], 412);
            }

            // Remove sensitive data from user data
            unset($user['password'], $user['twofa'], $user['apiKey']);

            // Generate JWT token with all user data except sensitive fields
            $token = $app->helper('jwt')->create($user);

            return ['JWT' => $token];
        }

    ]);

    // Endpoint untuk registrasi user
    $restApi->addEndPoint('/user/register', [

        /**
         * @OA\Post(
         *     path="/user/register",
         *     tags={"user"},
         *     @OA\Parameter(
         *         name="user",
         *         in="query",
         *         required=true,
         *         description="username user have",
         *         @OA\Schema(type="string")
         *     ),
         *     @OA\Parameter(
         *         name="name",
         *         in="query",
         *         required=true,
         *         description="full name user have",
         *         @OA\Schema(type="string")
         *     ),
         *     @OA\Parameter(
         *         name="email",
         *         in="query",
         *         required=true,
         *         description="email user have",
         *         @OA\Schema(type="email")
         *     ),
         *     @OA\Parameter(
         *         name="password",
         *         in="query",
         *         required=true,
         *         description="password user have",
         *         @OA\Schema(type="string")
         *     ),
         *     @OA\Response(response="200", description="User registered successfully"),
         *     @OA\Response(response="412", description="User or email already exists"),
         * )
         */
        'POST' => function($params, $app) {

            // Check permission
            if (!$app->helper('acl')->isAllowed('loginapi/api/register', $app->helper('auth')->getUser('role'))) {
                $app->response->status = 403;
                return ['error' => 'Permission denied'];
            }

            // Mengambil parameter dari request
            $user = $app->param('user');
            $name = $app->param('name');
            $email = $app->param('email');
            $password = $app->param('password');
            $created = time();

            // Validasi agar semua field tidak kosong
            if (empty($user)) {
                return $app->stop(['error' => 'Username is required'], 412);
            }

            if (empty($name)) {
                return $app->stop(['error' => 'Name is required'], 412);
            }

            if (empty($email)) {
                return $app->stop(['error' => 'Email is required'], 412);
            }

            if (empty($password)) {
                return $app->stop(['error' => 'Password is required'], 412);
            }

            // Validasi format email yang valid
            if (!filter_var($email, FILTER_VALIDATE_EMAIL)) {
                return $app->stop(['error' => 'Invalid email format'], 412);
            }

            // Validasi panjang password minimal 6 karakter
            if (strlen($password) < 6) {
                return $app->stop(['error' => 'Password must be at least 6 characters'], 412);
            }

            // Cek apakah user atau email sudah ada di database
            $userExist = $app->dataStorage->findOne('system/users', ['user' => $user]);
            $emailExist = $app->dataStorage->findOne('system/users', ['email' => $email]);

            if ($userExist) {
                return $app->stop(['error' => 'User already exists'], 412);
            }

            if ($emailExist) {
                return $app->stop(['error' => 'Email already exists'], 412);
            }

            $newUser = [
                'active' => true,
                'user' => $user,
                'name' => $name,
                'email' => $email,
                'password' => $app->hash($password),  // Hash password for security
                'i18n' => 'en',
                'role' => 'public',
                'theme' => 'auto',
                '_modified' => $created,
                '_created' => $created
            ];
            
            $app->dataStorage->save('system/users', $newUser);
            
            // Prepare response data without 'password' and 'role'
            $responseUser = [
                'active' => $newUser['active'],
                'user' => $newUser['user'],
                'name' => $newUser['name'],
                'email' => $newUser['email'],
                'i18n' => $newUser['i18n'],
                'theme' => $newUser['theme'],
                '_modified' => $newUser['_modified'],
                '_created' => $newUser['_created'],
            ];
            
            // Return the user data without 'password' and 'role'
            return ['success' => true, 'user' => $responseUser];
        }

    ]);


    // Endpoint to get all users with only the 'name' and '_id' fields
    $restApi->addEndPoint('/user/list', [

        /**
         * @OA\Get(
         *     path="/user/list",
         *     tags={"user"},
         *     @OA\Response(response="200", description="List of users with name and _id"),
         * )
         */
        'GET' => function($params, $app) {

            // Check permission
            if (!$app->helper('acl')->isAllowed('loginapi/api/list', $app->helper('auth')->getUser('role'))) {
                $app->response->status = 403;
                return ['error' => 'Permission denied'];
            }
    
            // Fetch all user data from 'system/users'
            $users = $app->dataStorage->find('system/users')->toArray();
    
            // Filter out users with role 'admin', 'Admin', or 'ADMIN' and map only 'name' and '_id'
            $result = array_map(function($user) {
                return [
                    'name' => $user['name'] ?? '',
                    '_id' => $user['_id']
                ];
            }, array_filter($users, function($user) {
                return strtolower($user['role'] ?? '') !== 'admin';
            }));
    
            return $result;
        }
    
    ]);
    
    // Endpoint to get a user by _id with only 'name' and 'email' fields
    $restApi->addEndPoint('/user/{id}', [

        /**
         * @OA\Get(
         *     path="/user/{id}",
         *     tags={"user"},
         *     @OA\Parameter(
         *         name="id",
         *         in="path",
         *         required=true,
         *         description="The _id of the user",
         *         @OA\Schema(type="string")
         *     ),
         *     @OA\Response(response="200", description="User data with name and email"),
         *     @OA\Response(response="404", description="User not found"),
         * )
         */
        'GET' => function($params, $app) {

            // Check permission
            if (!$app->helper('acl')->isAllowed('loginapi/api/get', $app->helper('auth')->getUser('role'))) {
                $app->response->status = 403;
                return ['error' => 'Permission denied'];
            }

            // Get the _id from the path parameters
            $userId = $params['id'];

            // Find the user by _id in the 'system/users' collection
            $user = $app->dataStorage->findOne('system/users', ['_id' => $userId]);

            // If the user does not exist, return a 404 error
            if (!$user) {
                return $app->stop(['error' => 'User not found'], 404);
            }

            // Return only 'name' and 'email' fields
            return [
                'name' => $user['name'] ?? '',
                'email' => $user['email'] ?? ''
            ];
        }

    ]);

});
