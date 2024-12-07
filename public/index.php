<?php
use \Psr\Http\Message\ServerRequestInterface as Request;
use \Psr\Http\Message\ResponseInterface as Response;
use Firebase\JWT\JWT;
use Firebase\JWT\Key;

require '../src/vendor/autoload.php';
$config = ['settings' => ['displayErrorDetails' => true]];
$app = new Slim\App($config);

$key = 'server_hack';

function generateToken($userid) {
    global $key;

    $iat = time();
    $payload = [
        'iss' => 'http://library.org',
        'aud' => 'http://library.com',
        'iat' => $iat,
        'exp' => $iat + 10000,
        "data" => array(
            "userid" => $userid
        )
    ];
    $token = JWT::encode($payload, $key, 'HS256');

    $servername = "localhost";
    $username = "root";
    $password = "";
    $dbname = "library";

    try {
        $conn = new PDO("mysql:host=$servername;dbname=$dbname", $username, $password);
        $conn->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);

        $sql = "INSERT INTO tokens (token, userid, status) VALUES (:token, :userid, 'active')";
        $stmt = $conn->prepare($sql);
        $stmt->bindParam(':token', $token);
        $stmt->bindParam(':userid', $userid);
        $stmt->execute();
    } catch (PDOException $e) {

    }

    return $token;
}

function validateToken($token) {
    global $key;
    $servername = "localhost";
    $username = "root";
    $password = "";
    $dbname = "library";

    try {
        $conn = new PDO("mysql:host=$servername;dbname=$dbname", $username, $password);
        $conn->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);

        $sql = "SELECT * FROM tokens WHERE token = :token AND status = 'active'";
        $stmt = $conn->prepare($sql);
        $stmt->bindParam(':token', $token);
        $stmt->execute();
        $data = $stmt->fetch(PDO::FETCH_ASSOC);

        if ($data) {
            $decoded = JWT::decode($token, new Key($key, 'HS256'));
            return $decoded->data->userid;
        } else {
            return false;
        }
    } catch (PDOException $e) {
        return false;
    }
}

function markTokenAsUsed($token) {
    $servername = "localhost";
    $username = "root";
    $password = "";
    $dbname = "library";

    try {
        $conn = new PDO("mysql:host=$servername;dbname=$dbname", $username, $password);
        $conn->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);

        $sql = "UPDATE tokens SET status = 'revoked', used_at = NOW() WHERE token = :token";
        $stmt = $conn->prepare($sql);
        $stmt->bindParam(':token', $token);
        $stmt->execute();
    } catch (PDOException $e) {
    }
}

function updateTokenStatus($token, $status) {
    $servername = "localhost";
    $username = "root";
    $password = "";
    $dbname = "library";

    try {
        $conn = new PDO("mysql:host=$servername;dbname=$dbname", $username, $password);
        $conn->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);

        $sql = "UPDATE tokens SET status = :status WHERE token = :token";
        $stmt = $conn->prepare($sql);
        $stmt->bindParam(':status', $status);
        $stmt->bindParam(':token', $token);
        $stmt->execute();
    } catch (PDOException $e) {
    }
}

$app->post('/user/register', function (Request $request, Response $response, array $args) {
    $data = json_decode($request->getBody());
    $uname = $data->username;
    $pass = $data->password;
    $servername = "localhost";
    $username = "root";
    $password = "";
    $dbname = "library";

    try {
        $conn = new PDO("mysql:host=$servername;dbname=$dbname", $username, $password);
        $conn->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);

        $stmt = $conn->prepare("SELECT COUNT(*) FROM users WHERE username = :username");
        $stmt->bindParam(':username', $uname);
        $stmt->execute();
        $count = $stmt->fetchColumn();

        if ($count > 0) {
            $response->getBody()->write(json_encode(array("status" => "fail", "data" => array("title" => "Username already taken"))));
        } else {
            $sql = "INSERT INTO users (username, password) VALUES (:username, :password)";
            $stmt = $conn->prepare($sql);
            $hashedPassword = hash('sha256', $pass);
            $stmt->bindParam(':username', $uname);
            $stmt->bindParam(':password', $hashedPassword);
            $stmt->execute();

            $response->getBody()->write(json_encode(array("status" => "success", "data" => null)));
        }
    } catch (PDOException $e) {
        $response->getBody()->write(json_encode(array("status" => "fail", "data" => array("title" => $e->getMessage()))));
    }

    $conn = null;
    return $response;
});

$app->post('/user/auth', function (Request $request, Response $response, array $args) {
    $data = json_decode($request->getBody());
    $uname = $data->username;
    $pass = $data->password;
    $servername = "localhost";
    $username = "root";
    $password = "";
    $dbname = "library";

    try {
        $conn = new PDO("mysql:host=$servername;dbname=$dbname", $username, $password);
        $conn->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);

        $sql = "SELECT * FROM users WHERE username='" . $uname . "' 
                AND password='" . hash('SHA256', $pass) . "'";
        $stmt = $conn->prepare($sql);
        $stmt->execute();

        $data = $stmt->fetchAll();
        if (count($data) == 1) {
            $userid = $data[0]['userid'];
            $token = generateToken($userid);
            $response->getBody()->write(json_encode(array("status" => "success", "token" => $token, "data" => null)));
        } else {
            $response->getBody()->write(json_encode(array("status" => "fail", "data" => array("title" => "Authentication Failed"))));
        }
    } catch (PDOException $e) {
        $response->getBody()->write(json_encode(array("status" => "fail", "data" => array("title" => $e->getMessage()))));
    }

    $conn = null;
    return $response;
});

$app->get('/user/show', function (Request $request, Response $response) {
    $headers = $request->getHeaders();
    error_log("Headers: " . print_r($headers, true));

    $authHeader = $request->getHeader('Authorization');
    error_log("Authorization Header: " . print_r($authHeader, true));
    if (empty($authHeader)) {
        error_log("Authorization header missing");
        return $response->withStatus(401)->write(json_encode(array("status" => "fail", "data" => array("title" => "Authorization header missing"))));
    }

    $token = str_replace('Bearer ', '', $authHeader[0]);
    error_log("Token: " . $token);

    $userid = validateToken($token);

    if (!$userid) {
        error_log("Invalid or expired token");
        return $response->withStatus(401)->write(json_encode(array("status" => "fail", "data" => array("title" => "Invalid or expired token"))));
    }

    $servername = "localhost";
    $dbusername = "root";
    $dbpassword = "";
    $dbname = "library";

    try {
        $conn = new PDO("mysql:host=$servername;dbname=$dbname", $dbusername, $dbpassword);
        $conn->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);

        $stmt = $conn->prepare("SELECT userid, username FROM users");
        $stmt->execute();
        $users = $stmt->fetchAll(PDO::FETCH_ASSOC);

        if ($users) {
            markTokenAsUsed($token);

            $newToken = generateToken($userid);

            return $response->write(json_encode(array("status" => "success", "token" => $newToken, "data" => $users)));
        } else {
            return $response->write(json_encode(array("status" => "fail", "message" => "No users found")));
        }
    } catch (PDOException $e) {
        return $response->withStatus(500)->write(json_encode(array("status" => "fail", "message" => $e->getMessage())));
    }

    $conn = null;
});

$app->put('/user/update', function (Request $request, Response $response) {
    $data = json_decode($request->getBody());

    if (!isset($data->token)) {
        return $response->withStatus(401)->write(json_encode(array("status" => "fail", "data" => array("title" => "Token missing in payload"))));
    }

    if (!isset($data->userid)) {
        return $response->withStatus(400)->write(json_encode(array("status" => "fail", "data" => array("title" => "User ID missing in payload"))));
    }

    $token = $data->token;
    $useridFromToken = validateToken($token);

    if (!$useridFromToken) {
        return $response->withStatus(401)->write(json_encode(array("status" => "fail", "data" => array("title" => "Invalid or expired token"))));
    }

    $useridToUpdate = $data->userid;

    if ($useridFromToken != $useridToUpdate) {
        return $response->withStatus(403)->write(json_encode(array("status" => "fail", "data" => array("title" => "Unauthorized action"))));
    }

    $uname = $data->username;
    $pass = $data->password;
    $servername = "localhost";
    $username = "root";
    $password = "";
    $dbname = "library";

    try {
        $conn = new PDO("mysql:host=$servername;dbname=$dbname", $username, $password);
        $conn->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);

        $sql = "UPDATE users SET username = :username, password = :password WHERE userid = :userid";
        $stmt = $conn->prepare($sql);
        $hashedPassword = hash('sha256', $pass);
        $stmt->bindParam(':username', $uname);
        $stmt->bindParam(':password', $hashedPassword);
        $stmt->bindParam(':userid', $useridToUpdate);
        $stmt->execute();

        markTokenAsUsed($token);

        $newToken = generateToken($useridFromToken);
        $response->getBody()->write(json_encode(array("status" => "success", "token" => $newToken, "data" => null)));
    } catch (PDOException $e) {
        $response->getBody()->write(json_encode(array("status" => "fail", "data" => array("title" => $e->getMessage()))));
    }

    $conn = null;
    return $response;
});

$app->delete('/user/delete', function (Request $request, Response $response) {
    $data = json_decode($request->getBody());

    if (json_last_error() !== JSON_ERROR_NONE) {
        error_log("JSON Error: " . json_last_error_msg());
        return $response->withStatus(400)->write(json_encode(array("status" => "fail", "data" => array("title" => "Invalid JSON payload"))));
    }

    if (!isset($data->token)) {
        return $response->withStatus(401)->write(json_encode(array("status" => "fail", "data" => array("title" => "Token missing in payload"))));
    }

    if (!isset($data->userid)) {
        return $response->withStatus(400)->write(json_encode(array("status" => "fail", "data" => array("title" => "User ID missing in payload"))));
    }

    $token = $data->token;
    $useridFromToken = validateToken($token);

    if (!$useridFromToken) {
        return $response->withStatus(401)->write(json_encode(array("status" => "fail", "data" => array("title" => "Invalid or expired token"))));
    }

    $useridToDelete = $data->userid;

    if ($useridFromToken != $useridToDelete) {
        return $response->withStatus(403)->write(json_encode(array("status" => "fail", "data" => array("title" => "Unauthorized action"))));
    }

    $servername = "localhost";
    $username = "root";
    $password = "";
    $dbname = "library";

    try {
        $conn = new PDO("mysql:host=$servername;dbname=$dbname", $username, $password);
        $conn->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);

        $sql = "DELETE FROM users WHERE userid = :userid";
        $stmt = $conn->prepare($sql);
        $stmt->bindParam(':userid', $useridToDelete);
        $stmt->execute();

        markTokenAsUsed($token);

        $response->getBody()->write(json_encode(array("status" => "success", "data" => null)));
    } catch (PDOException $e) {
        $response->getBody()->write(json_encode(array("status" => "fail", "data" => array("title" => $e->getMessage()))));
    }

    $conn = null;
    return $response;
});

$app->post('/author/register', function (Request $request, Response $response, array $args) {
    $data = json_decode($request->getBody());

    if (!isset($data->token)) {
        return $response->withStatus(401)->write(json_encode(array("status" => "fail", "data" => array("title" => "Token missing in payload"))));
    }

    if (!isset($data->name)) {
        return $response->withStatus(400)->write(json_encode(array("status" => "fail", "data" => array("title" => "Name missing in payload"))));
    }

    $token = $data->token;
    $name = $data->name;
    $useridFromToken = validateToken($token);

    if (!$useridFromToken) {
        return $response->withStatus(401)->write(json_encode(array("status" => "fail", "data" => array("title" => "Invalid or expired token"))));
    }

    $servername = "localhost";
    $username = "root";
    $password = "";
    $dbname = "library";

    try {
        $conn = new PDO("mysql:host=$servername;dbname=$dbname", $username, $password);
        $conn->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);

        $stmt = $conn->prepare("SELECT COUNT(*) FROM authors WHERE name = :name");
        $stmt->bindParam(':name', $name);
        $stmt->execute();
        $count = $stmt->fetchColumn();

        if ($count > 0) {
            $response->getBody()->write(json_encode(array("status" => "fail", "data" => array("title" => "Author name already taken"))));
        } else {
            $sql = "INSERT INTO authors (name) VALUES (:name)";
            $stmt = $conn->prepare($sql);
            $stmt->bindParam(':name', $name);
            $stmt->execute();

            markTokenAsUsed($token);

            $newToken = generateToken($useridFromToken);
            $response->getBody()->write(json_encode(array("status" => "success", "token" => $newToken, "data" => null)));
        }
    } catch (PDOException $e) {
        $response->getBody()->write(json_encode(array("status" => "fail", "data" => array("title" => $e->getMessage()))));
    }

    $conn = null;
    return $response;
});

$app->get('/author/show', function (Request $request, Response $response) {

    $headers = $request->getHeaders();
    error_log("Headers: " . print_r($headers, true));

    $authHeader = $request->getHeader('Authorization');
    error_log("Authorization Header: " . print_r($authHeader, true));
    if (empty($authHeader)) {
        error_log("Authorization header missing");
        return $response->withStatus(401)->write(json_encode(array("status" => "fail", "data" => array("title" => "Authorization header missing"))));
    }

    $token = str_replace('Bearer ', '', $authHeader[0]);
    error_log("Token: " . $token);

    $userid = validateToken($token);

    if (!$userid) {
        error_log("Invalid or expired token");
        return $response->withStatus(401)->write(json_encode(array("status" => "fail", "data" => array("title" => "Invalid or expired token"))));
    }

    $servername = "localhost";
    $dbusername = "root";
    $dbpassword = "";
    $dbname = "library";

    try {
        $conn = new PDO("mysql:host=$servername;dbname=$dbname", $dbusername, $dbpassword);
        $conn->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);

        $stmt = $conn->prepare("SELECT authorid, name FROM authors");
        $stmt->execute();
        $authors = $stmt->fetchAll(PDO::FETCH_ASSOC);

        if ($authors) {
            markTokenAsUsed($token);

            $newToken = generateToken($userid);

            return $response->write(json_encode(array("status" => "success", "token" => $newToken, "data" => $authors)));
        } else {
            return $response->write(json_encode(array("status" => "fail", "message" => "No authors found")));
        }
    } catch (PDOException $e) {
        return $response->withStatus(500)->write(json_encode(array("status" => "fail", "message" => $e->getMessage())));
    }

    $conn = null;
});

$app->put('/author/update', function (Request $request, Response $response) {
    $data = json_decode($request->getBody());

    if (!isset($data->token)) {
        return $response->withStatus(401)->write(json_encode(array("status" => "fail", "data" => array("title" => "Token missing in payload"))));
    }

    if (!isset($data->authorid)) {
        return $response->withStatus(400)->write(json_encode(array("status" => "fail", "data" => array("title" => "Author ID missing in payload"))));
    }

    $token = $data->token;
    $useridFromToken = validateToken($token);

    if (!$useridFromToken) {
        return $response->withStatus(401)->write(json_encode(array("status" => "fail", "data" => array("title" => "Invalid or expired token"))));
    }

    $authoridToUpdate = $data->authorid;
    $name = $data->name;
    $servername = "localhost";
    $username = "root";
    $password = "";
    $dbname = "library";

    try {
        $conn = new PDO("mysql:host=$servername;dbname=$dbname", $username, $password);
        $conn->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);

        $sql = "UPDATE authors SET name = :name WHERE authorid = :authorid";
        $stmt = $conn->prepare($sql);
        $stmt->bindParam(':name', $name);
        $stmt->bindParam(':authorid', $authoridToUpdate);
        $stmt->execute();

        markTokenAsUsed($token);

        $newToken = generateToken($useridFromToken);
        $response->getBody()->write(json_encode(array("status" => "success", "token" => $newToken, "data" => null)));
    } catch (PDOException $e) {
        $response->getBody()->write(json_encode(array("status" => "fail", "data" => array("title" => $e->getMessage()))));
    }

    $conn = null;
    return $response;
});

$app->delete('/author/delete', function (Request $request, Response $response) {
    $data = json_decode($request->getBody());

    if (json_last_error() !== JSON_ERROR_NONE) {
        error_log("JSON Error: " . json_last_error_msg());
        return $response->withStatus(400)->write(json_encode(array("status" => "fail", "data" => array("title" => "Invalid JSON payload"))));
    }

    if (!isset($data->token)) {
        return $response->withStatus(401)->write(json_encode(array("status" => "fail", "data" => array("title" => "Token missing in payload"))));
    }

    if (!isset($data->authorid)) {
        return $response->withStatus(400)->write(json_encode(array("status" => "fail", "data" => array("title" => "Author ID missing in payload"))));
    }

    $token = $data->token;
    $useridFromToken = validateToken($token);

    if (!$useridFromToken) {
        return $response->withStatus(401)->write(json_encode(array("status" => "fail", "data" => array("title" => "Invalid or expired token"))));
    }

    $authoridToDelete = $data->authorid;

    $servername = "localhost";
    $username = "root";
    $password = "";
    $dbname = "library";

    try {
        $conn = new PDO("mysql:host=$servername;dbname=$dbname", $username, $password);
        $conn->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);

        $sql = "DELETE FROM authors WHERE authorid = :authorid";
        $stmt = $conn->prepare($sql);
        $stmt->bindParam(':authorid', $authoridToDelete);
        $stmt->execute();

        markTokenAsUsed($token);

        $newToken = generateToken($useridFromToken);

        $response->getBody()->write(json_encode(array("status" => "success", "token" => $newToken, "data" => null)));
    } catch (PDOException $e) {
        $response->getBody()->write(json_encode(array("status" => "fail", "data" => array("title" => $e->getMessage()))));
    }

    $conn = null;
    return $response;
});

$app->post('/book/register', function (Request $request, Response $response, array $args) {
    $data = json_decode($request->getBody());

    if (!isset($data->token)) {
        return $response->withStatus(401)->write(json_encode(array("status" => "fail", "data" => array("title" => "Token missing in payload"))));
    }

    if (!isset($data->title) || !isset($data->authorid)) {
        return $response->withStatus(400)->write(json_encode(array("status" => "fail", "data" => array("title" => "Title or Author ID missing in payload"))));
    }

    $token = $data->token;
    $title = $data->title;
    $authorid = $data->authorid;
    $useridFromToken = validateToken($token);

    if (!$useridFromToken) {
        return $response->withStatus(401)->write(json_encode(array("status" => "fail", "data" => array("title" => "Invalid or expired token"))));
    }

    $servername = "localhost";
    $username = "root";
    $password = "";
    $dbname = "library";

    try {
        $conn = new PDO("mysql:host=$servername;dbname=$dbname", $username, $password);
        $conn->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);

        $stmt = $conn->prepare("SELECT COUNT(*) FROM books WHERE title = :title AND authorid = :authorid");
        $stmt->bindParam(':title', $title);
        $stmt->bindParam(':authorid', $authorid);
        $stmt->execute();
        $count = $stmt->fetchColumn();

        if ($count > 0) {
            $response->getBody()->write(json_encode(array("status" => "fail", "data" => array("title" => "Book already exists"))));
        } else {
            $sql = "INSERT INTO books (title, authorid) VALUES (:title, :authorid)";
            $stmt = $conn->prepare($sql);
            $stmt->bindParam(':title', $title);
            $stmt->bindParam(':authorid', $authorid);
            $stmt->execute();

            markTokenAsUsed($token);

            $newToken = generateToken($useridFromToken);
            $response->getBody()->write(json_encode(array("status" => "success", "token" => $newToken, "data" => null)));
        }
    } catch (PDOException $e) {
        $response->getBody()->write(json_encode(array("status" => "fail", "data" => array("title" => $e->getMessage()))));
    }

    $conn = null;
    return $response;
});

$app->get('/book/show', function (Request $request, Response $response) {
    $headers = $request->getHeaders();
    error_log("Headers: " . print_r($headers, true));

    $authHeader = $request->getHeader('Authorization');
    error_log("Authorization Header: " . print_r($authHeader, true));
    if (empty($authHeader)) {
        error_log("Authorization header missing");
        return $response->withStatus(401)->write(json_encode(array("status" => "fail", "data" => array("title" => "Authorization header missing"))));
    }

    $token = str_replace('Bearer ', '', $authHeader[0]);
    error_log("Token: " . $token);

    $userid = validateToken($token);

    if (!$userid) {
        error_log("Invalid or expired token");
        return $response->withStatus(401)->write(json_encode(array("status" => "fail", "data" => array("title" => "Invalid or expired token"))));
    }

    $servername = "localhost";
    $dbusername = "root";
    $dbpassword = "";
    $dbname = "library";

    try {
        $conn = new PDO("mysql:host=$servername;dbname=$dbname", $dbusername, $dbpassword);
        $conn->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);

        $stmt = $conn->prepare("SELECT bookid, title, authorid FROM books");
        $stmt->execute();
        $books = $stmt->fetchAll(PDO::FETCH_ASSOC);

        if ($books) {
            markTokenAsUsed($token);

            $newToken = generateToken($userid);

            return $response->write(json_encode(array("status" => "success", "token" => $newToken, "data" => $books)));
        } else {
            return $response->write(json_encode(array("status" => "fail", "message" => "No books found")));
        }
    } catch (PDOException $e) {
        return $response->withStatus(500)->write(json_encode(array("status" => "fail", "message" => $e->getMessage())));
    }

    $conn = null;
});

$app->put('/book/update', function (Request $request, Response $response) {
    $data = json_decode($request->getBody());

    if (!isset($data->token)) {
        return $response->withStatus(401)->write(json_encode(array("status" => "fail", "data" => array("title" => "Token missing in payload"))));
    }

    if (!isset($data->bookid)) {
        return $response->withStatus(400)->write(json_encode(array("status" => "fail", "data" => array("title" => "Book ID missing in payload"))));
    }

    $token = $data->token;
    $useridFromToken = validateToken($token);

    if (!$useridFromToken) {
        return $response->withStatus(401)->write(json_encode(array("status" => "fail", "data" => array("title" => "Invalid or expired token"))));
    }

    $bookidToUpdate = $data->bookid;
    $title = $data->title;
    $authorid = $data->authorid;
    $servername = "localhost";
    $username = "root";
    $password = "";
    $dbname = "library";

    try {
        $conn = new PDO("mysql:host=$servername;dbname=$dbname", $username, $password);
        $conn->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);

        $sql = "UPDATE books SET title = :title, authorid = :authorid WHERE bookid = :bookid";
        $stmt = $conn->prepare($sql);
        $stmt->bindParam(':title', $title);
        $stmt->bindParam(':authorid', $authorid);
        $stmt->bindParam(':bookid', $bookidToUpdate);
        $stmt->execute();

        markTokenAsUsed($token);

        $newToken = generateToken($useridFromToken);
        $response->getBody()->write(json_encode(array("status" => "success", "token" => $newToken, "data" => null)));
    } catch (PDOException $e) {
        $response->getBody()->write(json_encode(array("status" => "fail", "data" => array("title" => $e->getMessage()))));
    }

    $conn = null;
    return $response;
});

$app->delete('/book/delete', function (Request $request, Response $response) {
    $data = json_decode($request->getBody());

    if (json_last_error() !== JSON_ERROR_NONE) {
        error_log("JSON Error: " . json_last_error_msg());
        return $response->withStatus(400)->write(json_encode(array("status" => "fail", "data" => array("title" => "Invalid JSON payload"))));
    }

    if (!isset($data->token)) {
        return $response->withStatus(401)->write(json_encode(array("status" => "fail", "data" => array("title" => "Token missing in payload"))));
    }

    if (!isset($data->bookid)) {
        return $response->withStatus(400)->write(json_encode(array("status" => "fail", "data" => array("title" => "Book ID missing in payload"))));
    }

    $token = $data->token;
    $useridFromToken = validateToken($token);

    if (!$useridFromToken) {
        return $response->withStatus(401)->write(json_encode(array("status" => "fail", "data" => array("title" => "Invalid or expired token"))));
    }

    $bookidToDelete = $data->bookid;

    $servername = "localhost";
    $username = "root";
    $password = "";
    $dbname = "library";

    try {
        $conn = new PDO("mysql:host=$servername;dbname=$dbname", $username, $password);
        $conn->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);

        $sql = "DELETE FROM books WHERE bookid = :bookid";
        $stmt = $conn->prepare($sql);
        $stmt->bindParam(':bookid', $bookidToDelete);
        $stmt->execute();

        markTokenAsUsed($token);

        $newToken = generateToken($useridFromToken);

        $response->getBody()->write(json_encode(array("status" => "success", "token" => $newToken, "data" => null)));
    } catch (PDOException $e) {
        $response->getBody()->write(json_encode(array("status" => "fail", "data" => array("title" => $e->getMessage()))));
    }

    $conn = null;
    return $response;
});

$app->post('/book_author/register', function (Request $request, Response $response, array $args) {
    $data = json_decode($request->getBody());

    if (!isset($data->token)) {
        return $response->withStatus(401)->write(json_encode(array("status" => "fail", "data" => array("title" => "Token missing in payload"))));
    }

    if (!isset($data->bookid) || !isset($data->authorid)) {
        return $response->withStatus(400)->write(json_encode(array("status" => "fail", "data" => array("title" => "Book ID or Author ID missing in payload"))));
    }

    $token = $data->token;
    $bookid = $data->bookid;
    $authorid = $data->authorid;
    $useridFromToken = validateToken($token);

    if (!$useridFromToken) {
        return $response->withStatus(401)->write(json_encode(array("status" => "fail", "data" => array("title" => "Invalid or expired token"))));
    }

    $servername = "localhost";
    $username = "root";
    $password = "";
    $dbname = "library";

    try {
        $conn = new PDO("mysql:host=$servername;dbname=$dbname", $username, $password);
        $conn->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);

        $stmt = $conn->prepare("SELECT COUNT(*) FROM books_authors WHERE bookid = :bookid AND authorid = :authorid");
        $stmt->bindParam(':bookid', $bookid);
        $stmt->bindParam(':authorid', $authorid);
        $stmt->execute();
        $count = $stmt->fetchColumn();

        if ($count > 0) {
            $response->getBody()->write(json_encode(array("status" => "fail", "data" => array("title" => "Book author relationship already exists"))));
        } else {
            $sql = "INSERT INTO books_authors (bookid, authorid) VALUES (:bookid, :authorid)";
            $stmt = $conn->prepare($sql);
            $stmt->bindParam(':bookid', $bookid);
            $stmt->bindParam(':authorid', $authorid);
            $stmt->execute();

            markTokenAsUsed($token);

            $newToken = generateToken($useridFromToken);
            $response->getBody()->write(json_encode(array("status" => "success", "token" => $newToken, "data" => null)));
        }
    } catch (PDOException $e) {
        $response->getBody()->write(json_encode(array("status" => "fail", "data" => array("title" => $e->getMessage()))));
    }

    $conn = null;
    return $response;
});

$app->get('/book_author/show', function (Request $request, Response $response) {
    $headers = $request->getHeaders();
    error_log("Headers: " . print_r($headers, true));

    $authHeader = $request->getHeader('Authorization');
    error_log("Authorization Header: " . print_r($authHeader, true));
    if (empty($authHeader)) {
        error_log("Authorization header missing");
        return $response->withStatus(401)->write(json_encode(array("status" => "fail", "data" => array("title" => "Authorization header missing"))));
    }

    $token = str_replace('Bearer ', '', $authHeader[0]);
    error_log("Token: " . $token);

    $userid = validateToken($token);

    if (!$userid) {
        error_log("Invalid or expired token");
        return $response->withStatus(401)->write(json_encode(array("status" => "fail", "data" => array("title" => "Invalid or expired token"))));
    }

    $servername = "localhost";
    $dbusername = "root";
    $dbpassword = "";
    $dbname = "library";

    try {
        $conn = new PDO("mysql:host=$servername;dbname=$dbname", $dbusername, $dbpassword);
        $conn->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);

        $stmt = $conn->prepare("SELECT collectionid, bookid, authorid FROM books_authors");
        $stmt->execute();
        $bookAuthors = $stmt->fetchAll(PDO::FETCH_ASSOC);

        if ($bookAuthors) {
            markTokenAsUsed($token);

            $newToken = generateToken($userid);

            return $response->write(json_encode(array("status" => "success", "token" => $newToken, "data" => $bookAuthors)));
        } else {
            return $response->write(json_encode(array("status" => "fail", "message" => "No book authors found")));
        }
    } catch (PDOException $e) {
        return $response->withStatus(500)->write(json_encode(array("status" => "fail", "message" => $e->getMessage())));
    }

    $conn = null;
});

$app->put('/book_author/update', function (Request $request, Response $response) {
    $data = json_decode($request->getBody());

    if (!isset($data->token)) {
        return $response->withStatus(401)->write(json_encode(array("status" => "fail", "data" => array("title" => "Token missing in payload"))));
    }

    if (!isset($data->collectionid)) {
        return $response->withStatus(400)->write(json_encode(array("status" => "fail", "data" => array("title" => "Collection ID missing in payload"))));
    }

    $token = $data->token;
    $useridFromToken = validateToken($token);

    if (!$useridFromToken) {
        return $response->withStatus(401)->write(json_encode(array("status" => "fail", "data" => array("title" => "Invalid or expired token"))));
    }

    $collectionidToUpdate = $data->collectionid;
    $bookid = $data->bookid;
    $authorid = $data->authorid;
    $servername = "localhost";
    $username = "root";
    $password = "";
    $dbname = "library";

    try {
        $conn = new PDO("mysql:host=$servername;dbname=$dbname", $username, $password);
        $conn->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);

        $sql = "UPDATE books_authors SET bookid = :bookid, authorid = :authorid WHERE collectionid = :collectionid";
        $stmt = $conn->prepare($sql);
        $stmt->bindParam(':bookid', $bookid);
        $stmt->bindParam(':authorid', $authorid);
        $stmt->bindParam(':collectionid', $collectionidToUpdate);
        $stmt->execute();

        markTokenAsUsed($token);

        $newToken = generateToken($useridFromToken);
        $response->getBody()->write(json_encode(array("status" => "success", "token" => $newToken, "data" => null)));
    } catch (PDOException $e) {
        $response->getBody()->write(json_encode(array("status" => "fail", "data" => array("title" => $e->getMessage()))));
    }

    $conn = null;
    return $response;
});

$app->delete('/book_author/delete', function (Request $request, Response $response) {
    $data = json_decode($request->getBody());

    if (json_last_error() !== JSON_ERROR_NONE) {
        error_log("JSON Error: " . json_last_error_msg());
        return $response->withStatus(400)->write(json_encode(array("status" => "fail", "data" => array("title" => "Invalid JSON payload"))));
    }

    if (!isset($data->token)) {
        return $response->withStatus(401)->write(json_encode(array("status" => "fail", "data" => array("title" => "Token missing in payload"))));
    }

    if (!isset($data->collectionid)) {
        return $response->withStatus(400)->write(json_encode(array("status" => "fail", "data" => array("title" => "Collection ID missing in payload"))));
    }

    $token = $data->token;
    $useridFromToken = validateToken($token);

    if (!$useridFromToken) {
        return $response->withStatus(401)->write(json_encode(array("status" => "fail", "data" => array("title" => "Invalid or expired token"))));
    }

    $collectionidToDelete = $data->collectionid;

    $servername = "localhost";
    $username = "root";
    $password = "";
    $dbname = "library";

    try {
        $conn = new PDO("mysql:host=$servername;dbname=$dbname", $username, $password);
        $conn->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);

        $sql = "DELETE FROM books_authors WHERE collectionid = :collectionid";
        $stmt = $conn->prepare($sql);
        $stmt->bindParam(':collectionid', $collectionidToDelete);
        $stmt->execute();

        markTokenAsUsed($token);

        $newToken = generateToken($useridFromToken);

        $response->getBody()->write(json_encode(array("status" => "success", "token" => $newToken, "data" => null)));
    } catch (PDOException $e) {
        $response->getBody()->write(json_encode(array("status" => "fail", "data" => array("title" => $e->getMessage()))));
    }

    $conn = null;
    return $response;
});

$app->run();
?>