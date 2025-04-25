<?php
// Ensure session is started and configure session parameters
session_set_cookie_params([
    'lifetime' => 0, // Session lasts until the browser is closed
    'path' => '/',
    'secure' => false, // Set to true if using HTTPS
    'httponly' => true,
    'samesite' => 'Lax'
]);
session_start();

$servername = "localhost";
$username = "root"; // your MySQL username
$password = "";     // your MySQL password
$dbname = "smart_home";

$conn = new mysqli($servername, $username, $password, $dbname);
if ($conn->connect_error) {
    echo json_encode(["error" => "Database connection failed: " . $conn->connect_error]);
    exit;
}

if ($_SERVER['REQUEST_METHOD'] === 'GET') {
    $result = $conn->query("SELECT * FROM devices");
    if ($result) {
        $devices = [];
        while ($row = $result->fetch_assoc()) {
            $devices[] = $row;
        }
        echo json_encode($devices);
    } else {
        echo json_encode(["error" => "Failed to fetch devices: " . $conn->error]);
    }
}

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    // Only require login for device actions, not for login itself
    $publicActions = isset($_POST['action']) && $_POST['action'] === 'login';
    if (!$publicActions && (!isset($_SESSION['loggedin']) || $_SESSION['loggedin'] !== true)) {
        echo json_encode([
            "error" => "Unauthorized access. Please log in.",
            "debug" => $_SESSION // Debugging output to verify session variables
        ]);
        exit;
    }

    if (isset($_POST['id']) && isset($_POST['status'])) {
        // Validate input
        $id = filter_var($_POST['id'], FILTER_VALIDATE_INT);
        $status = filter_var($_POST['status'], FILTER_SANITIZE_STRING);

        if ($id === false || empty($status)) {
            echo json_encode(["error" => "Invalid input for updating device."]);
            exit;
        }

        // Update device status
        $stmt = $conn->prepare("UPDATE devices SET status = ? WHERE id = ?");
        $stmt->bind_param("si", $status, $id);
        if ($stmt->execute()) {
            echo json_encode(["message" => "Device updated successfully."]);
        } else {
            echo json_encode(["error" => "Failed to update device: " . $stmt->error]);
        }
    } elseif (isset($_POST['name']) && isset($_POST['type']) && isset($_POST['status'])) {
        // Validate input
        $name = filter_var($_POST['name'], FILTER_SANITIZE_STRING);
        $type = filter_var($_POST['type'], FILTER_SANITIZE_STRING);
        $status = filter_var($_POST['status'], FILTER_SANITIZE_STRING);

        if (empty($name) || empty($type) || empty($status)) {
            echo json_encode(["error" => "Invalid input for adding device."]);
            exit;
        }

        // Add a new device
        $stmt = $conn->prepare("INSERT INTO devices (name, type, status) VALUES (?, ?, ?)");
        $stmt->bind_param("sss", $name, $type, $status);
        if ($stmt->execute()) {
            echo json_encode(["message" => "Device added successfully."]);
        } else {
            echo json_encode(["error" => "Error adding device: " . $stmt->error]);
        }
    } elseif (isset($_POST['action']) && $_POST['action'] === 'removeDevice' && isset($_POST['id'])) {
        // Remove device section
        $id = filter_var($_POST['id'], FILTER_VALIDATE_INT);
        if ($id === false) {
            echo json_encode(["error" => "Invalid device ID."]);
            exit;
        }
        $stmt = $conn->prepare("DELETE FROM devices WHERE id = ?");
        $stmt->bind_param("i", $id);
        if ($stmt->execute()) {
            echo json_encode(["message" => "Device removed successfully."]);
        } else {
            echo json_encode(["error" => "Failed to remove device: " . $stmt->error]);
        }
    } elseif (isset($_POST['action']) && $_POST['action'] === 'login' && isset($_POST['username']) && isset($_POST['password'])) {
        // Validate input
        $username = filter_var($_POST['username'], FILTER_SANITIZE_STRING);
        $password = $_POST['password']; // Password is not sanitized to allow special characters

        if (empty($username) || empty($password)) {
            echo json_encode(["error" => "Invalid input for login."]);
            exit;
        }

        // Handle login
        try {
            $stmt = $conn->prepare("SELECT id, username, password FROM users WHERE username = ?");
            if ($stmt === false) {
                throw new Exception("Prepare failed: " . $conn->error);
            }
            $stmt->bind_param("s", $username);
            if (!$stmt->execute()) {
                throw new Exception("Execute failed: " . $stmt->error);
            }
            $result = $stmt->get_result();
            if ($result->num_rows > 0) {
                $row = $result->fetch_assoc();
                if (password_verify($password, $row['password'])) {
                    // Set session variables on successful login
                    $_SESSION['loggedin'] = true;
                    $_SESSION['username'] = $row['username'];
                    $_SESSION['user_id'] = $row['id'];

                    // Return user profile information
                    echo json_encode([
                        "message" => "Login successful.",
                        "profile" => [
                            "id" => $row['id'],
                            "username" => $row['username']
                        ]
                    ]);
                } else {
                    echo json_encode(["error" => "Invalid username or password."]);
                }
            } else {
                echo json_encode(["error" => "Invalid username or password."]);
            }
        } catch (Exception $e) {
            echo json_encode(["error" => "Login failed: " . $e->getMessage()]);
        }
    } elseif (isset($_POST['action']) && $_POST['action'] === 'signup' && isset($_POST['username']) && isset($_POST['password'])) {
        // Handle signup
        $username = filter_var($_POST['username'], FILTER_SANITIZE_STRING);
        $password = $_POST['password']; // Password is not sanitized to allow special characters

        if (empty($username) || empty($password)) {
            echo json_encode(["error" => "Invalid input for signup."]);
            exit;
        }

        // Check if username already exists
        $stmt = $conn->prepare("SELECT id FROM users WHERE username = ?");
        $stmt->bind_param("s", $username);
        $stmt->execute();
        $result = $stmt->get_result();
        if ($result->num_rows > 0) {
            echo json_encode(["error" => "Username already exists."]);
            exit;
        }

        // Hash the password
        $hashed_password = password_hash($password, PASSWORD_DEFAULT);

        // Insert the new user into the database
        $stmt = $conn->prepare("INSERT INTO users (username, password) VALUES (?, ?)");
        $stmt->bind_param("ss", $username, $hashed_password);

        if ($stmt->execute()) {
            echo json_encode(["message" => "Signup successful. Please log in."]);
        } else {
            echo json_encode(["error" => "Signup failed: " . $stmt->error]);
        }
    } elseif (isset($_POST['action']) && $_POST['action'] === 'logout') {
        // Handle logout
        session_unset();
        session_destroy();
        echo json_encode(["message" => "Logout successful."]);
    } else {
        echo json_encode(["error" => "Invalid POST request."]);
    }
}

$conn->close();
?>
