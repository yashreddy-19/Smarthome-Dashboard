<?php
// filepath: c:\xampp\htdocs\project\signup.php
$servername = "localhost";
$username = "root"; // your MySQL username
$password = "";     // your MySQL password
$dbname = "smart_home";

$conn = new mysqli($servername, $username, $password, $dbname);
if ($conn->connect_error) {
  die("Connection failed: " . $conn->connect_error);
}

// Set Content-Type header to application/json
header('Content-Type: application/json');

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
  $username = $_POST['username'];
  $password = $_POST['password'];
  $password_hashed = password_hash($password, PASSWORD_DEFAULT); // Hash the password

  $stmt = $conn->prepare("INSERT INTO users (username, password) VALUES (?, ?)");
  if ($stmt === false) {
      echo json_encode(['error' => 'Prepare failed: ' . $conn->error]);
      $conn->close();
      exit;
  }
  $stmt->bind_param("ss", $username, $password_hashed);

  if ($stmt->execute()) {
    echo json_encode(['message' => 'User registered successfully.']);
  } else {
    echo json_encode(['error' => 'Execute failed: ' . $stmt->error]);
  }
    $stmt->close();
} else {
  echo json_encode(['error' => 'Invalid request method.']);
}

$conn->close();
?>