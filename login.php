<?php
// Enable error reporting for debugging
error_reporting(E_ALL);
ini_set('display_errors', 1);

// Start session
session_start();

// Database connection
$servername = "localhost";
$username = "root";
$port = "3306";
$password = "bhupin123";
$dbname = "elearning";

$conn = new mysqli($servername, $username, $password, $dbname);

// Check connection
if ($conn->connect_error) {
    die("Connection failed: " . $conn->connect_error);
}

// Check if form is submitted
if ($_SERVER["REQUEST_METHOD"] == "POST") {
    // Get form data and sanitize it
    $email = trim($_POST['email']);
    $password = trim($_POST['password']);

    // Check if user exists
    $stmt = $conn->prepare("SELECT id, name, password FROM users WHERE email = ?");
    $stmt->bind_param("s", $email);
    $stmt->execute();
    $stmt->store_result();

    // If user exists, verify the password
    if ($stmt->num_rows > 0) {
        $stmt->bind_result($user_id, $name, $hashed_password);
        $stmt->fetch();

        if (password_verify($password, $hashed_password)) {
            // Store user details in session
            $_SESSION["user_id"] = $user_id;
            $_SESSION["user_name"] = $name;
            $_SESSION["email"] = $email;

            echo "Login successful! Redirecting...";
            header("refresh:2;url=dashboard.php"); // Redirect to dashboard after 2 seconds
            exit();
        } else {
            echo "Error: Incorrect password!";
        }
    } else {
        echo "Error: No user found with this email!";
    }

    $stmt->close();
}

// Close the database connection
$conn->close();
?>
