<?php
$mysqli = new mysqli("localhost", "root", "", "test");

if ($mysqli->connect_error) {
    die("Connection failed: " . $mysqli->connect_error);
}
echo "Connected successfully";
?>
