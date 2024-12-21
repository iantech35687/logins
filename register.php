<?php
include 'db_config.php'; // Include database configuration

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    // Retrieve and sanitize input data
    $username = trim($_POST['username']);
    $email = trim($_POST['email']);
    $password = trim($_POST['password']);
    $confirm_password = trim($_POST['confirm_password']);
    $role = trim($_POST['role']);

    // Additional fields based on role
    $school_name = isset($_POST['school_name']) ? trim($_POST['school_name']) : null;
    $student_name = isset($_POST['student_name']) ? trim($_POST['student_name']) : null;
    $school_registration = isset($_POST['school_registration']) ? trim($_POST['school_registration']) : null;

    // Basic validation
    if (empty($username) || empty($email) || empty($password) || empty($role)) {
        echo "<script>alert('All required fields must be filled.'); window.history.back();</script>";
        exit;
    }

    if (!filter_var($email, FILTER_VALIDATE_EMAIL)) {
        echo "<script>alert('Invalid email address.'); window.history.back();</script>";
        exit;
    }

    if ($password !== $confirm_password) {
        echo "<script>alert('Passwords do not match.'); window.history.back();</script>";
        exit;
    }

    // Hash the password
    $hashed_password = password_hash($password, PASSWORD_BCRYPT);

    // Prepare SQL query based on role
    $stmt = null;

    if ($role === 'administrator') {
        if (empty($school_registration)) {
            echo "<script>alert('School registration name is required for administrators.'); window.history.back();</script>";
            exit;
        }
        $stmt = $conn->prepare("INSERT INTO Users (username, email, password, role, school_registration) VALUES (?, ?, ?, ?, ?)");
        $stmt->bind_param("sssss", $username, $email, $hashed_password, $role, $school_registration);
    } elseif ($role === 'teacher' || $role === 'student') {
        if (empty($school_name)) {
            echo "<script>alert('School name is required for teachers and students.'); window.history.back();</script>";
            exit;
        }
        $stmt = $conn->prepare("INSERT INTO Users (username, email, password, role, school_name) VALUES (?, ?, ?, ?, ?)");
        $stmt->bind_param("sssss", $username, $email, $hashed_password, $role, $school_name);
    } elseif ($role === 'parent') {
        if (empty($student_name)) {
            echo "<script>alert('Student name is required for parents.'); window.history.back();</script>";
            exit;
        }
        $stmt = $conn->prepare("INSERT INTO Users (username, email, password, role, student_name) VALUES (?, ?, ?, ?, ?)");
        $stmt->bind_param("sssss", $username, $email, $hashed_password, $role, $student_name);
    } else {
        echo "<script>alert('Invalid role selected.'); window.history.back();</script>";
        exit;
    }

    // Execute query
    if ($stmt->execute()) {
        echo "<script>alert('Registration successful!'); window.location.href = '../login.html';</script>";
    } else {
        echo "<script>alert('Registration failed. Please try again.'); window.history.back();</script>";
    }

    $stmt->close();
}

$conn->close();
?>
