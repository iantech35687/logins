<?php
include 'db_config.php'; // Include database configuration

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    // Retrieve and sanitize input data
    $competency_name = trim($_POST['competency_name']);
    $description = trim($_POST['description']);
    $grade = trim($_POST['grade']);

    // Basic validation
    if (empty($competency_name) || empty($description) || empty($grade)) {
        echo "<script>alert('All fields are required.'); window.history.back();</script>";
        exit;
    }

    // Insert competency into database
    $stmt = $conn->prepare("INSERT INTO Competencies (competency_name, description, grade) VALUES (?, ?, ?)");
    $stmt->bind_param("sss", $competency_name, $description, $grade);

    if ($stmt->execute()) {
        echo "<script>alert('Competency created successfully!'); window.location.href = '../manage_competencies.html';</script>";
    } else {
        echo "<script>alert('Failed to create competency. Please try again.'); window.history.back();</script>";
    }

    $stmt->close();
}

$conn->close();
?>
