<?php

//Keluar jika nama belum diinput user jika kosong (empty)
if (empty($_POST["name"])) {
    die("Name is required");
}

//Agar user memasukkan email yang valid
if ( ! filter_var($_POST["email"], FILTER_VALIDATE_EMAIL)) {
    die("Valid email is required");
}

//Kondisi terjadi jika inputan password kurang dari 8 karakter
if (strlen($_POST["password"]) < 8) {
    die("Password must be at least 8 characters");
}

//Kondisi terjadi jika password tidak terdiri atas huruf
if ( ! preg_match("/[a-z]/i", $_POST["password"])) {
    die("Password must contain at least one letter");
}

//Kondisi terjadi jika password tidak terdiri atas angka
if ( ! preg_match("/[0-9]/", $_POST["password"])) {
    die("Password must contain at least one number");
}

//Kondisi terjadi jika password tidak sama dengan yang inputan diatasnya
if ($_POST["password"] !== $_POST["password_confirmation"]) {
    die("Passwords must match");
}

//Password hash digunakan agar password dapat tersimpan dengan aman
$password_hash = password_hash($_POST["password"], PASSWORD_DEFAULT);

$mysqli = require __DIR__ . "/database.php";

$sql = "INSERT INTO user (name, email, password_hash)
        VALUES (?, ?, ?)";
        
$stmt = $mysqli->stmt_init();

if ( ! $stmt->prepare($sql)) {
    die("SQL error: " . $mysqli->error);
}

$stmt->bind_param("sss",
                  $_POST["name"],
                  $_POST["email"],
                  $password_hash);
                  
if ($stmt->execute()) {

    header("Location: signup-success.html");
    exit;
    
} else {
    
    if ($mysqli->errno === 1062) {
        die("email already taken");
    } else {
        die($mysqli->error . " " . $mysqli->errno);
    }
}








