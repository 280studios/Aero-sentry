<?php
// success.php - Success page

include_once 'config.php';
session_start();

if (isset($_SESSION['challenge_passed']) && $_SESSION['challenge_passed'] === true) {
  unset($_SESSION['challenge_passed']);
  unset($_SESSION['challenge_passed_expiry']);
  /* Sessions still set by server.php:
    $_SESSION['challenge_passed']
    $_SESSION['challenge_passed_expiry']
  */
} else {
  header('Location: index.html');
  exit();
}
unset($_SESSION['client_info']);  // Reset
?>

<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Passed!</title>
  <link rel="stylesheet" href="styles.css">
  <style>
    body {
      margin: 0;
      padding: 0;
      font-family: 'Roboto', 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
      background-color: #f4f7f6;
      display: flex;
      justify-content: center;
      align-items: center;
      min-height: 100vh;
      color: #333;
      line-height: 1.6;
    }

    .welcome-container {
      background-color: #ffffff;
      padding: 40px 50px;
      border-radius: 8px;
      box-shadow: 0 4px 15px rgba(0, 0, 0, 0.1);
      text-align: center;
      max-width: 500px;
      width: 90%;
    }

    .welcome-icon {
      color: #28a745;
      margin-bottom: 20px;
    }

    .welcome-heading {
      color: #2c3e50;
      margin-top: 0;
      margin-bottom: 15px;
      font-weight: 700;
    }

    .welcome-message {
      color: #555;
      margin-bottom: 30px;
      font-size: 1.1em;
      font-weight: 300;
    }

    .navigation-links ul {
      list-style: none;
      padding: 0;
      margin: 0;
    }

    .navigation-links li {
      margin-bottom: 15px;
    }

    .nav-link {
      display: block;
      padding: 12px 20px;
      border: 1px solid #ddd;
      border-radius: 5px;
      text-decoration: none;
      color: #3498db;
      background-color: #fff;
      font-weight: 400;
      transition: background-color 0.3s ease, color 0.3s ease, border-color 0.3s ease;
    }

    .nav-link:hover {
      background-color: #f8f9fa;
      border-color: #ccc;
      color: #2980b9;
    }

    .nav-link.primary-action {
      background-color: #3498db;
      color: #ffffff;
      border-color: #3498db;
      font-weight: 700;
    }

    .nav-link.primary-action:hover {
      background-color: #2980b9;
      border-color: #2980b9;
      color: #ffffff;
    }

    .nav-link.logout-link {
      color: #e74c3c;
      border-color: #e74c3c;
    }

    .nav-link.logout-link:hover {
      background-color: #e74c3c;
      color: #ffffff;
      border-color: #e74c3c;
    }

    @media (max-width: 600px) {
      .welcome-container {
        padding: 30px 25px;
      }

      .welcome-heading {
        font-size: 1.8em;
      }

      .welcome-message {
        font-size: 1em;
      }

      .nav-link {
        padding: 10px 15px;
      }
    }
  </style>
</head>
<body>

  <div class="welcome-container">
    <svg class="welcome-icon" xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="currentColor" width="64" height="64">
      <path fill-rule="evenodd" d="M2.25 12c0-5.385 4.365-9.75 9.75-9.75s9.75 4.365 9.75 9.75-4.365 9.75-9.75 9.75S2.25 17.385 2.25 12zm13.36-1.814a.75.75 0 10-1.22-.872l-3.236 4.53L9.53 12.22a.75.75 0 00-1.06 1.06l2.25 2.25a.75.75 0 001.14-.094l3.75-5.25z" clip-rule="evenodd" />
    </svg>

    <h1 class="welcome-heading">Welcome!</h1>
    <p class="welcome-message">You have successfully passed the challenge. What would you like to do next?</p>

    <nav class="navigation-links">
      <ul>
        <li><a href="#" class="nav-link primary-action">Next</a></li>
        <li><a href="#" class="nav-link logout-link">Exit</a></li>
        <li><a href="index.html" class="nav-link">Back</a></li>
      </ul>
    </nav>
  </div>

</body>
</html>