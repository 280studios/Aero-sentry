<!-- session.php - Used for debugging session -->
<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>session.php</title>
  <style>
    body {
      font-family: Arial, sans-serif;
      background-color:rgb(208, 223, 227);
      display: flex;
      flex-direction: column;
      align-items: center;
      font-size: 1.1em;
      height: 100vh;
    }
  </style>
</head>
<body>
  <?php
    session_start();

    if (isset($_SESSION)) {
        // Display the session results
        echo "<h1>Session Results</h1>";
        echo "<pre>";
        print_r($_SESSION);
        echo "</pre>";
        echo "<br>";
    } else {
        echo "No session data available.";
    }

    echo "IP: " . $_SERVER['REMOTE_ADDR'];
  ?>
</body>
</html>