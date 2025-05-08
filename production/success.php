<?php
include_once 'config.php';
session_start();

if (isset($_SESSION['challenge_passed']) && $_SESSION['challenge_passed'] === true) {
  session_destroy();
  echo 'success';
} else {
  echo 'error';
}
?>