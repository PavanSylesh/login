<?php
session_start();

require 'config.php';

$id = $_GET['id'];

$query = "SELECT * FROM employees WHERE id = '$id'";
$result = $conn->query($query);
$row = $result->fetch_assoc();
?>

<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta http-equiv="X-UA-Compatible" content="IE=edge">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <link rel="stylesheet" href="css/update.css"> 
    <title>Update Page</title>
</head>
<body>

<form  action="" method="POST">
    <div class="container">
    <div class="form-group">
        <label for="firstname">First Name:</label><br>
        <input value="<?php echo $row['firstname']; ?>" type="text" name="firstname" required><br>
        <label for="lastname">Last Name:</label><br>
        <input value="<?php echo $row['lastname']; ?>" type="text" name="lastname" required><br>
        <label for="email">Email Address:</label><br>
        <input value="<?php echo $row['email']; ?>" type="email" name="email" required><br>
        <input type="submit" name="update" value="Save">
        <button class = 'btn'><a href="view.php">Back</a></button>
    </div>
    </div>
</form>
</body>
</html>

<?php
if (isset($_POST['update'])) {

    $first_name = $_POST['firstname'];
    $last_name = $_POST['lastname'];
    $email = $_POST['email'];

    $sql = "UPDATE employees SET firstname = '$first_name',lastname = '$last_name',email = '$email' WHERE id = '$id'"; 

    $result = $conn->query($sql);

    if ($result === true) {
        $_SESSION['message'] = "Information saved successfully.";
        header("Location: view.php");
        exit();
    } else {
        echo 'Error';
    }
}
$conn->close();


?>
