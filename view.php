<?php
session_start();
    require 'config.php';
    if(isset($_SESSION["loggedin"])&& ($_SESSION["loggedin"]=== true)){
        if(time()- $_SESSION["login_time_stamp"]>5){
            session_unset();
            session_destroy();
            header("Location:login.php");
        }
    }
    else {
        header("Location:login.php");
    }
?>

<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta http-equiv="X-UA-Compatible" content="IE=edge">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <link rel="stylesheet" type="text/css" href="css/view.css">
    <title>View Page</title>
</head>
<body>
    <div class="container">
    <table class='table'>
    <tr>
        <th>ID</th>
        <th>First Name</th>
        <th>Last Name</th>
        <th>Email</th>
        <th>Salary</th>
        <th colspan= 2 >Action</th>
    </tr>

    <?php
    $query= "SELECT * from employees";
    $result = $conn->query($query);

    while ($row = $result->fetch_assoc()) {

        ?>

    <tr>
        <td><?php echo $row['id'];  ?></td>
        <td><?php echo $row['firstname'];  ?></td>
        <td><?php echo $row['lastname'];  ?></td>
        <td><?php echo $row['email'];  ?></td>
        <td><a href="update.php?id=<?php echo $row['id'];?>">EDIT</a></td>
        <td><a href="delete.php?id=<?php echo $row['id'];?>">DELETE</a></td>
    </tr>
    <?php } ?>
    </table>
    </div>
    <a href="logout.php" >Sign Out of Your Account</a>
</body>
</html>