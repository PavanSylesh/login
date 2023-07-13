<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta http-equiv="X-UA-Compatible" content="IE=edge">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <link rel="stylesheet" href="css/employeeform.css"> 
    <title>Create Page</title>
    <script type="text/javascript" src = "js/validation.js"></script>
</head>
<body>
    <div class="container">
    <h1>Add Employee</h1>
	<form action="" method="POST">
		<label for="firstname">First Name:</label><br>
        <input type="text" name="firstname" id="firstname" required onblur="validateFirstName();"><br>
        <span id="fnameerr"></span><br>

		<label for="lastname">Last Name:</label><br>
		<input type="text" name="lastname" id = "lastname" required><br>

		<label for="email">Email Address:</label><br>
		<input type="email" name="email" id = "email" required><br>

        <label for="salary">salary:</label><br>
        <input type="number" id="salary" name="salary" required onblur="validateSalary();"><br>
        <span id="salaryerr"></span><br><br>

		<button type="submit" name="submit" >Add Employee</button>
	</form>
    </div>
</body>
</html>