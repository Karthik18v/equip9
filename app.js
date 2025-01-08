const mysql = require("mysql2");
const express = require("express");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const dotenv = require("dotenv");
dotenv.config();

const app = express();
app.use(express.json());

const connection = mysql.createPool({
  host: process.env.DB_HOST,
  user: process.env.DB_USER,
  password: process.env.DB_PASSWORD,
  database: process.env.DB_NAME,
  connectionLimit: 10,
});


// Register API
app.post("/register", async (req, res) => {
  console.log(res.body);
  try {
    const { first_name, last_name, mobile, password } = req.body;

    if (!first_name || !last_name || !mobile || !password) {
      return res.status(400).json({ error: "All fields are required!" });
    }

    const saltRounds = 10;
    const hashedPassword = await bcrypt.hash(password, saltRounds);

    const sql = "CALL CreateUser(?, ?, ?, ?, ?)";

    connection.query(
      sql,
      [first_name, last_name, mobile, hashedPassword, "Admin"],
      (err, result) => {
        if (err) {
          console.error("MySQL Error:", err);
          return res.status(500).json({ error: "Database error" });
        }
        res.status(201).json({ message: "User registered successfully" });
      }
    );
  } catch (error) {
    console.error("Server Error:", error);
    res.status(500).json({ error: "Internal server error" });
  }
});

// login
// Login endpoint using stored procedure to get user by mobile
app.post("/login", (req, res) => {
  const { mobile, password } = req.body;

  if (!mobile || !password) {
    return res.status(400).json({ error: "Mobile and password are required!" });
  }

  const sql = "CALL GetUserByMobile(?)"; // Call the stored procedure
  connection.query(sql, [mobile], async (err, results) => {
    if (err) {
      console.error("Database Error:", err);
      return res.status(500).json({ error: "Database error" });
    }

    if (results[0].length === 0) {
      return res.status(404).json({ error: "User not found" });
    }

    const user = results[0][0]; // Get the first (and only) user from the result

    // Log the values for debugging
    console.log("Password:", password);
    console.log("Hashed Password:", user.password);

    // Check if password and hashed password are both valid
    if (!password || !user.password) {
      return res.status(400).json({ error: "Invalid credentials" });
    }

    // Compare hashed password with the submitted password
    try {
      const match = await bcrypt.compare(password, user.password);
      console.log(match);

      if (!match) {
        return res.status(400).json({ error: "Incorrect password" });
      }

      // Password matched, generate a token (e.g., using JWT)
      const token = jwt.sign(
        { id: user.id, mobile: user.mobile },
        "Karthik123",
        {
          expiresIn: "1h",
        }
      );

      res.status(200).json({ message: "Login successful", token });
    } catch (compareError) {
      console.error("Error comparing passwords:", compareError);
      return res.status(500).json({ error: "Password comparison failed" });
    }
  });
});

app.get("/users", async (req, res) => {
  const sql = "CALL GetAllUsers()";
  connection.query(sql, (err, results) => {
    if (err) {
      console.error("Database Error:", err);
      return res.status(500).json({ error: "Internal Server Error" });
    }

    // `results[0]` contains the actual data from the stored procedure
    res.status(200).json({ users: results[0] });
  });
});

app.put("/users/:id", (req, res) => {
  const userId = req.params.id;
  const { first_name, last_name, mobile, updated_by } = req.body;

  if (!userId || !first_name || !last_name || !mobile || !updated_by) {
    return res.status(400).json({ error: "All fields are required" });
  }

  const sql = "CALL UpdateUser(?, ?, ?, ?, ?)";

  connection.query(
    sql,
    [userId, first_name, last_name, mobile, updated_by],
    (err, results) => {
      if (err) {
        console.error("Database Error:", err);
        return res.status(500).json({ error: "Internal Server Error" });
      }

      // Check if the user was actually updated
      if (results.affectedRows === 0) {
        return res.status(404).json({ error: "User not found" });
      }

      res
        .status(200)
        .json({ message: `User with ID ${userId} updated successfully` });
    }
  );
});

app.delete("/users/:id", async (req, res) => {
  const userId = req.params.id;
  if (!userId) {
    return res.status(400).json({ error: "User ID is required" });
  }

  const sql = "CALL DeleteUser(?)";

  connection.query(sql, [userId], (err, results) => {
    if (err) {
      console.error("Database Error:", err);
      return res.status(500).json({ error: "Internal Server Error" });
    }

    // Check if the user was actually deleted (affected rows)
    if (results.affectedRows === 0) {
      return res.status(404).json({ error: "User not found" });
    }

    res
      .status(200)
      .json({ message: `User with ID ${userId} deleted successfully` });
  });
});

app.listen(4000, () => console.log(`Server Running At http://localhost:4000`));
