const express = require("express");
const multer = require("multer");
const mysql = require("mysql");
const path = require("path");
const fs = require("fs");
const cors = require("cors");
const xlsx = require("xlsx");
const nodemailer = require("nodemailer");
const crypto = require("crypto");
const app = express();
const session = require("express-session");
const MySQLStore = require("express-mysql-session")(session);
require("dotenv").config();


app.use(express.json());
app.use(
  cors({
    origin: "http://server-jodp.onrender.com", // Allow requests only from your frontend
    credentials: true, 
  })
);
app.use("/uploads", express.static("uploads"));

// Setup MySQL Connection
const dbOptions = {
  host: process.env.DB_HOST,
  user: process.env.DB_USER,
  password: process.env.DB_PASSWORD,
  database: process.env.DB_NAME,
  port: process.env.DB_PORT,
  charset: "utf8mb4",
};

// Connect to MySQL
const db = mysql.createConnection(dbOptions);
db.connect((err) => {
  if (err) console.error("MySQL connection failed:", err);
  else console.log("Connected to MySQL");
});

// Initialize session store
const sessionStore = new MySQLStore(dbOptions);

// Middleware
app.use(
  session({
    key: "session_cookie_name",
    secret: process.env.SESSION_SECRET || "supersecret",
    store: sessionStore, // ✅ properly initialized
    resave: false,
    saveUninitialized: false,
    cookie: { secure: false }, // true if using HTTPS
  })
);

app.get("/", (req, res) => {
  res.send("✅ Backend is running on Render!");
});



//CHECKING FOR ERROR IN EVENT POSTING
// app.post("/events", (req, res) => {
//   const { content, latitude, longitude } = req.body;
//   const userId = req.session.user.id;

//   if (!content || !latitude || !longitude) {
//     return res.status(400).json({ error: "All fields are required" });
//   }

//   const sql = "INSERT INTO events (content, latitude, longitude) VALUES (?, ?, ?)";
//   db.query(sql, [content, latitude, longitude], (err, result) => {
//     if (err) {
//       console.error("Failed to insert event:", err);
//       return res.status(500).json({ error: "Database error" });
//     }

//     const eventId = result.insertId;
//     const notifMessage = "A new event has been posted.";

//     const notifSql = "INSERT INTO notifications (type, message, related_id, user_id, created_at) VALUES (?, ?, ?, ?, NOW())";
//     db.query(notifSql, ["event", notifMessage, eventId, userId || null], (notifErr) => {
//       if (notifErr) {
//         console.error("Failed to insert event notification:", notifErr);
//         // Don't block the response if notification fails
//       }

//       res.json({ id: eventId, content, latitude, longitude });
//     });
//   });
// });


// Fetch events from database
app.get("/events", (req, res) => {
  db.query("SELECT * FROM events ORDER BY id DESC", (err, results) => {
    if (err) {
      console.error("Failed to fetch events:", err);
      return res.status(500).json({ error: "Database error" });
    }
    res.json(results);
  });
});



app.get("/api/users", (req, res) => {
  const getAlumniQuery = "SELECT * FROM alumni WHERE role = 'alumni'";
  db.query(getAlumniQuery, (err, results) => {
      if (err) {
          console.error("Error fetching alumni users:", err);
          return res.status(500).json({ message: "Database error" });
      }
      res.json(results);
  });
});




app.get("/api/users/:id", (req, res) => {
  const userId = req.params.id;

  const getUserQuery = "SELECT * FROM alumni WHERE id = ?";
  db.query(getUserQuery, [userId], (err, results) => {
    if (err) {
      console.error("Error fetching user:", err);
      return res.status(500).json({ message: "Database error" });
    }

    if (results.length === 0) {
      return res.status(404).json({ message: "User not found" });
    }

    res.json(results[0]); // return single user object
  });
});

// Configure Multer
const profilestorage = multer.diskStorage({
  destination: (req, file, cb) => {
    const uploadPath = path.join(__dirname, 'uploads');
    cb(null, uploadPath);
  },
  filename: (req, file, cb) => {
    const uniqueName = `${Date.now()}-${file.originalname}`;
    cb(null, uniqueName);
  },
});

const profileupload = multer({ storage: profilestorage });
// Update User and Handle Email Change
app.put("/api/users/:id", profileupload.single('profile'), (req, res) => {
  const { id } = req.params;
  const { name, middlename, lastname, email, password } = req.body;
  const profile = req.file ? `/uploads/${req.file.filename}` : null;

  if (!name || !lastname || !email) {
    return res.status(400).json({ message: "Name, Lastname, and Email are required" });
  }

  const selectQuery = "SELECT password, email, profile FROM alumni WHERE id = ?";
  db.query(selectQuery, [id], async (err, results) => {
    if (err) return res.status(500).json({ message: "Database error" });
    if (results.length === 0) return res.status(404).json({ message: "User not found" });

    const user = results[0];

    if (email !== user.email) {
      if (!password) {
        return res.status(400).json({ message: "Password is required to confirm email change" });
      }

      const passwordMatch = await bcrypt.compare(password, user.password);
      if (!passwordMatch) {
        return res.status(401).json({ code: "INVALID_PASSWORD", message: "Incorrect password" });
      }

      const verificationCode = generateVerificationCode();
      const expirationTime = new Date(Date.now() + 3600000); // 1 hour

      const insertQuery = "INSERT INTO email_verifications (user_id, email, code, expires_at) VALUES (?, ?, ?, ?)";
      db.query(insertQuery, [id, email, verificationCode, expirationTime], (err) => {
        if (err) return res.status(500).json({ message: "Failed to store verification code" });

        sendVerificationCode(email, verificationCode, res);
      });
    } else {
      const finalProfile = profile || user.profile;
      const updateQuery = "UPDATE alumni SET first_name = ?, middle_name = ?, last_name = ?, profile = ? WHERE id = ?";
      db.query(updateQuery, [name, middlename, lastname, finalProfile, id], (err) => {
        if (err) return res.status(500).json({ message: "Invalid input! Please check the form and try again." });
        res.json({ message: "User updated successfully", profile: finalProfile });
      });
    }
  });
});


// Confirm Email Route
app.post('/confirm-email', (req, res) => {
  const { code, userId } = req.body;

  if (!code || !userId) {
    return res.status(400).json({ message: "Code and User ID are required" });
  }

  const selectCodeQuery = "SELECT email FROM email_verifications WHERE user_id = ? AND code = ? AND expires_at > NOW()";
  db.query(selectCodeQuery, [userId, code], (err, results) => {
    if (err) return res.status(500).json({ message: "Internal server error" });
    if (results.length === 0) {
      return res.status(400).json({ message: "Invalid or expired code" });
    }

    const { email } = results[0];
    const updateQuery = "UPDATE alumni SET email = ? WHERE id = ?";

    db.query(updateQuery, [email, userId], (err, result) => {
      if (err) return res.status(500).json({ message: "Failed to update email" });
      if (result.affectedRows === 0) return res.status(404).json({ message: "No user found to update" });
      res.json({ message: "✅ Email verified successfully! You can now log in with your new email." });
    });
  });
});

// Helper function to send email
function sendVerificationCode(email, code, res) {
  const transporter = nodemailer.createTransport({
    service: "gmail",
    auth: {
      user: "jaymarkobaran18@gmail.com",
      pass: "dzwvjlwmkjmmkqed",
    },
  });

  const mailOption = {
    from: "memotrace@gmail.com",
    to: email,
    subject: 'Confirm your email change',
    text: `Your verification code is: ${code}`
  };

  transporter.sendMail(mailOption, (error) => {
    if (error) return res.status(500).json({ message: "Failed to send verification email" });
    res.json({ message: "Verification code sent. Please check your email to get the verification code." });
  });
}

// Helper function to generate verification code
function generateVerificationCode() {
  return Math.floor(100000 + Math.random() * 900000).toString();
}


// Change Password Route
app.put("/api/users/:id/change-password", async (req, res) => {
  const { id } = req.params;
  const { currentPassword, newPassword } = req.body;

  if (!currentPassword || !newPassword) {
    return res.status(400).json({ message: "All fields are required." });
  }

  try {
    // Fetch user from database
    const selectQuery = "SELECT password FROM alumni WHERE id = ?";
    db.query(selectQuery, [id], async (err, results) => {
      if (err) return res.status(500).json({ message: "Database error" });
      if (results.length === 0) return res.status(404).json({ message: "User not found" });

      const user = results[0];

      // Compare current password with hashed password
      const passwordMatch = await bcrypt.compare(currentPassword, user.password);
      if (!passwordMatch) {
        return res.status(401).json({ code: "INVALID_PASSWORD", message: "Incorrect password" });
      }

      // Hash new password before storing
      const hashedPassword = await bcrypt.hash(newPassword, 10);

      // Update password in database
      const updateQuery = "UPDATE alumni SET password = ? WHERE id = ?";
      db.query(updateQuery, [hashedPassword, id], (err) => {
        if (err) return res.status(500).json({ message: "Database error" });

        res.status(200).json({ message: "Password updated successfully." });
      });
    });
  } catch (error) {
    console.error("Error updating password:", error);
    res.status(500).json({ message: "Internal server error." });
  }
});

app.put("/api/users/:id/change-userpassword", async (req, res) => {
  const { id } = req.params;
  const { currentPassword, newPassword } = req.body;

  if (!currentPassword || !newPassword) {
    return res.status(400).json({ message: "All fields are required." });
  }

  const COOLDOWN_DURATION = 5 * 60 * 1000; // 5 minutes in milliseconds

  // Check cooldown before proceeding
  const userAttempts = failedAttempts[id];
  const now = Date.now();

  if (userAttempts && userAttempts.cooldownUntil && now < userAttempts.cooldownUntil) {
    const remaining = Math.ceil((userAttempts.cooldownUntil - now) / 1000);
    return res.status(429).json({
      code: "COOLDOWN_ACTIVE",
      message: `Too many failed attempts. Please try again in ${remaining} seconds.`,
    });
  }

  try {
    const selectQuery = "SELECT password, email FROM alumni WHERE id = ?";
    db.query(selectQuery, [id], async (err, results) => {
      if (err) return res.status(500).json({ message: "Database error" });
      if (results.length === 0) return res.status(404).json({ message: "User not found" });

      const user = results[0];

      const passwordMatch = await bcrypt.compare(currentPassword, user.password);
      if (!passwordMatch) {
        // Initialize tracking if not yet set
        if (!failedAttempts[id]) {
          failedAttempts[id] = { attempts: 1 };
        } else {
          failedAttempts[id].attempts += 1;
        }

        // Trigger cooldown and email alert if 3 failed attempts
        if (failedAttempts[id].attempts >= 3) {
          failedAttempts[id].cooldownUntil = Date.now() + COOLDOWN_DURATION;
          sendFailedAttemptAlert(user.email);
          failedAttempts[id].attempts = 0; // Reset attempts after alert
        }

        return res.status(401).json({
          code: "INVALID_PASSWORD",
          message: "Incorrect password",
        });
      }

      // On success, reset attempt and cooldown
      failedAttempts[id] = null;

      const hashedPassword = await bcrypt.hash(newPassword, 10);
      const updateQuery = "UPDATE alumni SET password = ? WHERE id = ?";
      db.query(updateQuery, [hashedPassword, id], (err) => {
        if (err) return res.status(500).json({ message: "Database error" });

        res.status(200).json({ message: "Password updated successfully." });
      });
    });
  } catch (error) {
    console.error("Error updating password:", error);
    res.status(500).json({ message: "Internal server error." });
  }
});

// In-memory tracking of failed attempts (use database for persistence in production)
const failedAttempts = {};

// Email alert sender
function sendFailedAttemptAlert(email) {
  const transporter = nodemailer.createTransport({
    service: "gmail",
    auth: {
      user: "jaymarkobaran18@gmail.com",
      pass: "dzwvjlwmkjmmkqed", // use environment variable in production
    },
  });

  const mail = {
    from: "memotrace@gmail.com",
    to: email,
    subject: "Security Alert: Multiple Failed Password Attempts",
    text: `There have been 3 unsuccessful attempts to change your password on your MEMOTRACE account. If this wasn't you, please secure your account immediately.`,
  };

  transporter.sendMail(mail, (error, info) => {
    if (error) {
      console.error("Email sending error:", error);
    } else {
      console.log("Alert email sent:", info.response);
    }
  });
}

function sendPasswordResetCode(email, code, res) {
  const transporter = nodemailer.createTransport({
    service: "gmail",
    auth: {
      user: "jaymarkobaran18@gmail.com",
      pass: "dzwvjlwmkjmmkqed", // Consider using environment variables instead of hardcoding
    },
  });

  const mailOptions = {
    from: "memotrace@gmail.com",
    to: email,
    subject: "Password Reset Verification Code",
    text: `You have requested to reset your password.\n\nYour verification code is: ${code}\n\nIf you did not request this, please ignore this email.`,
  };

  transporter.sendMail(mailOptions, (error) => {
    if (error) {
      console.error("Error sending password reset email:", error);
      return res.status(500).json({ message: "Failed to send password reset email." });
    }
    res.json({ message: "Password reset code sent. Please check your email." });
  });
}

app.post("/api/send-code", (req, res) => {
  const { email } = req.body;
  if (!email) return res.status(400).json({ message: "Email is required" });

  const verificationCode = Math.floor(100000 + Math.random() * 900000).toString(); // 6-digit code
  const expirationTime = new Date(Date.now() + 10 * 60 * 1000); // expires in 10 mins

  const getUserQuery = "SELECT id FROM alumni WHERE email = ?";
  db.query(getUserQuery, [email], (err, results) => {
    if (err) {
      console.error("Database error:", err);
      return res.status(500).json({ message: "Internal server error" });
    }

    if (results.length === 0) {
      return res.status(404).json({ message: "Email not found" });
    }

    const userId = results[0].id;

    const insertQuery = `
      INSERT INTO password_resets (user_id, email, code, expires_at)
      VALUES (?, ?, ?, ?)
    `;
    db.query(insertQuery, [userId, email, verificationCode, expirationTime], (err) => {
      if (err) {
        console.error("Error inserting code into DB:", err);
        return res.status(500).json({ message: "Failed to store verification code" });
      }

      // Use your email function to send the code
      sendPasswordResetCode(email, verificationCode, res);
    });
  });
});

// POST /api/verify-code
app.post("/api/verify-code", (req, res) => {
  const { email, code } = req.body;

  if (!email || !code) {
    return res.status(400).json({ message: "Email and code are required" });
  }

  const checkQuery = `
    SELECT * FROM password_resets
    WHERE email = ? AND code = ? AND expires_at > NOW()
    ORDER BY created_at DESC LIMIT 1
  `;

  db.query(checkQuery, [email, code], (err, results) => {
    if (err) return res.status(500).json({ message: "Database error" });

    if (results.length === 0) {
      return res.status(400).json({ message: "Invalid or expired verification code" });
    }

    res.json({ message: "Code verified successfully" });
  });
});


app.post("/api/reset-password", async (req, res) => {
  const { email, password } = req.body;

  if (!email || !password)
    return res.status(400).json({ message: "Email and password are required" });

  try {
    const hashedPassword = await bcrypt.hash(password, 10);

    const updateQuery = `UPDATE alumni SET password = ? WHERE email = ?`;
    db.query(updateQuery, [hashedPassword, email], (err, result) => {
      if (err) {
        console.error("Error updating password:", err);
        return res.status(500).json({ message: "Failed to update password" });
      }

      if (result.affectedRows === 0) {
        return res.status(404).json({ message: "User not found" });
      }

      res.json({ message: "Password updated successfully" });
    });
  } catch (err) {
    console.error("Hashing error:", err);
    res.status(500).json({ message: "Server error" });
  }
});
// this is for user acction creatiom
const bcrypt = require("bcryptjs");
app.post("/api/register", async (req, res) => {
  try {
    const {
      firstName,
      middleName,
      lastName,
      email,
      alumniCardNumber,
      gender,
      yearGraduate,
      course,
      workTitle,
      address,
      password,
      privacyPolicyAccepted,
      mobileNumber,
      civilStatus,
      birthday,
      regionOfOrigin,
      province,
      locationResidence,
      role, // New field
    } = req.body;

    if (!firstName || !lastName || !email || !password || !alumniCardNumber || !privacyPolicyAccepted) {
      return res.status(400).json({ message: "All required fields must be filled" });
    }

    // Check if Alumni Card Number exists in alumni_ids list
    const checkAlumniIDQuery = "SELECT * FROM alumni_ids WHERE alumni_id = ?";
    db.query(checkAlumniIDQuery, [alumniCardNumber], async (err, result) => {
      if (err) {
        console.error("Database error:", err);
        return res.status(500).json({ message: "Make Sure your information is correct" });
      }

      if (result.length === 0) {
        return res.status(400).json({ message: "Invalid Alumni Card Number" });
      }

      // 🔹 Check if Alumni Card Number already registered in alumni table
      const checkDuplicateQuery = "SELECT * FROM alumni WHERE alumni_card_number = ?";
      db.query(checkDuplicateQuery, [alumniCardNumber], async (dupErr, dupResult) => {
        if (dupErr) {
          console.error("Database error:", dupErr);
          return res.status(500).json({ message: "Database error while checking duplicates" });
        }

        if (dupResult.length > 0) {
          return res.status(400).json({ message: "Invalid input. Please verify the form. Alumni Card Number not accepted." });
        }

        // Generate verification token
        const verificationToken = crypto.randomBytes(32).toString("hex");

        // Hash Password
        const hashedPassword = await bcrypt.hash(password, 10);

        // Set role (default to 'alumni' if not provided)
        const userRole = role && role === "admin" ? "admin" : "alumni";

        // Insert user into database
        const insertQuery = `
          INSERT INTO alumni (
            first_name, middle_name, last_name, email, alumni_card_number,
            gender, year_graduate, course, work_title, address, password,
            verification_token, privacy_policy_accepted, mobileNumber,
            civilStatus, birthday, regionOfOrigin, province, locationResidence, role
          ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`;

        db.query(
          insertQuery,
          [
            firstName, middleName, lastName, email, alumniCardNumber,
            gender, yearGraduate, course, workTitle, address,
            hashedPassword, verificationToken, privacyPolicyAccepted,
            mobileNumber, civilStatus, birthday, regionOfOrigin,
            province, locationResidence, userRole,
          ],
          (insertErr) => {
            if (insertErr) {
              console.error("Error inserting user:", insertErr);
              return res.status(500).json({ message: "Invalid input! Please check the form and try again." });
            }

            sendVerificationEmail(email, verificationToken);
            res.json({ message: "Registration successful. Please verify your email." });
          }
        );
      });
    });
  } catch (error) {
    console.error("Server error:", error);
    res.status(500).json({ message: "Server error" });
  }
});


// ✅ Verify Email API
app.get("/api/verify-email", (req, res) => {
  const { token } = req.query; // Get token from query parameters

  if (!token) {
    return res.status(400).send("Missing verification token");
  }

  const sql = "UPDATE alumni SET is_verified = 1 WHERE verification_token = ?";
  db.query(sql, [token], (err, result) => {
    if (err) {
      console.error("Database error:", err);
      return res.status(500).send("Database error");
    }

    if (result.affectedRows === 0) {
      return res.status(400).send("Invalid or expired token");
    }

    // ✅ Clear the verification token after successful verification
    const clearTokenSql = "UPDATE alumni SET verification_token = NULL WHERE verification_token = ?";
    db.query(clearTokenSql, [token], (clearErr) => {
      if (clearErr) {
        console.error("Error clearing token:", clearErr);
      }
      // continue anyway
    });

    // ✅ Redirect to login page after verification
    res.redirect("http://server-jodp.onrender.com/login"); 
    // 🔹 Change to your frontend login URL when deployed
  });
});



function sendVerificationEmail(email, token) {
  const transporter = nodemailer.createTransport({
      service: "gmail",
      auth: {
          user: "jaymarkobaran18@gmail.com",
          pass: "dzwvjlwmkjmmkqed",
      },
  });

  const mail = {
      from: "memotrace@gmail.com",
      to: email,
      subject: "Verify Your Email",
      text: `Click the link to verify your Memotrace email account: http://localhost:5000/api/verify-email?token=${token}`,
  };

  transporter.sendMail(mail, (error, info) => {
    if (error) {
        console.error("Email sending error:", error);
    } else {
        console.log("Email sent: ", info.response);
    }
});
} 




app.use(
  session({
    secret: "memo_trace",
    resave: false,
    saveUninitialized: false,
    cookie: {
      secure: false, // Set to `true` if using HTTPS
      httpOnly: true,
      sameSite: "lax"
    }
  })
);

app.post("/api/login", (req, res) => {
  const { email, password } = req.body;

  const sql = "SELECT * FROM alumni WHERE email = ?";

  db.query(sql, [email], async (err, result) => {
    if (err) {
      console.error("Database error:", err);
      return res.status(500).json({ message: "Database error" });
    }

    if (result.length === 0) {
      return res.status(400).json({ message: "Invalid email or password" });
    }

    const user = result[0];

    if (user.is_verified === 0) {
      return res.status(400).json({ message: "Email not verified. Please check your email.", is_verified: 0 });
    }

    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch) {
      return res.status(400).json({ message: "Invalid email or password" });
    }

    // Store user session
    req.session.user = {
      id: user.id,
      profile:user.profile,
      email: user.email,
      name: `${user.first_name}`, 
      middlename: `${user.middle_name}`,
      lastname: `${user.last_name}`,
      gender: user.gender,
      course: user.course,
      work: user.work_title,
      yeargraduate: user.year_graduate,
      address: user.address,
      role: user.role,
      has_submitted_survey: user.has_submitted_survey,
      isGTSsurvey: user.isGTSsurvey,
    };

    res.json({
      message: "Login successful",
      is_verified: user.is_verified,
      user: req.session.user,
    });
  });
});

app.get("/api/session", (req, res) => {
  if (req.session.user) {
    res.json({ user: req.session.user });
  } else {
    res.status(401).json({ message: "No active session" });
  }
}); 

app.get("/user", (req, res) => {
  if (!req.session.user) {
    return res.status(401).json({ message: "Not logged in" });
  }
  res.json({ user: req.session.user });
});




app.post("/api/logout", (req, res) => {
  req.session.destroy((err) => {
    if (err) {
      return res.status(500).json({ message: "Logout failed" });
    }
    res.json({ message: "Logout successful" });
  });
});
// Get logged-in user
app.get("/api/user", (req, res) => {
  if (!req.session.user) return res.status(401).json({ error: "Not logged in" });
  res.json(req.session.user);
});
// get the user data
app.get("/api/profile", (req, res) => {
  if (!req.session.user || !req.session.user.id) {
    return res.status(401).json({ error: "Not logged in" });
  }

  const userId = req.session.user.id;

  const getUserQuery = "SELECT * FROM alumni WHERE id = ?";
  db.query(getUserQuery, [userId], (err, results) => {
    if (err) {
      console.error("Database error:", err);
      return res.status(500).json({ error: "Database error" });
    }

    if (results.length === 0) {
      return res.status(404).json({ error: "User not found" });
    }

    res.json(results[0]); // return fresh user data from DB
  });
});

app.post("/api/posts", (req, res) => {
  if (!req.session.user) return res.status(401).json({ error: "Unauthorized" });

  const { content } = req.body;
  const userId = req.session.user.id;
  
  const postSql = "INSERT INTO posts (user_id, content) VALUES (?, ?)";
  db.query(postSql, [userId, content], (error, result) => {
    if (error) {
      console.error("❌ Error creating post:", error.sqlMessage || error);
      return res.status(500).json({ error: "Internal Server Error" });
    }

    const newPostId = result.insertId;
    const message = `created a new JOB POST`;

    const notifSql = "INSERT INTO notifications (type, message, related_id, user_id, created_at) VALUES (?, ?, ?, ?, NOW())";
    db.query(notifSql, ["post", message, newPostId, userId], (notifErr) => {
      if (notifErr) {
        console.error("❌ Error creating notification:", notifErr.sqlMessage || notifErr);
      }

      res.status(201).json({ 
        id: newPostId,
        user_id: userId,
        content,
        date_posted: new Date()
      });
    });
  });
});


app.get("/api/notifications", (req, res) => {
  const currentUserId = req.session.user?.id;

  const sql = `
    SELECT 
      n.id,
      n.type,
      n.message,
      n.related_id,
      n.created_at,
      u.first_name,
      u.profile,
      y.yearbook_name,
      yi.file_path AS yearbook_image,
      p.content AS post_content,
      e.content AS event_content,
      e.location_name AS event_location,
      e.images AS event_images
    FROM notifications n
    LEFT JOIN alumni u ON n.user_id = u.id
    LEFT JOIN yearbooks y ON n.type = 'yearbook' AND n.related_id = y.id
    LEFT JOIN (
      SELECT yearbook_id, MIN(id) AS first_image_id
      FROM images
      GROUP BY yearbook_id
    ) first_img ON y.id = first_img.yearbook_id
    LEFT JOIN images yi ON yi.id = first_img.first_image_id
    LEFT JOIN posts p ON n.type = 'post' AND n.related_id = p.id
    LEFT JOIN events e ON n.type = 'event' AND n.related_id = e.id
    WHERE (n.user_id != ? OR n.type = 'yearbook')
    ORDER BY n.created_at DESC
    LIMIT 10
  `;

  db.query(sql, [currentUserId], (err, results) => {
    if (err) {
      console.error("❌ Error fetching notifications:", err.sqlMessage || err);
      return res.status(500).json({ error: "Internal Server Error" });
    }
    res.json(results);
  });
});



// Get all posts
app.get("/api/posts", (req, res) => {
  const sql = `
    SELECT posts.id, posts.content, posts.date_posted, posts.user_id, 
           alumni.first_name, alumni.last_name, alumni.profile
    FROM posts 
    JOIN alumni ON posts.user_id = alumni.id 
    ORDER BY posts.date_posted DESC
  `;

  db.query(sql, (error, posts) => {
    if (error) {
      console.error("❌ Database Query Error:", error.sqlMessage || error);
      return res.status(500).json({ error: "Internal Server Error" });
    }

    console.log("✅ Posts Retrieved:", posts.length, "posts found.");
    res.json(posts);
  });
});

app.put("/api/posts/:id", (req, res) => {
  if (!req.session.user) return res.status(401).json({ error: "Unauthorized" });

  const { content } = req.body;
  const postId = req.params.id;
  const userId = req.session.user.id;

  const sql = "UPDATE posts SET content = ? WHERE id = ? AND user_id = ?";
  db.query(sql, [content, postId, userId], (error, result) => {
    if (error) {
      console.error("❌ Error updating post:", error.sqlMessage || error);
      return res.status(500).json({ error: "Internal Server Error" });
    }

    if (result.affectedRows === 0) {
      return res.status(403).json({ error: "Unauthorized or post not found" });
    }

    res.json({ success: true, content });
  });
});

// Delete post
app.delete("/api/posts/:id", (req, res) => {
  const postId = req.params.id;
  if (!postId) return res.status(400).json({ error: "Post ID is required" });

  const sql = "DELETE FROM posts WHERE id = ?";
  db.query(sql, [postId], (error, result) => {
    if (error) {
      console.error("❌ Error deleting post:", error.sqlMessage || error);
      return res.status(500).json({ error: error.sqlMessage || "Internal Server Error" });
    }
    if (result.affectedRows === 0) {
      return res.status(404).json({ error: "Post not found" });
    }
    res.sendStatus(204);
  });
});


// Ensure 'uploads' directory exists
const uploadDir = path.join(__dirname, "uploads");
if (!fs.existsSync(uploadDir)) {
    fs.mkdirSync(uploadDir);
}

// Fix multer configuration (Use `storage` instead of `eventimage`)
const eventimage = multer.diskStorage({
  destination: (req, file, cb) => {
      cb(null, uploadDir);
  },
  filename: (req, file, cb) => {
      cb(null, `${Date.now()}-${file.originalname}`);
  },
});
const eventupload = multer({ storage: eventimage }); // ✅ Fixed here


// Post an Event
app.post("/api/events", eventupload.array("images", 5), (req, res) => {
  if (!req.session.user) {
    return res.status(401).json({ error: "User not authenticated" });
  }

  const user_id = req.session.user.id;
  const { content, location_name, latitude, longitude } = req.body;

  if (!req.files || req.files.length === 0) {
    return res.status(400).json({ error: "No images uploaded" });
  }

  const imagePaths = req.files.map((file) => `/uploads/${file.filename}`);

  const sql = "INSERT INTO events (user_id, content, location_name, latitude, longitude, images) VALUES (?, ?, ?, ?, ?, ?)";
  db.query(sql, [user_id, content, location_name, latitude, longitude, JSON.stringify(imagePaths)], (err, result) => {
    if (err) return res.status(500).json({ error: err.message });

    const newEventId = result.insertId;
    const message = ` posted a new EVENT.`;

    // 🔔 Insert Notification
    const notifSql = "INSERT INTO notifications (type, message, related_id, user_id, created_at) VALUES (?, ?, ?, ?, NOW())";
    db.query(notifSql, ["event", message, newEventId, user_id], (notifErr) => {
      if (notifErr) {
        console.error("❌ Error creating event notification:", notifErr.message || notifErr);
        // You can still send success if notification fails
      }

      res.json({ 
        success: true, 
        message: "Event posted successfully!", 
        images: imagePaths, 
        event_id: newEventId 
      });
    });
  });
});


// Get All Events
app.get("/api/events", (req, res) => {
  const sql = `
    SELECT e.*, 
           u.first_name, 
           u.last_name, 
           u.profile
    FROM events e 
    JOIN alumni u ON e.user_id = u.id 
    ORDER BY e.created_at DESC
  `;

  db.query(sql, (err, results) => {
    if (err) {
      console.error("❌ Error fetching events:", err.message);
      return res.status(500).json({ error: err.message });
    }

    res.json({ success: true, events: results });
  });
});


// Get Events by User
app.get("/api/events/user", (req, res) => {
  if (!req.session.user) {
      return res.status(401).json({ error: "User not authenticated" });
  }

  const user_id = req.session.user.id;
  const sql = "SELECT * FROM events WHERE user_id = ? ORDER BY created_at DESC";

  db.query(sql, [user_id], (err, results) => {
      if (err) return res.status(500).json({ error: err.message });
      res.json(results);
  });
});

// Delete Event (Only if the logged-in user is the owner)
app.delete("/api/events/:id", (req, res) => {
  if (!req.session.user) {
      return res.status(401).json({ error: "User not authenticated" });
  }

  const user_id = req.session.user.id;
  const event_id = req.params.id;

  const sql = "DELETE FROM events WHERE id = ? AND user_id = ?";
  db.query(sql, [event_id, user_id], (err, result) => {
      if (err) return res.status(500).json({ error: err.message });
      if (result.affectedRows === 0) return res.status(403).json({ error: "Not authorized to delete this event" });

      res.json({ success: true, message: "Event deleted successfully!" });
  });
});

// Multer Storage (Save files inside `/uploads`)
const storage = multer.diskStorage({
  destination: (req, file, cb) => {
    const folderName = req.body.folderName || "default";
    const uploadPath = `uploads/${folderName}`;
    fs.mkdirSync(uploadPath, { recursive: true });
    cb(null, uploadPath);
  },
  filename: (req, file, cb) => {
    cb(null, file.originalname);
  },
});

const upload = multer({ storage });


// Upload Yearbook Folder with Multiple Files and Student Names from Excel
app.post("/upload-yearbook", upload.fields([{ name: "images", maxCount: 100 }, { name: "studentNames", maxCount: 1 }]), (req, res) => {
  const { folderName, yearbookName } = req.body;

  if (!folderName || !req.files["images"]) {
    return res.status(400).json({ message: "Folder and images are required" });
  }

  // Insert yearbook info
  const insertYearbookQuery = "INSERT INTO yearbooks (folder_name, yearbook_name) VALUES (?, ?)";
  db.query(insertYearbookQuery, [folderName, yearbookName], (err, result) => {
    if (err) return res.status(500).json({ error: "Database error" });

    const yearbookId = result.insertId;

    // Insert images
    const imageValues = req.files["images"].map((file) => [yearbookId, file.originalname, file.path]);
    const insertImagesQuery = "INSERT INTO images (yearbook_id, file_name, file_path) VALUES ?";
    db.query(insertImagesQuery, [imageValues], (err) => {
      if (err) return res.status(500).json({ error: "Error saving images" });
    });

    // Process and insert student names if present
    if (req.files["studentNames"]) {
      const studentFile = req.files["studentNames"][0].path;
      const workbook = xlsx.readFile(studentFile);
      const sheetName = workbook.SheetNames[0];
      const sheetData = xlsx.utils.sheet_to_json(workbook.Sheets[sheetName]);

      const studentValues = sheetData.map((row) => [yearbookId, row["First Name"], row["Last Name"]]);
      const insertStudentsQuery = "INSERT INTO students (yearbook_id, first_name, last_name) VALUES ?";
      db.query(insertStudentsQuery, [studentValues], (err) => {
        if (err) return res.status(500).json({ error: "Error saving student names" });
      });
    }

    // 🔔 Create a notification
    const message = `A new yearbook "${yearbookName}" was uploaded.`;
    const notifSql = `INSERT INTO notifications (type, message, related_id, created_at) VALUES (?, ?, ?, NOW())`;
    db.query(notifSql, ["yearbook", message, yearbookId], (notifErr) => {
      if (notifErr) {
        console.error("❌ Error creating yearbook notification:", notifErr.sqlMessage || notifErr);
        // Don't block the response
      }

      res.json({ message: "Yearbook uploaded successfully!" });
    });
  });
});


// Get All Yearbooks
app.get("/yearbooks", (req, res) => {
  const query = "SELECT * FROM yearbooks ORDER BY date_uploaded DESC";
  db.query(query, (err, results) => {
    if (err) return res.status(500).json({ error: err });
    res.json(results);
  });
});

app.get("/yearbooks/count", (req, res) => {
  const query = "SELECT COUNT(*) AS count FROM yearbooks";
  db.query(query, (err, results) => {
    if (err) return res.status(500).json({ error: err });
    res.json(results[0]);
  });
});


// Get Images for a Specific Yearbook
app.get("/yearbook/:id/images", (req, res) => {
  const query = "SELECT file_path FROM images WHERE yearbook_id = ?";
  db.query(query, [req.params.id], (err, results) => {
    if (err) return res.status(500).json({ error: err });
    res.json(results);
  });
});

// Delete yearbook by ID
app.delete("/yearbook/:id", async (req, res) => {
  const { id } = req.params;

  try {
    // Delete from database
    db.query("DELETE FROM yearbooks WHERE id = ?", [id]);

    res.json({ success: true, message: "Yearbook deleted successfully" });
  } catch (error) {
    console.error("Error deleting yearbook:", error);
    res.status(500).json({ success: false, message: "Failed to delete yearbook" });
  }
});

// Delete Yearbook (Cascade Deletes Images)
app.delete("/yearbook/:id", (req, res) => {
  const query = "DELETE FROM yearbooks WHERE id = ?";
  db.query(query, [req.params.id], (err) => {
    if (err) return res.status(500).json({ error: err });
    res.json({ message: "Yearbook deleted successfully!" });
  });
});


// API to upload Excel file and save Alumni IDs to MySQL

app.post("/upload-alumni-ids", upload.single("alumniFile"), (req, res) => {
  if (!req.file) {
    return res.status(400).json({ message: "No file uploaded" });
  }

  const filePath = req.file.path;
  try {
    const workbook = xlsx.readFile(filePath);
    const sheetName = workbook.SheetNames[0];
    const sheetData = xlsx.utils.sheet_to_json(workbook.Sheets[sheetName]);

    // DEBUG: Print keys in each row to confirm the header
    console.log("Headers found in Excel:", Object.keys(sheetData[0]));

    // Replace "Alumni ID" below with exact header name if needed
    const alumniIDs = sheetData
      .map(row => String(row["Alumni ID"]).trim()) // convert and trim
      .filter(id => id && id !== "undefined" && id !== "null" && id !== ""); // remove empty/invalid

    if (alumniIDs.length === 0) {
      fs.unlinkSync(filePath);
      return res.status(400).json({ message: "No valid Alumni IDs found in the file." });
    }

   const sql = "INSERT IGNORE INTO alumni_ids (alumni_id) VALUES ?";
    const values = alumniIDs.map(id => [id]);

    db.query(sql, [values], (err, result) => {
      fs.unlinkSync(filePath);
      if (err) {
        console.error("Database error:", err);
        return res.status(500).json({ message: "Error inserting into database", error: err });
      }

      res.json({ message: `${result.affectedRows} Alumni IDs uploaded successfully` });
    });

  } catch (error) {
    fs.unlinkSync(filePath);
    console.error("File processing error:", error);
    res.status(500).json({ message: "Error processing Excel file" });
  }
});

 //for show alumni id number
app.get("/check-alumni-id/:id", (req, res) => {
  const alumniID = req.params.id;
  
  const sql = "SELECT * FROM alumni_ids WHERE alumni_id = ?";
  db.query(sql, [alumniID], (err, result) => {
      if (err) {
          console.error("Database error:", err);
          return res.status(500).json({ message: "Database error" });
      }
      
      if (result.length > 0) {
          res.json({ exists: true });
      } else {
          res.json({ exists: false });
      }
  });
});






app.get("/api/courses", (req, res) => {
  const sql = "SELECT DISTINCT name FROM courses ORDER BY name;";
  db.query(sql, (err, results) => {
    if (err) return res.status(500).json({ error: "Database error" });
    res.json(results.map(row => row.name));
  });
});

app.get("/api/workfields", (req, res) => {
  const sql = "SELECT DISTINCT name FROM work_fields ORDER BY name;";
  db.query(sql, (err, results) => {
    if (err) return res.status(500).json({ error: "Database error" });
    res.json(results.map(row => row.name));
  });
});

app.get("/api/worktitle", (req, res) => {
  const sql = "SELECT DISTINCT title FROM work_titles ORDER BY title;";
  db.query(sql, (err, results) => {
    if (err) return res.status(500).json({ error: "Database error" });
    res.json(results.map(row => row.title));
  });
});

//this is for survey Option
app.post("/api/surveyop", (req, res) => {
  console.log("Received Data:", req.body);

  const { selectedCourse, selectedWorkField, workTitles } = req.body;

  if (!selectedCourse?.trim()  || !Array.isArray(workTitles) || workTitles.length === 0) {
    return res.status(400).json({ error: "All fields are required" });
  }

  const getOrInsert = (table, name, callback) => {
    const getIdQuery = `SELECT id FROM ${table} WHERE name = ?`;
    const insertQuery = `INSERT INTO ${table} (name) VALUES (?)`;

    db.query(getIdQuery, [name], (err, result) => {
      if (err) {
        console.error(`Error fetching ${table}:`, err);
        return res.status(500).json({ error: "Database error" });
      }

      if (result.length > 0) {
        callback(result[0].id);
      } else {
        db.query(insertQuery, [name], (err, insertResult) => {
          if (err) {
            console.error(`Error inserting into ${table}:`, err);
            return res.status(500).json({ error: "Database error" });
          }
          callback(insertResult.insertId);
        });
      }
    });
  };

  getOrInsert("courses", selectedCourse, (courseId) => {
    getOrInsert("work_fields", selectedWorkField, (workFieldId) => {
      const insertWorkTitle = "INSERT INTO work_titles (course_id, work_field_id, title) VALUES (?, ?, ?)";

      let insertedCount = 0;
      workTitles.forEach((title) => {
        db.query(insertWorkTitle, [courseId, workFieldId, title], (err) => {
          if (err) {
            console.error("Error inserting work title:", err);
            return res.status(500).json({ error: "Database error" });
          }
          insertedCount++;
          if (insertedCount === workTitles.length) {
            res.json({ message: "Survey data inserted successfully" });
          }
        });
      });
    });
  });
});

// Fetch Survey Data
app.get("/api/survey", (req, res) => {
  const query = `
    SELECT 
      c.name AS course, 
      wf.name AS work_field, 
      wt.title AS work_title
    FROM work_titles wt
    JOIN courses c ON wt.course_id = c.id
    JOIN work_fields wf ON wt.work_field_id = wf.id
    ORDER BY c.name, wf.name, wt.title;
  `;

  db.query(query, (err, results) => {
    if (err) {
      console.error("Error fetching survey data:", err);
      return res.status(500).json({ error: "Database error" });
    }
    
    res.json(results);
  });
});

// Express.js example
app.post("/api/mark-survey", async (req, res) => {
  try {
    const userId = req.session.userId; // assuming session stores userId
    if (!userId) return res.status(401).json({ success: false, message: "Not logged in" });

     db.query("UPDATE users SET has_submitted_survey = 1 WHERE id = ?", [userId]);

    res.json({ success: true });
  } catch (err) {
    console.error(err);
    res.status(500).json({ success: false, message: "Server error" });
  }
});

//for related course and work field
app.get("/api/is-related", (req, res) => {
  const { course, workField } = req.query;

  if (!course || !workField) {
    return res.status(400).json({ error: "Missing course or workField parameter" });
  }

  const sql = "SELECT * FROM course_work_relation WHERE course_name = ? AND work_field_name = ?";
  
  db.query(sql, [course, workField], (err, results) => {
    if (err) return res.status(500).json({ error: "Database error" });

    if (results.length > 0) {
      res.json({ related: true, message: "Course is related to work field." });
    } else {
      res.json({ related: false, message: "Course is NOT related to work field." });
    }
  });
});




app.post("/api/surveysubmit", async (req, res) => {
  try {
    if (!req.session || !req.session.user) {
      console.log("Session Data:", req.session); // Debugging session data
      return res.status(401).json({ message: "User not authenticated" });
    }

    console.log("User session stored:", req.session.user);

    // Extract user details from session
    const { id, name, middlename, lastname, gender, course, work, yeargraduate } = req.session.user;

    // Extract survey responses from request body
    const { employmentStatus, industry, workExperience, educationRelevance, alumniEvents, skills } = req.body;

    if (!employmentStatus || !industry || !workExperience) {
      return res.status(400).json({ message: "Missing required fields" });
    }

    // Convert skills object to JSON string if it's valid
    const skillsJSON = skills ? JSON.stringify(skills) : null;

    console.log("Survey Data to Insert:", {
      id, name, middlename, lastname, gender, course, work, yeargraduate,
      employmentStatus, industry, workExperience, educationRelevance, alumniEvents, skillsJSON
    });

    const insertSurveySQL = `
        INSERT INTO alumni_survey 
        (name, middlename, lastname, gender, course, work, yeargraduate, employment_status, industry, work_experience, education_relevance, alumni_events, skills) 
        VALUES ( ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    `;

    const insertValues = [
      name, middlename, lastname, gender, course, work, yeargraduate,
      employmentStatus, industry, workExperience, educationRelevance, alumniEvents, skillsJSON
    ];

    db.query(insertSurveySQL, insertValues, (err, result) => {
      if (err) {
        console.error("Error inserting survey data:", err.sqlMessage);
        return res.status(500).json({ message: "Database error", error: err.sqlMessage });
      }

      // 🔥 Update has_submitted_survey field after successful submission
      const updateSurveyStatusSQL = `UPDATE alumni SET has_submitted_survey = 1 WHERE id = ?`;

      db.query(
        "UPDATE alumni SET has_submitted_survey = 1 WHERE id = ?",
        [req.session.user.id],
        (err, result) => {
          if (err) {
            console.error("Error updating survey status:", err);
          }

        res.status(200).json({ message: "Survey submitted successfully", has_submitted_survey: true });
      });
    });

  } catch (error) {
    console.error("Survey submission error:", error);
    res.status(500).json({ message: "Server error" });
  }
});


// Fetch survey data
app.get("/api/surveydata", (req, res) => {
  const query = `
    SELECT name, middlename, lastname, yeargraduate, employment_status, industry, work_experience, education_relevance, alumni_events, course, work 
    FROM alumni_survey
  `;
  
  db.query(query, (err, results) => {
    if (err) {
      console.error("Error fetching survey data:", err);
      res.status(500).json({ message: "Internal Server Error" });
    } else {
      res.json(results);
    }
  });
});


// 🔹 Save schema (overwrite latest)
app.post("/api/schema", (req, res) => {
  let schema = req.body;

  // Unwrap if mistakenly wrapped
  while (schema && schema.schema) {
    schema = schema.schema;
  }

  const schemaStr = JSON.stringify(schema);

  db.query("DELETE FROM schema_store", function (err) {
    if (err) return res.json({ success: false, error: err });

    db.query("INSERT INTO schema_store (schema_json) VALUES (?)", [schemaStr], function (err2) {
      if (err2) return res.json({ success: false, error: err2 });
      res.json({ success: true });
    });
  });
});

app.get("/api/schema", (req, res) => {
  db.query(
    "SELECT schema_json FROM schema_store ORDER BY id DESC LIMIT 1",
    function (err, rows) {
      if (err) return res.json({ success: false, error: err });
      if (!rows.length) return res.json({ success: true, schema: { sections: [] } });

      let parsed;
      try {
        parsed = JSON.parse(rows[0].schema_json);

        // Unwrap double-encoded
        if (typeof parsed === "string") {
          parsed = JSON.parse(parsed);
        }

        // Unwrap nested { schema: {...} }
        while (parsed && parsed.schema) {
          parsed = parsed.schema;
        }

        // Ensure at least { sections: [] }
        if (!parsed.sections) {
          parsed.sections = [];
        }

        // Normalize fields
       parsed.sections.forEach((section, sIdx) => {
            if (!Array.isArray(section.fields)) section.fields = []; // normalize

            section.fields.forEach((field, fIdx) => {
              if (!field || typeof field !== "object") {
                section.fields[fIdx] = { key: `s${sIdx}_f${fIdx}`, type: "text", label: "" }; // replace invalid
                return;
              }

              if (!field.key) field.key = `s${sIdx}_f${fIdx}`;

              if (["radio", "checkbox"].includes(field.type) && typeof field.options === "string") {
                field.options = field.options.split(",").map((o) => o.trim());
              }
            });
          });

      } catch (e) {
        console.error("❌ JSON parse error:", e);
        return res.json({ success: false, error: "Invalid JSON in DB" });
      }

      console.log("FINAL schema sent:", JSON.stringify(parsed, null, 2));
      res.json({ success: true, schema: parsed });
    }
  );
});

// 🔹 Save form submission
app.post("/api/submit", (req, res) => {
  const answers = JSON.stringify(req.body);

  // Ensure session + user is available
  if (!req.session || !req.session.user) {
    console.log("Session Data:", req.session); // Debugging session data
    return res.status(401).json({ message: "User not authenticated" });
  }

  // Insert submission with user_id
   db.query(
    `INSERT INTO submissions (user_id, answers_json, created_at)
     VALUES (?, ?, NOW())
     ON DUPLICATE KEY UPDATE answers_json = VALUES(answers_json), created_at = NOW()`,
    [req.session.user.id, answers],
    (err, result) => {
      if (err) {
        console.error("Error inserting/updating submission:", err);
        return res.status(500).json({ success: false, error: err });
      }

      // Update alumni table
      db.query(
        "UPDATE alumni SET isGTSsurvey = 1 WHERE id = ?",
        [req.session.user.id],
        (err, updateResult) => {
          if (err) {
            console.error("Error updating survey status:", err);
            return res.status(500).json({ success: false, error: err });
          }

          return res.json({
            success: true,
            message: "Survey submitted successfully",
            isGTSsurvey: true,
          });
        }
      );
    }
  );
});



app.get("/api/submissions", (req, res) => {
  db.query("SELECT * FROM submissions ORDER BY created_at DESC", (err, rows) => {
    if (err) return res.json({ success: false, error: err });

    const data = rows.map(r => JSON.parse(r.answers_json));
    res.json({ success: true, data });
  });
});


app.get("/api/submission/:id", (req, res) => {
  const userId = req.params.id;

  db.query(
    "SELECT answers_json FROM submissions WHERE user_id = ? ORDER BY created_at DESC LIMIT 1",
    [userId],
    (err, results) => {
      if (err) {
        console.error("Error fetching submission:", err);
        return res.status(500).json({ success: false, error: err });
      }

      if (results.length === 0) {
        return res.json({ success: true, answers: {} });
      }

      let answers = {};
      try {
        answers = JSON.parse(results[0].answers_json);
      } catch (e) {
        console.error("Error parsing answers:", e);
      }

      res.json({ success: true, answers });
    }
  );
});


// Save schema (always id=1, update if exists)
app.post("/api/survyschema", (req, res) => {
  const schema = JSON.stringify(req.body);

  db.query(
    `INSERT INTO survey_schema (id, schema_json) 
     VALUES (1, ?) 
     ON DUPLICATE KEY UPDATE schema_json = VALUES(schema_json), updated_at = CURRENT_TIMESTAMP`,
    [schema],
    (err) => {
      if (err) {
        console.error("❌ Failed to save schema:", err);
        return res.json({ success: false, error: err });
      }
      res.json({ success: true });
    }
  );
});

// Load schema
app.get("/api/survyschema", (req, res) => {
  db.query("SELECT schema_json, updated_at FROM survey_schema WHERE id = 1", (err, rows) => {
    if (err) {
      console.error("❌ Failed to load schema:", err);
      return res.json({ success: false, error: err });
    }
    if (rows.length === 0) {
      return res.json({ success: true, schema: { sections: [] } });
    }
    res.json({
      success: true,
      schema: JSON.parse(rows[0].schema_json),
      updated_at: rows[0].updated_at,
    });
  });
});

// Save submission
app.post("/api/submitsurvey", (req, res) => {
  const answers = JSON.stringify(req.body);

  // First insert the survey submission
  db.query(
    "INSERT INTO survey_submissions (submission_json) VALUES (?)",
    [answers],
    function (err) {
      if (err) {
        return res.status(500).json({ success: false, error: err.message });
      }

      // After successful insert, update alumni
      db.query(
        "UPDATE alumni SET has_submitted_survey = 1 WHERE id = ?",
        [req.session.user?.id],
        (err, result) => {
          if (err) {
            console.error("Error updating survey status:", err);
            return res
              .status(500)
              .json({ success: false, error: "Failed to update alumni survey status" });
          }
           // Also update session
          if (req.session.user) req.session.user.has_submitted_survey = 1;

          // Final single response
          res.status(200).json({
            success: true,
            message: "Survey submitted successfully",
            has_submitted_survey: true,
          });
        }
      );
    }
  );
});


// Get submissions
app.get("/api/surveysubmissions", (req, res) => {
  db.query("SELECT * FROM survey_submissions ORDER BY created_at DESC", (err, rows) => {
    if (err) return res.json({ success: false, error: err });

    // Parse each submission_json into a real object
    const data = rows.map(r => {
      try {
        return JSON.parse(r.submission_json);
      } catch {
        return {};
      }
    });

    res.json({ success: true, data });
  });
});



// ✅ Get latest schema
app.get("/api/feedback-schema", (req, res) => {
  db.query(
    "SELECT id, schema_json FROM feedback_schema ORDER BY updated_at DESC LIMIT 1",
    (err, results) => {
      if (err) return res.status(500).json({ success: false, error: err.message });

      if (!results.length) return res.json({ success: true, schema: { sections: [] } });

      let schema;
      try {
        schema = JSON.parse(results[0].schema_json);
      } catch {
        schema = { raw: results[0].schema_json };
      }
      res.json({ success: true, id: results[0].id, schema });
    }
  );
});

// ✅ Save schema (new version)
app.post("/api/feedback-schema", (req, res) => {
  const updatedSchema = req.body;
  if (!updatedSchema) return res.status(400).json({ success: false, error: "Invalid schema" });

  const schemaString = JSON.stringify(updatedSchema);
  db.query(
    "INSERT INTO feedback_schema (schema_json) VALUES (?)",
    [schemaString],
    (err, result) => {
      if (err) return res.status(500).json({ success: false, error: err.message });
      res.json({ success: true, id: result.insertId });
    }
  );
});

// ✅ Save employer response
app.post("/api/feedback-response", (req, res) => {
  const schema_id = req.body.schema_id || null;
  const alumni_id = req.body.alumni_id || null; // ✅ get alumni_id
  const response = req.body.response || req.body;
  const responseString = JSON.stringify(response);

  if (!alumni_id) {
    return res.status(400).json({ success: false, error: "alumni_id is required" });
  }

  db.query(
    "INSERT INTO feedback_responses (schema_id, alumni_id, response_json) VALUES (?, ?, ?)",
    [schema_id, alumni_id, responseString],
    (err, result) => {
      if (err) {
        return res.status(500).json({ success: false, error: err.message });
      }
      res.json({ success: true, id: result.insertId });
    }
  );
});


// ✅ Get all responses
app.get("/api/feedback-responses", (req, res) => {
  db.query(
    "SELECT id, schema_id, response_json, created_at FROM feedback_responses ORDER BY created_at DESC",
    (err, results) => {
      if (err) return res.status(500).json({ success: false, error: err.message });

      const formatted = results.map((row) => {
        let parsed;
        try {
          parsed = JSON.parse(row.response_json);
        } catch {
          parsed = row.response_json;
        }
        return { ...row, response: parsed };
      });
      res.json({ success: true, responses: formatted });
    }
  );
});


// Start Server
app.listen(5000, () => console.log("Server running on port 5000"));
