const express = require("express");
const multer = require("multer");
const mysql = require('mysql2');
const path = require("path");
const fs = require("fs");
const cors = require("cors");
const xlsx = require("xlsx");
const nodemailer = require("nodemailer");
const crypto = require("crypto");
const app = express();
const session = require('express-session');
const MySQLStore = require('express-mysql-session')(session);
const { v2: cloudinary } = require("cloudinary");
const { CloudinaryStorage } = require("multer-storage-cloudinary");
const fetch = require("node-fetch");


app.use(
  cors({
    origin: "https://stii-memotrace.onrender.com", // Allow requests only from your frontend
     methods: ['GET','POST','PUT','DELETE','OPTIONS'],
    credentials: true, 
  })
);

// Allow larger JSON and URL-encoded bodies (for base64 images)
app.use(express.json({ limit: "50mb" }));
app.use(express.urlencoded({ limit: "50mb", extended: true }));


// Setup MySQL Connection
const db = mysql.createConnection({
   host: process.env.DB_HOST,
  port: process.env.DB_PORT,
  user: process.env.DB_USER,
  password: process.env.DB_PASS,
  database: process.env.DB_NAME,
  ssl: { ca: process.env.DB_SSL_CA },
});

db.connect((err) => {
  if (err) console.error("MySQL connection failed:", err);
  else console.log("Connected to MySQL");
});

// 🔹 Session store uses its own MySQL connection pool
const sessionStore = new MySQLStore({
  host: process.env.DB_HOST,
  port: process.env.DB_PORT,
  user: process.env.DB_USER,
  password: process.env.DB_PASS,
  database: process.env.DB_NAME,
  ssl: { ca: process.env.DB_SSL_CA },
});

// 🔹 Express-session setup
app.set("trust proxy", 1);
app.use(
  session({
    key: 'memotrace_session',
    secret: process.env.SESSION_SECRET,
    store: sessionStore,
    resave: false,
    saveUninitialized: false,
    cookie: {
      secure: true, 
      httpOnly: true,
      sameSite: 'none',
      maxAge: 1000 * 60 * 60 * 24, // 1 day
    },
  })
);



app.get("/", (req, res) => {
  res.send("backend is running! Use /api/alumni to fetch data.");
});

cloudinary.config({
  cloud_name: process.env.CLOUDINARY_CLOUD_NAME,
  api_key: process.env.CLOUDINARY_API_KEY,
  api_secret: process.env.CLOUDINARY_API_SECRET,
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

app.get("/api/user/:id", (req, res) => {
  const userId = req.params.id;

  const query = `
    SELECT 
      a.id AS user_id, 
      a.first_name,
      a.middle_name,
      a.last_name, 
      a.email, 
      a.course, 
      a.year_graduate, 
      a.profile, 
      a.address,
      we.id AS work_id,
      we.position, 
      we.company, 
      we.location AS work_location, 
      we.start_date AS work_start_date, 
      we.end_date AS work_end_date, 
      we.description AS work_description, 
      we.is_current,
      e.id AS education_id,
      e.program_type, 
      e.field_of_study, 
      e.institution_name, 
      e.institution_location, 
      e.start_date AS edu_start_date, 
      e.end_date AS edu_end_date, 
      e.is_completed
    FROM alumni a
    LEFT JOIN work_experiences we ON a.id = we.user_id
    LEFT JOIN education e ON a.id = e.user_id
    WHERE a.id = ?;
  `;

  db.query(query, [userId], (err, results) => {
    if (err) {
      console.error("❌ Error fetching user with joins:", err);
      return res.status(500).json({ message: "Database error" });
    }

    if (results.length === 0) {
      return res.status(404).json({ message: "User not found" });
    }

    // 🧠 Format data to avoid repetition (grouped)
    const user = {
      id: results[0].user_id,
      first_name: results[0].first_name,
      middle_name: results[0].middle_name,
      last_name: results[0].last_name,
      email: results[0].email,
      course: results[0].course,
      address: results[0].address,
      year_graduate: results[0].year_graduate,
      profile: results[0].profile,
      work_experiences: results[0].position,
      education: [],
    };

    // 🧱 Build unique work experiences
    const workMap = new Map();
    const eduMap = new Map();

    results.forEach((row) => {
      // ✅ Collect work experience
      if (row.work_id && !workMap.has(row.work_id)) {
        workMap.set(row.work_id, {
          id: row.work_id,
          position: row.position,
          company: row.company,
          location: row.work_location,
          start_date: row.work_start_date,
          end_date: row.work_end_date,
          description: row.work_description,
          is_current: !!row.is_current,
        });
      }

      // ✅ Collect education
      if (row.education_id && !eduMap.has(row.education_id)) {
        eduMap.set(row.education_id, {
          id: row.education_id,
          program_type: row.program_type,
          field_of_study: row.field_of_study,
          institution_name: row.institution_name,
          institution_location: row.institution_location,
          start_date: row.edu_start_date,
          end_date: row.edu_end_date,
          is_completed: !!row.is_completed,
        });
      }
    });

    user.work_experiences = Array.from(workMap.values());
    user.education = Array.from(eduMap.values());

    res.json(user);
  });
});


// Configure Multer
const profileStorage = new CloudinaryStorage({
  cloudinary: cloudinary,
  params: async (req, file) => {
    const folderName = "profiles"; // or you can use req.body.folderName
    return {
      folder: `profiles/${folderName}`,
      public_id: `${Date.now()}-${file.originalname.split(".")[0]}`, // unique ID
      resource_type: "auto", // images, PDFs, etc.
    };
  },
});

const profileUpload = multer({ storage: profileStorage });

app.put("/api/users/:id", profileUpload.single("profile"), async (req, res) => {
  const { id } = req.params;
  const { name, middlename, lastname, email, password } = req.body;
  const profile = req.file ? req.file.path : null; // Cloudinary URL

  if (!name || !lastname || !email) {
    return res.status(400).json({ message: "Name, Lastname, and Email are required" });
  }

  const selectQuery = "SELECT password, email, profile FROM alumni WHERE id = ?";
  db.query(selectQuery, [id], async (err, results) => {
    if (err) return res.status(500).json({ message: "Database error" });
    if (results.length === 0) return res.status(404).json({ message: "User not found" });

    const user = results[0];

    // Email change verification
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

      const insertQuery = `
        INSERT INTO email_verifications (user_id, email, code, expires_at)
        VALUES (?, ?, ?, ?)
      `;
      db.query(insertQuery, [id, email, verificationCode, expirationTime], (err) => {
        if (err) return res.status(500).json({ message: "Failed to store verification code" });

        sendVerificationCode(email, verificationCode);
        return res.json({
          message:
            "Verification code sent. Please verify your new email before saving any profile changes.",
          requiresVerification: true,
        });
      });

      return; // Stop further updates
    }

    // Update other fields
    const finalProfile = profile || user.profile;
    const updateQuery = `
      UPDATE alumni
      SET first_name = ?, middle_name = ?, last_name = ?, profile = ?
      WHERE id = ?
    `;
    db.query(updateQuery, [name, middlename, lastname, finalProfile, id], (err) => {
      if (err) return res.status(500).json({ message: "Invalid input! Please check the form and try again." });

      res.json({
        message: "User updated successfully",
        profile: finalProfile,
        requiresVerification: false,
      });
    });
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

// Helper function to send email// Helper function – no res dependency
async function sendVerificationCode(email, code) {
  try {
    const response = await fetch("https://api.brevo.com/v3/smtp/email", {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        "api-key": process.env.BREVO_API_KEY,
      },
      body: JSON.stringify({
        sender: { name: "MemoTrace", email: process.env.SMTP_USER },
        to: [{ email }],
        subject: "Confirm your email change",
        textContent: `Your verification code is: ${code}`,
        htmlContent: `
          <p>Your account email has been successfully changed.</p>
          <p>Your verification code is: <b>${code}</b></p>
          <p>If you did not request this change, please contact support immediately.</p>
        `,
      }),
    });

    if (!response.ok) {
      const data = await response.json().catch(() => ({}));
      console.error("❌ Brevo API error:", data);
      throw new Error("Failed to send verification email");
    }

    console.log(`✅ Verification email sent to: ${email}`);
    return true;

  } catch (error) {
    console.error("❌ Error sending verification email:", error);
    throw error;
  }
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

async function sendFailedAttemptAlert(email) {
  try {
    const response = await fetch("https://api.brevo.com/v3/smtp/email", {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        "api-key": process.env.BREVO_API_KEY,
      },
      body: JSON.stringify({
        sender: { name: "MemoTrace", email: process.env.SMTP_USER },
        to: [{ email }],
        subject: "Security Alert: Multiple Failed Password Attempts",
        textContent: `There have been 3 unsuccessful attempts to change your password on your MEMOTRACE account. If this wasn't you, please secure your account immediately.`,
        htmlContent: `
          <p>There have been <b>3 unsuccessful attempts</b> to change your password on your MEMOTRACE account.</p>
          <p>If this wasn't you, please secure your account immediately.</p>
        `,
      }),
    });

    const data = await response.json();

    if (!response.ok) {
      console.error("❌ Brevo API error (failed attempt alert):", data);
      return;
    }

    console.log(`✅ Security alert email sent to: ${email}`);
    console.log("📄 Brevo API response:", data);

  } catch (error) {
    console.error("❌ Error sending security alert email:", error);
  }
}

// / Helper function to send password reset email via Brevo API
async function sendPasswordResetCode(email, code, res) {
  if (!process.env.BREVO_API_KEY || !process.env.SMTP_USER) {
    console.error("❌ Brevo API key or sender email is missing in environment variables");
    return res.status(500).json({ message: "Email service not configured." });
  }

  try {
    const response = await fetch("https://api.brevo.com/v3/smtp/email", {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        "api-key": process.env.BREVO_API_KEY,
      },
      body: JSON.stringify({
        sender: { name: "MemoTrace", email: process.env.SMTP_USER }, // verified sender
        to: [{ email }], // must use `email` key
        subject: "Password Reset Verification Code",
        htmlContent: `
          <p>You have requested to reset your password.</p>
          <p>Your verification code is: <b>${code}</b></p>
          <p>If you did not request this, please ignore this email.</p>
          <p>— MemoTrace Team</p>
        `,
        textContent: `You have requested to reset your password.\nYour verification code is: ${code}\nIf you did not request this, please ignore this email.`,
      }),
    });

    const data = await response.json();

    if (!response.ok) {
      console.error("❌ Brevo API error:", data);
      return res.status(500).json({ message: "Failed to send password reset email." });
    }

    console.log(`✅ Password reset email sent to: ${email}`);
    console.log("📄 Brevo API response:", data);
    res.json({ message: "Password reset code sent. Please check your email." });

  } catch (error) {
    console.error("❌ Error sending password reset email:", error);
    res.status(500).json({ message: "Failed to send password reset email." });
  }
}



// POST /api/send-code
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
      address,
      password,
      privacyPolicyAccepted,
      mobileNumber,
      civilStatus,
      birthday,
      role,
    } = req.body;

    if (
      !firstName ||
      !lastName ||
      !email ||
      !password ||
      !alumniCardNumber ||
      !privacyPolicyAccepted
    ) {
      return res
        .status(400)
        .json({ message: "All required fields must be filled" });
    }

    // ✅ Check if Alumni Card Number exists
    const checkAlumniIDQuery = "SELECT * FROM alumni_ids WHERE alumni_id = ?";
    db.query(checkAlumniIDQuery, [alumniCardNumber], async (err, result) => {
      if (err) {
        console.error("Database error:", err);
        return res
          .status(500)
          .json({ message: "Make sure your information is correct" });
      }

      if (result.length === 0) {
        return res.status(400).json({ message: "Invalid Alumni Card Number" });
      }

      // ✅ Check if already registered
      const checkDuplicateQuery =
        "SELECT * FROM alumni WHERE alumni_card_number = ?";
      db.query(checkDuplicateQuery, [alumniCardNumber], async (dupErr, dupResult) => {
        if (dupErr) {
          console.error("Database error:", dupErr);
          return res
            .status(500)
            .json({ message: "Database error while checking duplicates" });
        }

        if (dupResult.length > 0) {
          return res.status(400).json({
            message:
              "Invalid input. Please verify the form. Alumni Card Number not accepted.",
          });
        }

        // ✅ Generate verification token
        const verificationToken = crypto.randomBytes(32).toString("hex");

        // ✅ Hash password
        const hashedPassword = await bcrypt.hash(password, 10);

        // ✅ Role assignment
        const userRole = role && role === "admin" ? "admin" : "alumni";

        // ✅ Insert user into DB
        const insertQuery = `
          INSERT INTO alumni (
            first_name, middle_name, last_name, email, alumni_card_number,
            gender, course, year_graduate, address, password,
            verification_token, privacy_policy_accepted, mobileNumber,
            civilStatus, birthday, role
          ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        `;

        db.query(
          insertQuery,
          [
            firstName,
            middleName,
            lastName,
            email,
            alumniCardNumber,
            gender,
            course,
            yearGraduate,
            address,
            hashedPassword,
            verificationToken,
            privacyPolicyAccepted,
            mobileNumber,
            civilStatus,
            birthday,
            userRole,
          ],
          (insertErr) => {
            if (insertErr) {
              console.error("Error inserting user:", insertErr);

              // ✅ Specific duplicate entry error handler
              if (insertErr.code === "ER_DUP_ENTRY") {
                return res.status(400).json({
                  message:
                    "Duplicate entry detected. This email or Alumni Card Number is already registered.",
                });
              }

              return res.status(500).json({
                message: "Invalid input! Please check the form and try again.",
              });
            }

            // ✅ Send verification email
            sendVerificationEmail(email, verificationToken);
            
            res.json({
              message: "Registration successful. Please verify your email.",
            });
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
    res.redirect("https://stii-memotrace.onrender.com/login"); 
    // 🔹 Change to your frontend login URL when deployed
  });
});




// Helper function to send verification email via Brevo API
async function sendVerificationEmail(email, token, res) {
  if (!process.env.BREVO_API_KEY || !process.env.SMTP_USER) {
    console.error("❌ Brevo API key or sender email is missing in environment variables");
    if (res) return res.status(500).json({ message: "Email service not configured." });
    return;
  }

  try {
    const response = await fetch("https://api.brevo.com/v3/smtp/email", {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        "api-key": process.env.BREVO_API_KEY,
      },
      body: JSON.stringify({
        sender: { name: "MemoTrace", email: process.env.SMTP_USER }, // verified sender
        to: [{ email }], // must use `email` key
        subject: "Verify Your Email",
        htmlContent: `
          <p>Click the link below to verify your Memotrace email account:</p>
          <p><a href="https://stii-memotrace.onrender.com/api/verify-email?token=${token}">
          Verify Email</a></p>
          <p>— MemoTrace Team</p>
        `,
        textContent: `Click the link to verify your Memotrace email account: https://stii-memotrace.onrender.com/api/verify-email?token=${token}`,
      }),
    });

    const data = await response.json();

    if (!response.ok) {
      console.error("❌ Brevo API error:", data);
      if (res) return res.status(500).json({ message: "Failed to send verification email." });
      return;
    }

    console.log(`✅ Verification email sent to: ${email}`);
    console.log("📄 Brevo API response:", data);
    if (res) res.json({ message: "Verification email sent. Please check your inbox." });

  } catch (error) {
    console.error("❌ Error sending verification email:", error);
    if (res) res.status(500).json({ message: "Failed to send verification email." });
  }
}


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

    
    req.session.save((err) => {
  if (err) {
    console.error("Session save error:", err);
    return res.status(500).json({ message: "Session error" });
  }
    res.json({
      message: "Login successful",
      is_verified: user.is_verified,
      user: req.session.user,
    });
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

// ✅ Ensure uploads directory exists
const uploadDirs = path.join(__dirname, "uploads");
if (!fs.existsSync(uploadDirs)) {
  fs.mkdirSync(uploadDirs, { recursive: true });
}

// ✅ Proper Multer setup
const poststorage = multer.diskStorage({
  destination: (req, file, cb) => {
    cb(null, uploadDirs);
  },
  filename: (req, file, cb) => {
    const uniqueSuffix = Date.now() + "-" + Math.round(Math.random() * 1e9);
    const ext = path.extname(file.originalname);
    cb(null, `${file.fieldname}-${uniqueSuffix}${ext}`);
  },
});

const uploads = multer({
  storage: poststorage, // ✅ FIXED — must be `storage: poststorage`
  limits: { fileSize: 20 * 1024 * 1024 }, // 20MB per file
  fileFilter: (req, file, cb) => {
    const allowedTypes = ["image/jpeg", "image/png", "image/jpg", "image/webp"];
    if (!allowedTypes.includes(file.mimetype)) {
      return cb(new Error("Only JPEG, PNG, JPG, and WEBP files are allowed."));
    }
    cb(null, true);
  },
});

// ✅ Serve /uploads folder publicly
app.use("/postuploads", express.static(uploadDirs));

// ✅ POST route
app.post(
  "/api/posts",
  (req, res, next) => {
    uploads.array("images", 5)(req, res, (err) => {
      if (err instanceof multer.MulterError) {
        if (err.code === "LIMIT_FILE_SIZE") {
          return res.status(400).json({
            error: "Image file too large (max 20 MB per image).",
          });
        }
        return res.status(400).json({ error: err.message });
      } else if (err) {
        return res.status(400).json({ error: err.message });
      }
      next();
    });
  },
  (req, res) => {
    if (!req.session?.user) {
      return res.status(401).json({ error: "Unauthorized" });
    }

    const userId = req.session.user.id;
    const { content, location_name, lat, lon } = req.body;
    const files = req.files || [];

    if (!content && files.length === 0) {
      return res
        .status(400)
        .json({ error: "Post must have text or at least one image." });
    }

    // ✅ Step 1: Insert post
    const postSql = `
      INSERT INTO posts (user_id, content, location_name, latitude, longitude)
      VALUES (?, ?, ?, ?, ?)
    `;

    db.query(
      postSql,
      [userId, content || null, location_name || null, lat || null, lon || null],
      (error, result) => {
        if (error) {
          console.error("❌ Error creating post:", error.sqlMessage || error);
          return res.status(500).json({ error: "Internal Server Error" });
        }

        const newPostId = result.insertId;

        // ✅ Step 2: Save image URLs if any
        const imageUrls = files.map((f) => `/postuploads/${f.filename}`);
        if (imageUrls.length > 0) {
          const imgValues = imageUrls.map((url) => [newPostId, url]);
          const imgSql = "INSERT INTO post_images (post_id, image_url) VALUES ?";
          db.query(imgSql, [imgValues], (imgErr) => {
            if (imgErr) {
              console.error("⚠️ Error saving images:", imgErr.sqlMessage || imgErr);
            }
          });
        }

        // ✅ Step 3: Create notification
        const notifSql = `
          INSERT INTO notifications (type, message, related_id, user_id, created_at)
          VALUES (?, ?, ?, ?, NOW())
        `;
        db.query(
          notifSql,
          ["post", "created a new JOB POST", newPostId, userId],
          (notifErr) => {
            if (notifErr) {
              console.error("⚠️ Error creating notification:", notifErr.sqlMessage || notifErr);
            }

            // ✅ Step 4: Return post data
            res.status(201).json({
              id: newPostId,
              user_id: userId,
              content,
              images: imageUrls,
              location: location_name ? { name: location_name, lat, lon } : null,
              date_posted: new Date(),
            });
          }
        );
      }
    );
  }
);

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
      GROUP_CONCAT(pi.image_url) AS post_images,
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
    LEFT JOIN post_images pi ON pi.post_id = p.id
    LEFT JOIN events e ON n.type = 'event' AND n.related_id = e.id
    WHERE (n.user_id != ? OR n.type = 'yearbook')
    GROUP BY n.id, n.type, n.message, n.related_id, n.created_at, u.first_name, u.profile, 
             y.yearbook_name, yi.file_path, p.content, e.content, e.location_name, e.images
    ORDER BY n.created_at DESC
    LIMIT 10
  `;

  db.query(sql, [currentUserId], (err, results) => {
    if (err) {
      console.error("❌ Error fetching notifications:", err.sqlMessage || err);
      return res.status(500).json({ error: "Internal Server Error" });
    }

    // Convert CSV post_images and event_images to arrays
    const formattedResults = results.map((r) => ({
      ...r,
      post_images: r.post_images ? r.post_images.split(",") : [],
      event_images: r.event_images ? r.event_images.split(",") : [],
    }));

    res.json(formattedResults);
  });
});


// Get all posts
app.get("/api/posts", (req, res) => {
  if (!req.session.user) {
    return res.status(401).json({ error: "Unauthorized" });
  }

  const sql = `
    SELECT 
      p.id AS post_id,
      p.content,
      p.date_posted,
      p.location_name,
      p.latitude,
      p.longitude,
      u.id AS user_id,
      u.first_name,
      u.last_name,
      u.profile,
      pi.image_url
    FROM posts p
    JOIN alumni u ON p.user_id = u.id
    LEFT JOIN post_images pi ON p.id = pi.post_id
    ORDER BY p.date_posted DESC, p.id DESC
  `;

  db.query(sql, (err, results) => {
    if (err) {
      console.error("❌ Error fetching posts:", err.sqlMessage || err);
      return res.status(500).json({ error: "Internal Server Error" });
    }

    const postsMap = results.reduce((acc, row) => {
      if (!acc[row.post_id]) {
        acc[row.post_id] = {
          id: row.post_id,
          user_id: row.user_id,
          username: row.first_name,
          lastname: row.last_name,
          profile_image: row.profile,
          content: row.content,
          date_posted: row.date_posted,
          images: [],
          location: row.location_name
            ? {
                name: row.location_name,
                lat: row.latitude,
                lon: row.longitude,
              }
            : null,
        };
      }

      // ✅ Fix: Normalize image paths
      if (row.image_url) {
        const cleanUrl = row.image_url.startsWith("/")
          ? row.image_url
          : `/${row.image_url}`;
        acc[row.post_id].images.push(cleanUrl);
      }

      return acc;
    }, {});

    res.json(Object.values(postsMap));
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


app.post("/api/messages", (req, res) => {
  const { sender_id, receiver_id, message } = req.body;

  if (!sender_id || !receiver_id || !message) {
    return res.status(400).json({ error: "Missing required fields" });
  }

  const sql = `
    INSERT INTO messages (sender_id, receiver_id, message, is_seen, created_at)
    VALUES (?, ?, ?, FALSE, NOW())
  `;

  db.query(sql, [sender_id, receiver_id, message], (err, result) => {
    if (err) {
      console.error("⚠️ Error inserting message:", err);
      return res.status(500).json({ error: "Failed to send message" });
    }

    const newMessageId = result.insertId;

    // Fetch the newly inserted message to return it to frontend
    db.query("SELECT * FROM messages WHERE id = ?", [newMessageId], (err, rows) => {
      if (err) {
        console.error("⚠️ Error fetching new message:", err);
        return res.status(500).json({ error: "Message saved but fetch failed" });
      }

      res.status(200).json(rows[0]);
    });
  });
});



// ===============================
// 1️⃣ Get conversations (excluding hidden/deleted ones per user)
// ===============================
app.get("/api/messages/:userId/conversations", (req, res) => {
  const { userId } = req.params;

  const sql = `
    SELECT 
      u.id AS partner_id,
      u.first_name,
      u.last_name,
      u.profile,
      m.message AS last_message,
      m.created_at AS last_message_time,

      -- 👇 Count unseen messages sent TO this user by the partner
      (
        SELECT COUNT(*)
        FROM messages AS um
        WHERE 
          um.sender_id = u.id
          AND um.receiver_id = ?
          AND um.is_seen = 0
          AND um.deleted_by_receiver = 0
          AND um.hidden_by_receiver = 0
      ) AS unseen_count

    FROM (
      SELECT
        CASE
          WHEN sender_id = ? THEN receiver_id
          ELSE sender_id
        END AS partner_id,
        MAX(id) AS last_msg_id
      FROM messages
      WHERE 
        (
          (sender_id = ? AND deleted_by_sender = 0 AND hidden_by_sender = 0)
          OR
          (receiver_id = ? AND deleted_by_receiver = 0 AND hidden_by_receiver = 0)
        )
      GROUP BY partner_id
    ) AS conv
    JOIN messages AS m ON m.id = conv.last_msg_id
    JOIN alumni AS u ON u.id = conv.partner_id
    ORDER BY m.created_at DESC;
  `;

  db.query(sql, [userId, userId, userId, userId, userId], (err, results) => {
    if (err) {
      console.error("⚠️ Error fetching conversations:", err);
      return res.status(500).json({ error: err.message });
    }

    console.log(`✅ Conversations fetched for user ${userId}:`, results.length);
    res.json(results);
  });
});


// ===============================
// 2️⃣ Get messages between two users (excluding deleted for current user)
// ===============================
app.get("/api/messages/:senderId/:receiverId", (req, res) => {
  const { senderId, receiverId } = req.params;

  const sql = `
    SELECT *
    FROM messages
    WHERE
      (
        (sender_id = ? AND receiver_id = ? AND deleted_by_sender = 0)
        OR
        (sender_id = ? AND receiver_id = ? AND deleted_by_receiver = 0)
      )
    ORDER BY created_at ASC
  `;

  db.query(sql, [senderId, receiverId, receiverId, senderId], (err, results) => {
    if (err) {
      console.error("⚠️ Error fetching messages:", err);
      return res.status(500).json({ error: "Database error" });
    }

    res.json(results);
  });
});



// ===============================
// 3️⃣ Mark messages as seen (new!)
// ===============================
app.patch("/api/messages/:userId/:partnerId/seen", (req, res) => {
  const { userId, partnerId } = req.params;

  const sql = `
    UPDATE messages
    SET is_seen = 1
    WHERE sender_id = ? AND receiver_id = ? AND is_seen = 0
  `;

  db.query(sql, [partnerId, userId], (err, result) => {
    if (err) {
      console.error("⚠️ Mark seen error:", err);
      return res.status(500).json({ error: err.message });
    }

    console.log(`👁️ Marked ${result.affectedRows} messages as seen between ${partnerId} → ${userId}`);
    res.json({ success: true, updated: result.affectedRows });
  });
});



// ===============================
// 4️⃣ Hide conversation for a user
// ===============================
app.patch("/api/messages/:userId/:partnerId/hide", (req, res) => {
  const { userId, partnerId } = req.params;

  const sql = `
    UPDATE messages
    SET 
      hidden_by_sender = CASE WHEN sender_id = ? THEN 1 ELSE hidden_by_sender END,
      hidden_by_receiver = CASE WHEN receiver_id = ? THEN 1 ELSE hidden_by_receiver END
    WHERE (sender_id = ? AND receiver_id = ?)
       OR (sender_id = ? AND receiver_id = ?)
  `;

  db.query(sql, [userId, userId, userId, partnerId, partnerId, userId], (err) => {
    if (err) {
      console.error("Hide conversation error:", err);
      return res.status(500).json({ error: err.message });
    }
    res.json({ success: true });
  });
});



// ===============================
// 5️⃣ Unhide conversation
// ===============================
app.patch("/api/messages/:userId/:partnerId/unhide", (req, res) => {
  const { userId, partnerId } = req.params;

  const sql = `
    UPDATE messages
    SET 
      hidden_by_sender = CASE WHEN sender_id = ? THEN 0 ELSE hidden_by_sender END,
      hidden_by_receiver = CASE WHEN receiver_id = ? THEN 0 ELSE hidden_by_receiver END
    WHERE (sender_id = ? AND receiver_id = ?)
       OR (sender_id = ? AND receiver_id = ?)
  `;

  db.query(sql, [userId, userId, userId, partnerId, partnerId, userId], (err) => {
    if (err) {
      console.error("Unhide conversation error:", err);
      return res.status(500).json({ error: err.message });
    }
    res.json({ success: true });
  });
});



// ===============================
// 6️⃣ Delete conversation (soft delete per user)
// ===============================
app.delete("/api/messages/:userId/:partnerId/delete", (req, res) => {
  const { userId, partnerId } = req.params;

  const deleteSentSQL = `UPDATE messages SET deleted_by_sender = 1 WHERE sender_id = ? AND receiver_id = ?`;
  const deleteReceivedSQL = `UPDATE messages SET deleted_by_receiver = 1 WHERE receiver_id = ? AND sender_id = ?`;

  db.query(deleteSentSQL, [userId, partnerId], (err) => {
    if (err) {
      console.error("⚠️ Delete (sent) error:", err);
      return res.status(500).json({ error: err.message });
    }

    db.query(deleteReceivedSQL, [userId, partnerId], (err2) => {
      if (err2) {
        console.error("⚠️ Delete (received) error:", err2);
        return res.status(500).json({ error: err2.message });
      }
      res.json({ success: true, message: "Conversation deleted successfully" });
    });
  });
});



// ===============================
// 7️⃣ Unsend message (hard delete)
// ===============================
app.delete("/api/messages/:id", (req, res) => {
  const { id } = req.params;

  const sql = `DELETE FROM messages WHERE id = ?`;

  db.query(sql, [id], (err, result) => {
    if (err) {
      console.error("⚠️ Unsend message error:", err);
      return res.status(500).json({ error: "Failed to unsend message" });
    }

    if (result.affectedRows === 0) {
      return res.status(404).json({ error: "Message not found" });
    }

    console.log(`🚮 Message ${id} permanently deleted`);
    res.json({ success: true });
  });
});

app.get("/api/messages/users", (req, res) => {
  const currentUserId = req.session.user?.id;

  if (!currentUserId) {
    return res.status(401).json({ message: "Not logged in" });
  }

  const query = `
    SELECT 
      a.id AS partner_id,
      a.first_name AS name,
      a.profile AS profile,
      (
        SELECT m.message 
        FROM messages m 
        WHERE 
          (m.sender_id = a.id AND m.receiver_id = ?) OR 
          (m.sender_id = ? AND m.receiver_id = a.id)
        ORDER BY m.created_at DESC LIMIT 1
      ) AS last_message
    FROM alumni a
    WHERE a.id != ?
    ORDER BY a.first_name ASC
  `;

  db.query(query, [currentUserId, currentUserId, currentUserId], (err, rows) => {
    if (err) {
      console.error("Error fetching users:", err);
      return res.status(500).json({ message: "Server error" });
    }
    res.json(rows);
  });
});




// ================================
// 📦 Fill Out Later Endpoints
// ================================

// 1️⃣ GET /api/getlatercount
app.get("/api/getlatercount", (req, res) => {
  if (!req.session.user) {
    return res.status(401).json({ success: false, message: "Unauthorized" });
  }

  const userId = req.session.user.id;

  db.query(
    "SELECT later_count FROM alumni WHERE id = ?",
    [userId],
    (err, rows) => {
      if (err) {
        console.error("Error fetching later_count:", err);
        return res.status(500).json({ success: false, message: "Database error" });
      }

      if (rows.length === 0) {
        return res.status(404).json({ success: false, message: "User not found" });
      }

      res.json({ success: true, count: rows[0].later_count || 0 });
    }
  );
});

// 2️⃣ POST /api/incrementlater
app.post("/api/incrementlater", (req, res) => {
  if (!req.session.user) {
    return res.status(401).json({ success: false, message: "Unauthorized" });
  }

  const userId = req.session.user.id;
  const LATER_LIMIT = 3;

  // Get current count
  db.query("SELECT later_count FROM alumni WHERE id = ?", [userId], (err, rows) => {
    if (err) {
      console.error("Error fetching later_count:", err);
      return res.status(500).json({ success: false, message: "Database error" });
    }

    if (rows.length === 0) {
      return res.status(404).json({ success: false, message: "User not found" });
    }

    const currentCount = rows[0].later_count || 0;

    if (currentCount >= LATER_LIMIT) {
      return res.status(400).json({ success: false, message: "Limit reached" });
    }

    // Increment later_count
    db.query(
      "UPDATE alumni SET later_count = later_count + 1 WHERE id = ?",
      [userId],
      (updateErr) => {
        if (updateErr) {
          console.error("Error updating later_count:", updateErr);
          return res.status(500).json({ success: false, message: "Failed to update count" });
        }

        // Optional: Update the session data too
        req.session.user.later_count = currentCount + 1;

        res.json({ success: true });
      }
    );
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

// 📅 Post an Event
app.post("/api/events", eventupload.array("images", 5), (req, res) => {
  if (!req.session.user) {
    return res.status(401).json({ error: "User not authenticated" });
  }

  const user_id = req.session.user.id;
  const { content, location_name, latitude, longitude } = req.body;

  // ✅ If no images, still allow posting
  const imagePaths = req.files && req.files.length > 0
    ? req.files.map((file) => `/uploads/${file.filename}`)
    : [];

  // ✅ Insert into events (images optional)
  const sql = `
    INSERT INTO events (user_id, content, location_name, latitude, longitude, images) 
    VALUES (?, ?, ?, ?, ?, ?)
  `;

  db.query(
    sql,
    [user_id, content, location_name || null, latitude || null, longitude || null, JSON.stringify(imagePaths)],
    (err, result) => {
      if (err) {
        console.error("❌ Event insert error:", err);
        return res.status(500).json({ error: err.message });
      }

      const newEventId = result.insertId;
      const message = `posted a new EVENT.`;

      // 🔔 Insert notification
      const notifSql = `
        INSERT INTO notifications (type, message, related_id, user_id, created_at)
        VALUES (?, ?, ?, ?, NOW())
      `;
      db.query(notifSql, ["event", message, newEventId, user_id], (notifErr) => {
        if (notifErr) {
          console.error("❌ Notification error:", notifErr.message || notifErr);
          // Not critical, so continue
        }

        res.json({
          success: true,
          message: "Event posted successfully!",
          event_id: newEventId,
          images: imagePaths,
        });
      });
    }
  );
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

// Update Event
app.put("/api/events/:id", (req, res) => {
  const { id } = req.params;
  const { content } = req.body;

  const sql = "UPDATE events SET content = ? WHERE id = ?";
  db.query(sql, [content, id], (err, result) => {
    if (err) {
      console.error("❌ Error updating event:", err);
      return res.status(500).json({ success: false, error: err.message });
    }
    res.json({ success: true });
  });
});

app.get("/cloudinary-signature", (req, res) => {
  const timestamp = Math.round(new Date().getTime() / 1000);
  const paramsToSign = {
    timestamp,
    folder: `yearbooks/${req.query.folder || "default"}`
  };
  const signature = cloudinary.utils.api_sign_request(paramsToSign, process.env.CLOUDINARY_API_SECRET);

  res.json({
    timestamp,
    signature,
    apiKey: process.env.CLOUDINARY_API_KEY,
    cloudName: process.env.CLOUDINARY_CLOUD_NAME,
  });
  console.log("✅ Uploaded:", uploadResult.secure_url);
});

// Multer Storage (Save files inside `/uploads`)
const storage = new CloudinaryStorage({
  cloudinary: cloudinary,
  params: async (req, file) => {
    const folderName = req.body.folderName || "default";
    return {
      folder: `yearbooks/${folderName}`,
      public_id: file.originalname.split(".")[0],
      resource_type: "auto", // allows images, pdfs, etc.
    };
  },
});


const upload = multer({ storage });

app.use("/uploads", express.static("uploads"));

// Upload Yearbook Folder with Multiple Files and Student Names from Excel
app.post("/upload-yearbook", upload.single("studentNames"), (req, res) => {
  const { folderName, yearbookName } = req.body;

  // ❌ imageUrls from req.body
  let imageUrls = req.body.imageUrls;

  // Multer does not parse arrays with [] automatically, fix it:
  if (!imageUrls) {
    return res.status(400).json({ message: "Missing folder or image URLs" });
  }

  // If only 1 URL, make it an array
  if (!Array.isArray(imageUrls)) imageUrls = [imageUrls];

  // Insert yearbook info
  const insertYearbookQuery = "INSERT INTO yearbooks (folder_name, yearbook_name) VALUES (?, ?)";
  db.query(insertYearbookQuery, [folderName, yearbookName], (err, result) => {
    if (err) return res.status(500).json({ error: "Database error" });

    const yearbookId = result.insertId;

    // Insert images
    const imageValues = imageUrls.map((url) => [yearbookId, path.basename(url), url]);
    const insertImagesQuery = "INSERT INTO images (yearbook_id, file_name, file_path) VALUES ?";
    db.query(insertImagesQuery, [imageValues], (err) => {
      if (err) return res.status(500).json({ error: "Error saving image URLs" });
    });

    // Process student Excel
    if (req.file) {
      const workbook = xlsx.readFile(req.file.path);
      const sheet = workbook.Sheets[workbook.SheetNames[0]];
      const sheetData = xlsx.utils.sheet_to_json(sheet);
      const studentValues = sheetData.map((r) => [yearbookId, r["First Name"], r["Last Name"]]);

      db.query("INSERT INTO students (yearbook_id, first_name, last_name) VALUES ?", [studentValues], (err) => {
        if (err) console.error("Error saving students:", err);
      });
    }

    // Create notification
    const notifQuery = "INSERT INTO notifications (type, message, related_id, created_at) VALUES (?, ?, ?, NOW())";
    db.query(notifQuery, ["yearbook", `A new yearbook "${yearbookName}" was uploaded.`, yearbookId]);

    res.json({ message: "Yearbook uploaded successfully!" });
  });
});

// 🟢 Get All Yearbooks
app.get("/yearbooks", (req, res) => {
  const query = "SELECT * FROM yearbooks ORDER BY date_uploaded DESC";
  db.query(query, (err, results) => {
    if (err) {
      console.error("❌ Error fetching yearbooks:", err);
      return res.status(500).json({ error: "Database error while fetching yearbooks" });
    }
    res.json(results);
  });
});


// 🟢 Get Yearbook Count
app.get("/yearbooks/count", (req, res) => {
  const query = "SELECT COUNT(*) AS count FROM yearbooks";
  db.query(query, (err, results) => {
    if (err) {
      console.error("❌ Error counting yearbooks:", err);
      return res.status(500).json({ error: "Database error while counting yearbooks" });
    }
    res.json(results[0]);
  });
});


// 🟢 Get Images for a Specific Yearbook
app.get("/yearbook/:id/images", (req, res) => {
  const query = "SELECT file_path FROM images WHERE yearbook_id = ?";
  
  db.query(query, [req.params.id], (err, results) => {
    if (err) {
      console.error("❌ Error fetching images:", err);
      return res.status(500).json({ error: "Database error while fetching images" });
    }

    const images = results.map((img) => {
      if (!img.file_path) return img;

      const filePath = img.file_path.replace(/\\/g, "/"); // normalize backslashes

      // 🟢 If it's a Cloudinary URL, return as is
      if (filePath.startsWith("http") && filePath.includes("cloudinary.com")) {
        return { ...img, file_path: filePath };
      }

      // 🟡 Otherwise, assume it's a local file
      return {
        ...img,
        file_path: `https://server-1-gjvd.onrender.com/${filePath}`,
      };
    });

    res.json(images);
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

// CREATE WORK EXPERIENCE
app.post("/api/work", async (req, res) => {
  try {
    // ✅ Ensure user is logged in
    if (!req.session.user || !req.session.user.id) {
      return res.status(401).json({ success: false, message: "Not logged in" });
    }
    const userId = req.session.user.id;

    const { position, company, location, startDate, endDate, description, isCurrent } = req.body;

    // ✅ Validate required fields
    if (!position || !company) {
      return res.status(400).json({ message: "Position and company are required." });
    }

    const query = `
      INSERT INTO work_experiences (user_id, position, company, location, start_date, end_date, description, is_current)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?)
    `;
    const result = await db.query(query, [
      userId,
      position,
      company,
      location || "",
      startDate || null,
      endDate || null,
      description || "",
      isCurrent ? 1 : 0,
    ]);

    res.status(201).json({ success: true, id: result.insertId });
  } catch (err) {
    console.error("Error saving work:", err);
    res.status(500).json({ message: "Server error while saving work." });
  }
});
// UPDATE WORK EXPERIENCE
app.put("/api/work/:id", (req, res) => {
  // ✅ Ensure user is logged in
  if (!req.session.user || !req.session.user.id) {
    return res.status(401).json({ success: false, message: "Not logged in" });
  }

  const userId = req.session.user.id;
  const workId = req.params.id;

  const { position, company, location, startDate, endDate, description, isCurrent } = req.body;

  // ✅ Validate required fields
  if (!position || !company) {
    return res.status(400).json({ success: false, message: "Position and company are required." });
  }

  const query = `
    UPDATE work_experiences
    SET position = ?, company = ?, location = ?, start_date = ?, end_date = ?, description = ?, is_current = ?
    WHERE id = ? AND user_id = ?
  `;

  db.query(
    query,
    [
      position,
      company,
      location || "",
      startDate || null,
      endDate || null,
      description || "",
      isCurrent ? 1 : 0,
      workId,
      userId,
    ],
    (err, result) => {
      if (err) {
        console.error("❌ Error updating work:", err);
        return res.status(500).json({ success: false, message: "Server error while updating work." });
      }

      if (result.affectedRows === 0) {
        return res.status(404).json({ success: false, message: "Record not found or not owned by user" });
      }

      res.json({ success: true, message: "Work experience updated successfully." });
    }
  );
});



app.get("/api/work", (req, res) => {
  if (!req.session.user || !req.session.user.id) {
    return res.status(401).json({ error: "Not logged in" });
  }

  const userId = req.session.user.id;

  const query = `
    SELECT *
    FROM work_experiences
    WHERE user_id = ?
    ORDER BY start_date DESC
  `;

  db.query(query, [userId], (err, results) => {
    if (err) {
      console.error("Database error fetching work:", err);
      return res.status(500).json({ error: "Database error while fetching work" });
    }

    res.json(results); // ✅ send all works as array
  });
});


app.post("/api/education", (req, res) => {
  if (!req.session.user || !req.session.user.id) {
    return res.status(401).json({ success: false, message: "Not logged in" });
  }

  const userId = req.session.user.id;
  const {
    programType,
    fieldOfStudy,
    institutionName,
    institutionLocation,
    startDate,
    endDate,
    isCompleted,
  } = req.body;

  const query = `
    INSERT INTO education (
      user_id, program_type, field_of_study,
      institution_name, institution_location,
      start_date, end_date, is_completed,
      created_at, updated_at
    )
    VALUES (?, ?, ?, ?, ?, ?, ?, ?, NOW(), NOW())
  `;

  db.query(
    query,
    [
      userId,
      programType,
      fieldOfStudy,
      institutionName,
      institutionLocation,
      startDate,
      endDate,
      isCompleted ? 1 : 0,
    ],
    (err, result) => {
      if (err) {
        console.error("❌ Error saving education:", err);
        return res.status(500).json({ success: false, message: "Database error" });
      }

      res.json({ success: true, id: result.insertId });
    }
  );
});
app.put("/api/education/:id", (req, res) => {
  if (!req.session.user || !req.session.user.id) {
    return res.status(401).json({ success: false, message: "Not logged in" });
  }

  const userId = req.session.user.id;
  const educationId = req.params.id;

  const {
    programType,
    fieldOfStudy,
    institutionName,
    institutionLocation,
    startDate,
    endDate,
    isCompleted,
  } = req.body;

  const query = `
    UPDATE education
    SET program_type = ?, field_of_study = ?, institution_name = ?, 
        institution_location = ?, start_date = ?, end_date = ?, 
        is_completed = ?, updated_at = NOW()
    WHERE id = ? AND user_id = ?
  `;

  db.query(
    query,
    [
      programType,
      fieldOfStudy,
      institutionName,
      institutionLocation,
      startDate,
      endDate,
      isCompleted ? 1 : 0,
      educationId,
      userId,
    ],
    (err, result) => {
      if (err) {
        console.error("❌ Error updating education:", err);
        return res.status(500).json({ success: false, message: "Database error" });
      }

      if (result.affectedRows === 0) {
        return res.status(404).json({ success: false, message: "Record not found or not owned by user" });
      }

      res.json({ success: true });
    }
  );
});



app.get("/api/education", (req, res) => {
  if (!req.session.user || !req.session.user.id) {
    return res.status(401).json({ success: false, message: "Not logged in" });
  }

  const userId = req.session.user.id;
  const query = `
    SELECT id, program_type AS programType, field_of_study AS fieldOfStudy,
           institution_name AS institutionName, institution_location AS institutionLocation,
           start_date AS startDate, end_date AS endDate, is_completed AS isCompleted
    FROM education
    WHERE user_id = ?
    ORDER BY start_date DESC
  `;

  db.query(query, [userId], (err, results) => {
    if (err) {
      console.error("Error fetching education:", err);
      return res.status(500).json({ success: false, message: "Database error" });
    }
    res.json({ success: true, data: results });
  });
});

// ✅ Get latest education for logged-in user
app.get("/api/education/latest", (req, res) => {
  if (!req.session.user || !req.session.user.id) {
    return res.status(401).json({ success: false, message: "Not logged in" });
  }

  const userId = req.session.user.id;

  const query = `
    SELECT *
    FROM education
    WHERE user_id = ?
    ORDER BY end_date DESC, created_at DESC
    LIMIT 1
  `;

  db.query(query, [userId], (err, results) => {
    if (err) {
      console.error("❌ Error fetching latest education:", err);
      return res.status(500).json({ success: false, message: "Database error" });
    }

    if (results.length === 0) {
      return res.json(null); // No education data
    }

    res.json(results[0]);
  });
});


// Get all alumni work data
app.get("/api/workdata", (req, res) => {
  const query = `
    SELECT w.*, a.course, a.year_graduate
    FROM work_experiences w
    INNER JOIN (
      SELECT user_id, MAX(created_at) AS latest
      FROM work_experiences
      GROUP BY user_id
    ) latest_work ON w.user_id = latest_work.user_id AND w.created_at = latest_work.latest
    LEFT JOIN alumni a ON w.user_id = a.id
  `;

  db.query(query, (err, results) => {
    if (err) {
      console.error("Error fetching latest work data:", err);
      return res.status(500).json({ message: "Database error" });
    }
    res.json(results);
  });
});

// Get all alumni education data
app.get("/api/educationdata", (req, res) => {
  const query = `
    SELECT e.*, a.course, a.year_graduate
    FROM education e
    LEFT JOIN alumni a ON e.user_id = a.id
  `;
  db.query(query, (err, results) => {
    if (err) {
      console.error("Error fetching education data:", err);
      return res.status(500).json({ message: "Database error" });
    }
    res.json(results);
  });
});

app.get("/api/allalumni", (req, res) => {
  const query = `
    SELECT 
      id,
      first_name,
      last_name,
      course,
      year_graduate
    FROM alumni
    WHERE course IS NOT NULL AND year_graduate IS NOT NULL
    ORDER BY year_graduate DESC;
  `;

  db.query(query, (err, results) => {
    if (err) {
      console.error("Error fetching alumni data:", err);
      return res.status(500).json({ error: "Database query failed" });
    }

    res.json(results);
  });
});

app.get("/api/alumni_profiles", (req, res) => {
  const query = `
    SELECT 
      a.id AS alumni_id,
      CONCAT(a.last_name, ' ', a.first_name) AS full_name,
      a.course,
      a.year_graduate,
      w.company AS current_work,
      w.position AS current_position,
      e.institution_name AS pursuing_school,
      e.program_type AS pursuing_degree,
      CASE WHEN e.id IS NOT NULL THEN TRUE ELSE FALSE END AS is_pursuing_education
    FROM alumni a

    -- Latest work experience per user
    LEFT JOIN (
      SELECT w1.*
      FROM work_experiences w1
      INNER JOIN (
        SELECT user_id, MAX(created_at) AS latest
        FROM work_experiences
        GROUP BY user_id
      ) w2 ON w1.user_id = w2.user_id AND w1.created_at = w2.latest
    ) w ON w.user_id = a.id

    -- Latest education per user
    LEFT JOIN (
      SELECT e1.*
      FROM education e1
      INNER JOIN (
        SELECT user_id, MAX(created_at) AS latest
        FROM education
        GROUP BY user_id
      ) e2 ON e1.user_id = e2.user_id AND e1.created_at = e2.latest
    ) e ON e.user_id = a.id

    WHERE a.role = 'alumni'
    ORDER BY a.year_graduate DESC;
  `;

  db.query(query, (err, results) => {
    if (err) {
      console.error("Error fetching alumni profiles:", err);
      return res.status(500).json({ error: "Database query failed" });
    }
    res.json(results);
  });
});


// ✅ Route: Get latest work experience by user ID
app.get("/api/work/latest", (req, res) => {
  if (!req.session.user || !req.session.user.id) {
    return res.status(401).json({ error: "Not logged in" });
  }

  const userId = req.session.user.id;

  const query = `
    SELECT *
    FROM work_experiences
    WHERE user_id = ? AND is_current = 1
    ORDER BY created_at DESC
    LIMIT 1
  `;

  db.query(query, [userId], (err, results) => {
    if (err) {
      console.error("Error fetching latest work:", err);
      return res.status(500).json({ error: "Database error" });
    }

    if (results.length === 0) {
      return res.json({ message: "No current work record found" });
    }

    res.json(results[0]);
  });
});

app.get("/api/alumni", (req, res) => {
  const getAlumniQuery = `
    SELECT *
    FROM alumni
    WHERE role = 'alumni'
  `;

  db.query(getAlumniQuery, (err, alumniResults) => {
    if (err) {
      console.error("Error fetching alumni:", err);
      return res.status(500).json({ message: "Database error (alumni)" });
    }

    if (alumniResults.length === 0) {
      return res.json([]);
    }

    // Get all alumni IDs to fetch work & education for all of them
    const alumniIds = alumniResults.map(a => a.id);

    // Queries for related data
    const workQuery = `
      SELECT *
      FROM work_experiences
      WHERE user_id IN (?)
      ORDER BY start_date DESC
    `;
    const educationQuery = `
      SELECT id, user_id, program_type AS programType, field_of_study AS fieldOfStudy,
             institution_name AS institutionName, institution_location AS institutionLocation,
             start_date AS startDate, end_date AS endDate, is_completed AS isCompleted
      FROM education
      WHERE user_id IN (?)
      ORDER BY start_date DESC
    `;

    // Fetch work & education in parallel
    db.query(workQuery, [alumniIds], (err, workResults) => {
      if (err) {
        console.error("Error fetching work:", err);
        return res.status(500).json({ message: "Database error (work)" });
      }

      db.query(educationQuery, [alumniIds], (err, educationResults) => {
        if (err) {
          console.error("Error fetching education:", err);
          return res.status(500).json({ message: "Database error (education)" });
        }

        // Combine all data by alumni
        const combined = alumniResults.map(alumni => ({
          ...alumni,
          work: workResults.filter(w => w.user_id === alumni.id),
          education: educationResults.filter(e => e.user_id === alumni.id)
        }));

        res.json(combined);
      });
    });
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
  const userId = req.session.user?.id;
  const answers = JSON.stringify(req.body);

  if (!userId) {
    return res.status(401).json({ success: false, error: "User not logged in" });
  }

  // First insert the survey submission with user ID
  db.query(
    "INSERT INTO survey_submissions (user_id, submission_json) VALUES (?, ?)",
    [userId, answers],
    function (err) {
      if (err) {
        console.error("Error saving survey:", err);
        return res.status(500).json({ success: false, error: err.message });
      }

      // After successful insert, update alumni table
      db.query(
        "UPDATE alumni SET has_submitted_survey = 1 WHERE id = ?",
        [userId],
        (err) => {
          if (err) {
            console.error("Error updating survey status:", err);
            return res
              .status(500)
              .json({ success: false, error: "Failed to update alumni survey status" });
          }

          // Update session
          req.session.user.has_submitted_survey = 1;

          // Final response
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
app.get("/api/allsubmissions", (req, res) => {
  const query = `
    SELECT s.id AS submission_id, s.answers_json AS submission_json, s.created_at,
           a.id AS user_id, a.first_name, a.course, a.year_graduate
    FROM submissions s
    LEFT JOIN alumni a ON s.user_id = a.id

    UNION ALL

    SELECT ss.id AS submission_id, ss.submission_json, ss.created_at,
           a.id AS user_id, a.first_name, a.course, a.year_graduate
    FROM survey_submissions ss
    LEFT JOIN alumni a ON ss.user_id = a.id

    ORDER BY created_at DESC
  `;

  db.query(query, (err, rows) => {
    if (err) {
      console.error("Error fetching merged submissions:", err);
      return res.status(500).json({ success: false, error: err.message });
    }

    const data = rows.map((r) => {
      let parsed;
      try {
        parsed = JSON.parse(r.submission_json);
      } catch {
        parsed = {};
      }

      // ✅ Normalize array format if needed
      if (Array.isArray(parsed)) {
        parsed = parsed.reduce((acc, item) => {
          if (item.label && item.value) acc[item.label] = item.value;
          return acc;
        }, {});
      }

      // ✅ Flatten nested objects (tables) — keep only string/array answers
      const cleaned = {};
      for (const [key, val] of Object.entries(parsed)) {
        if (typeof val === "string" || Array.isArray(val)) {
          cleaned[key] = val;
        } else if (
          val &&
          typeof val === "object" &&
          "rows" in val &&
          "columns" in val &&
          "values" in val
        ) {
          // skip table-like entries
          continue;
        }
      }

      return {
        user_id: r.user_id,
        user: {
          first_name: r.first_name || "Unknown",
          course: r.course || "Unknown Program",
          year_graduate: r.year_graduate || "Unknown Year",
        },
        submission: cleaned,
        created_at: r.created_at,
      };
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

// ✅ Save employer response with token verification
app.post("/api/feedback-response", (req, res) => {
  const { schema_id, response, token } = req.body;
  const responseString = JSON.stringify(response || req.body);

  if (!token) {
    return res.status(400).json({ success: false, error: "Token is required" });
  }

  // ✅ Find alumni_id based on token
  const findTokenQuery = "SELECT alumni_id FROM employer_tokens WHERE token = ?";
  db.query(findTokenQuery, [token], (err, rows) => {
    if (err) {
      console.error("❌ Token lookup error:", err);
      return res.status(500).json({ success: false, error: "Database error" });
    }

    if (rows.length === 0) {
      return res.status(400).json({ success: false, error: "Invalid or expired token" });
    }

    const alumni_id = rows[0].alumni_id;

    // ✅ Insert feedback response
    const insertQuery = `
      INSERT INTO feedback_responses (schema_id, alumni_id, response_json)
      VALUES (?, ?, ?)
    `;
    db.query(insertQuery, [schema_id, alumni_id, responseString], (err, result) => {
      if (err) {
        console.error("❌ DB Insert Error:", err);
        return res.status(500).json({ success: false, error: err.message });
      }

      // ✅ Optionally mark token as used
      db.query("UPDATE employer_tokens SET used = 1 WHERE token = ?", [token]);

      console.log("✅ Feedback Saved for Alumni ID:", alumni_id);
      res.json({ success: true, id: result.insertId });
    });
  });
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

const MAX_INVITES_PER_MONTH = 2;

app.post("/api/sendemployerinvite", (req, res) => {
  try {
    if (!req.session?.user?.id) {
      return res.status(401).json({ success: false, message: "Not logged in" });
    }

    const alumniId = req.session.user.id;
    const { employerName, employerEmail, sendAutomatically } = req.body;

    const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    if (!emailRegex.test(employerEmail)) {
      return res.status(400).json({ success: false, message: "Invalid email address" });
    }

    db.query(
      "SELECT employer_invite_count, invite_last_reset FROM alumni WHERE id = ?",
      [alumniId],
      (err, result) => {
        if (err) {
          console.error("DB error (check invite count):", err);
          return res.status(500).json({ success: false, message: "Server error" });
        }

        const now = new Date();
        const thisMonth = `${now.getFullYear()}-${now.getMonth() + 1}`;
        const lastReset = result[0]?.invite_last_reset;
        let currentCount = result[0]?.employer_invite_count || 0;
        const lastMonth =
          lastReset &&
          `${new Date(lastReset).getFullYear()}-${new Date(lastReset).getMonth() + 1}`;

        if (lastMonth !== thisMonth) {
          currentCount = 0;
          db.query(
            "UPDATE alumni SET employer_invite_count = 0, invite_last_reset = ? WHERE id = ?",
            [now, alumniId]
          );
        }

        if (currentCount >= MAX_INVITES_PER_MONTH) {
          return res.json({
            success: false,
            message: `You have reached your monthly limit of ${MAX_INVITES_PER_MONTH} invitations.`,
          });
        }

        db.query("SELECT id FROM employers WHERE email = ?", [employerEmail], (err2, results) => {
          if (err2) {
            console.error("DB error (employer lookup):", err2);
            return res.status(500).json({ success: false, message: "Database error" });
          }

          const employerId = results.length ? results[0].id : null;

          const handleEmployer = async (employerId) => {
            const token = crypto.randomBytes(32).toString("hex");
            const expiresAt = new Date(Date.now() + 7 * 24 * 60 * 60 * 1000);

            db.query(
              `INSERT INTO employer_tokens (alumni_id, employer_id, token, expires_at, used)
               VALUES (?, ?, ?, ?, false)`,
              [alumniId, employerId, token, expiresAt],
              async (err3) => {
                if (err3) {
                  console.error("DB error (token insert):", err3);
                  return res.status(500).json({ success: false, message: "Failed to generate link" });
                }

                db.query(
                  `UPDATE alumni 
                   SET employer_invite_count = employer_invite_count + 1,
                       invite_last_reset = ?
                   WHERE id = ?`,
                  [now, alumniId]
                );

                const link = `https://stii-memotrace.onrender.com/Efeedback?token=${token}`;
                const alumniName = req.session.user.full_name || "One of our alumni";

                if (sendAutomatically) {
                  try {
                    const brevoResponse = await fetch("https://api.brevo.com/v3/smtp/email", {
                      method: "POST",
                      headers: {
                        "Content-Type": "application/json",
                        "api-key": process.env.BREVO_API_KEY,
                      },
                      body: JSON.stringify({
                        sender: { name: "STII Alumni Office", email: process.env.SMTP_USER },
                        to: [{ email: employerEmail }],
                        subject: "Employer Feedback Request",
                        htmlContent: `
                          <p>Dear ${employerName},</p>
                          <p>${alumniName} listed you as their employer. Please complete our short feedback survey.</p>
                          <p><a href="${link}" target="_blank">Click here to provide feedback</a></p>
                          <p>This link expires in 7 days.</p>
                        `,
                        textContent: `
Dear ${employerName},

${alumniName} listed you as their employer. Please complete our short feedback survey:

${link}

This link expires in 7 days.
                        `,
                      }),
                    });

                    const data = await brevoResponse.json();
                    if (!brevoResponse.ok) {
                      console.error("❌ Brevo API error:", data);
                      return res.status(500).json({ success: false, message: "Failed to send email." });
                    }

                    console.log(`✅ Employer feedback email sent to: ${employerEmail}`);
                    return res.json({
                      success: true,
                      message: `Invitation sent to ${employerEmail}. (${currentCount + 1}/${MAX_INVITES_PER_MONTH} this month)`,
                    });

                  } catch (emailErr) {
                    console.error("❌ Error sending employer feedback email:", emailErr);
                    return res.status(500).json({ success: false, message: "Failed to send email." });
                  }
                } else {
                  return res.json({
                    success: true,
                    message: `Invitation link generated. (${currentCount + 1}/${MAX_INVITES_PER_MONTH} this month)`,
                    inviteLink: link,
                  });
                }
              }
            );
          };

          if (!employerId) {
            db.query(
              "INSERT INTO employers (name, email) VALUES (?, ?)",
              [employerName, employerEmail],
              (insertErr, insertResult) => {
                if (insertErr) {
                  console.error("Employer insert error:", insertErr);
                  return res.status(500).json({ success: false, message: "Failed to add employer" });
                }
                handleEmployer(insertResult.insertId);
              }
            );
          } else {
            handleEmployer(employerId);
          }
        });
      }
    );
  } catch (err) {
    console.error("❌ Error sending employer invite:", err);
    res.status(500).json({ success: false, message: "Server error" });
  }
});

// ✅ Get current invite count for logged-in alumni
app.get("/api/employer-invite-count", (req, res) => {
  try {
    if (!req.session?.user?.id) {
      return res.status(401).json({ success: false, message: "Not logged in" });
    }

    const alumniId = req.session.user.id;

    db.query(
      "SELECT employer_invite_count, invite_last_reset FROM alumni WHERE id = ?",
      [alumniId],
      (err, result) => {
        if (err) {
          console.error("DB error (get invite count):", err);
          return res.status(500).json({ success: false, message: "Server error" });
        }

        if (result.length === 0) {
          return res.status(404).json({ success: false, message: "Alumni not found" });
        }

        const now = new Date();
        const thisMonth = `${now.getFullYear()}-${now.getMonth() + 1}`;
        const lastReset = result[0].invite_last_reset;
        const lastMonth =
          lastReset &&
          `${new Date(lastReset).getFullYear()}-${new Date(lastReset).getMonth() + 1}`;

        // Reset if new month
        if (lastMonth !== thisMonth) {
          db.query(
            "UPDATE alumni SET employer_invite_count = 0, invite_last_reset = ? WHERE id = ?",
            [now, alumniId]
          );
          return res.json({ success: true, count: 0 });
        }

        // ✅ Return existing count
        res.json({
          success: true,
          count: result[0].employer_invite_count || 0,
        });
      }
    );
  } catch (err) {
    console.error("❌ Error fetching invite count:", err);
    res.status(500).json({ success: false, message: "Server error" });
  }
});


app.use(express.static(path.join(__dirname, "build")));
app.get("*", (req, res) => {
  res.sendFile(path.join(__dirname, "build", "index.html"));
});

// Start Server
const PORT = process.env.PORT || 5000;  // 5000 for local dev
app.listen(PORT, () => console.log(`Server running on port ${PORT}`));
