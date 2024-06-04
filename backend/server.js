const express = require("express");
const mysql = require('mysql');
const cors = require('cors');
const bcrypt = require('bcryptjs')
const app = express()
app.use(cors());
app.use(express.json());


const db = mysql.createConnection({
    host: "localhost",
    user: "appuser",
    password: "app2027",
    database: "signup"
})

// app.post('/signup', (req,res) => {
//     const sql = "INSERT INTO login (name,email,hashedpassword) VALUES ?";
//     const values = [
//         [req.body.name,req.body.email,req.body.password]
//     ];
//     db.query(sql,[values], (err,data) => {
//         if(err) {
//             return res.json("Error");
//         }
//         return res.json(data);
//     })
// })
const saltRounds = 10;
app.post('/signup', (req,res) => {
    const {name, email, password} = req.body;

    //Hash password
    bcrypt.hash(String(password), saltRounds, (err, hashedPassword) => {
        if(err) {
            console.error("error hashing password", err)
            return res.status(500).json("Error hashing password");
        }
        console.log(hashedPassword)
        const sql = "INSERT INTO login (name, email, hashedpassword) VALUES (?, ?, ?)";
        const values = [name, email, hashedPassword];
        db.query(sql, values, (dbErr, result) => {
            if(dbErr) {
                console.error("Error inserting data", dbErr)
                return res.status(500).json("Error when inserting user data")
            }
            console.log("data inserted successfully:", result)
            return res.status(200).json("User registered")
        });
    });
});
// app.post('/login', (req,res) => {
//     const sql = "SELECT * FROM login WHERE `email` = ? AND `hashedpassword` = ?";
    
//     db.query(sql,[req.body.email,req.body.password], (err,data) => {
//         if(err) {
//             return res.json("Error");
//         }
//         if(data.length > 0) {
//             return res.json("Success");
//         } else {
//             return res.json("Failed")
//         }
//     })
// })
app.post('/login', (req, res) => {
    const { email, password } = req.body;

    const sql = "SELECT hashedpassword FROM login WHERE email=?";
    db.query(sql, email, (err, results) => {
        if (err) {
            console.error("Error querying database", err);
            return res.status(500).json("Error querying database");
        }
        
        if (results.length === 0) {
            console.log("User not found for email:", email);
            return res.status(401).json("User not found");
        }

        const hashedPassword = results[0].hashedpassword;

        // Compare inputed password with hashed password from database
        bcrypt.compare(String(password), hashedPassword, (bcryptErr, isMatch) => {
            if (bcryptErr) {
                console.error("Error comparing passwords:", bcryptErr);
                return res.status(500).json("Error comparing passwords");
            }

            if (isMatch) {
                return res.status(200).json("Success");
            } else {
                return res.status(401).json("Incorrect password");
            }
        });
    });
});

app.listen (8081, ()=> {
    console.log("listening")
})