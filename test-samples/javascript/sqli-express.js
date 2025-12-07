// Sample vulnerable Express.js code with SQL injection vulnerabilities

const express = require('express');
const mysql = require('mysql');
const app = express();

const db = mysql.createConnection({
  host: 'localhost',
  user: 'root',
  password: 'password',
  database: 'testdb'
});

// VULNERABLE: SQL injection via req.query
app.get('/user', (req, res) => {
  const userId = req.query.id;
  const query = 'SELECT * FROM users WHERE id = ' + userId; // SQLi vulnerability

  db.query(query, (err, results) => {
    if (err) throw err;
    res.json(results);
  });
});

// VULNERABLE: SQL injection via req.params
app.get('/product/:id', (req, res) => {
  const productId = req.params.id;
  const sql = `SELECT * FROM products WHERE id = ${productId}`; // SQLi vulnerability

  db.query(sql, (error, rows) => {
    if (error) throw error;
    res.send(rows);
  });
});

// VULNERABLE: SQL injection via req.body
app.post('/login', (req, res) => {
  const username = req.body.username;
  const password = req.body.password;
  const query = "SELECT * FROM users WHERE username = '" + username + "' AND password = '" + password + "'"; // SQLi vulnerability

  db.query(query, (err, results) => {
    if (err) throw err;
    if (results.length > 0) {
      res.json({ success: true });
    } else {
      res.json({ success: false });
    }
  });
});

// SAFE: Parameterized query (should not trigger SQLi detection)
app.get('/safe-user', (req, res) => {
  const userId = req.query.id;
  const query = 'SELECT * FROM users WHERE id = ?';

  db.query(query, [userId], (err, results) => {
    if (err) throw err;
    res.json(results);
  });
});

app.listen(3000);
