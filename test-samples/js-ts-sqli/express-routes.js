// Sample vulnerable Express.js routes with SQL injection vulnerabilities
// This file demonstrates common SQLi patterns in Express route handlers

const express = require('express');
const mysql = require('mysql2');

const app = express();
const db = mysql.createConnection({
  host: 'localhost',
  user: 'root',
  password: 'password',
  database: 'testdb'
});

app.use(express.json());

// VULN: SQL Injection - req.query parameter concatenation
app.get('/user', (req, res) => {
  const userId = req.query.id;
  // Line 19: Critical SQLi - direct concatenation of user input into SQL query
  const query = 'SELECT * FROM users WHERE id = ' + userId;

  db.query(query, (err, results) => {
    if (err) throw err;
    res.json(results);
  });
});

// VULN: SQL Injection - req.params concatenation
app.get('/product/:id', (req, res) => {
  const productId = req.params.id;
  // Line 31: Critical SQLi - URL parameter directly concatenated into query
  const sql = `SELECT * FROM products WHERE id = ${productId}`;

  db.query(sql, (error, rows) => {
    if (error) throw error;
    res.send(rows);
  });
});

// VULN: SQL Injection - req.body in POST request
app.post('/login', (req, res) => {
  const username = req.body.username;
  const password = req.body.password;
  // Line 45: Critical SQLi - POST body parameters in SQL string
  const query = `SELECT * FROM users WHERE username = '${username}' AND password = '${password}'`;

  db.query(query, (err, results) => {
    if (err) throw err;
    if (results.length > 0) {
      res.json({ success: true, user: results[0] });
    } else {
      res.status(401).json({ success: false });
    }
  });
});

// VULN: SQL Injection - ORDER BY clause
app.get('/users', (req, res) => {
  const sortBy = req.query.sort || 'id';
  const order = req.query.order || 'ASC';
  // Line 63: High SQLi - dynamic ORDER BY with user input
  const query = `SELECT * FROM users ORDER BY ${sortBy} ${order}`;

  db.query(query, (err, results) => {
    if (err) throw err;
    res.json(results);
  });
});

app.listen(3000, () => {
  console.log('Server running on port 3000');
});

module.exports = app;
