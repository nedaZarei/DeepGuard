
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

app.get('/user', (req, res) => {
  const userId = req.query.id;
  const query = 'SELECT * FROM users WHERE id = ' + userId;

  db.query(query, (err, results) => {
    if (err) throw err;
    res.json(results);
  });
});

app.get('/product/:id', (req, res) => {
  const productId = req.params.id;
  const sql = `SELECT * FROM products WHERE id = ${productId}`;

  db.query(sql, (error, rows) => {
    if (error) throw error;
    res.send(rows);
  });
});

app.post('/login', (req, res) => {
  const username = req.body.username;
  const password = req.body.password;
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

app.get('/users', (req, res) => {
  const sortBy = req.query.sort || 'id';
  const order = req.query.order || 'ASC';
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
