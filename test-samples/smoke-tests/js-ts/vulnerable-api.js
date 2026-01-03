// Vulnerable API endpoints for smoke testing
const express = require('express');
const mysql = require('mysql');

const app = express();
app.use(express.json());

// Database connection
const db = mysql.createConnection({
  host: 'localhost',
  user: 'app_user',
  password: 'password',
  database: 'myapp'
});

// SQL Injection vulnerability - string concatenation
app.get('/users/:id', (req, res) => {
  const userId = req.params.id;

  // VULNERABLE: Direct string concatenation
  const query = "SELECT * FROM users WHERE id = " + userId;

  db.query(query, (err, results) => {
    if (err) throw err;
    res.json(results);
  });
});

// SQL Injection vulnerability - template literal
app.get('/posts', (req, res) => {
  const category = req.query.category;

  // VULNERABLE: Using template literal without parameterization
  db.query(`SELECT * FROM posts WHERE category = '${category}'`, (err, results) => {
    if (err) throw err;
    res.json(results);
  });
});

// XSS vulnerability - unescaped output
app.get('/search', (req, res) => {
  const searchTerm = req.query.q;

  // VULNERABLE: Directly embedding user input in HTML
  const html = `
    <html>
      <body>
        <h1>Search Results for: ${searchTerm}</h1>
        <p>No results found</p>
      </body>
    </html>
  `;

  res.send(html);
});

app.listen(3000, () => {
  console.log('Server running on port 3000');
});
