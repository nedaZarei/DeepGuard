// Complex Express.js example with multiple SQL injection vulnerabilities
// Demonstrates realistic but vulnerable search and filtering functionality

const express = require('express');
const mysql = require('mysql2/promise');

const app = express();
app.use(express.json());

const pool = mysql.createPool({
  host: 'localhost',
  user: 'root',
  password: 'password',
  database: 'ecommerce'
});

// VULN: SQL Injection - complex search with multiple parameters
app.get('/search', async (req, res) => {
  const searchTerm = req.query.q;
  const category = req.query.category;
  const minPrice = req.query.min_price;
  const maxPrice = req.query.max_price;

  // Line 25: Critical SQLi - building WHERE clause with concatenation
  let query = 'SELECT * FROM products WHERE 1=1';

  if (searchTerm) {
    query += ` AND name LIKE '%${searchTerm}%'`;
  }

  if (category) {
    query += ` AND category = '${category}'`;
  }

  if (minPrice) {
    query += ` AND price >= ${minPrice}`;
  }

  if (maxPrice) {
    query += ` AND price <= ${maxPrice}`;
  }

  try {
    const [rows] = await pool.query(query);
    res.json(rows);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// VULN: SQL Injection - dynamic table name
app.get('/report/:table', async (req, res) => {
  const tableName = req.params.table;
  const year = req.query.year;

  // Line 58: Critical SQLi - dynamic table name from URL parameter
  const query = `SELECT * FROM ${tableName} WHERE year = ${year}`;

  try {
    const [rows] = await pool.query(query);
    res.json({ table: tableName, data: rows });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// VULN: SQL Injection - bulk update with IN clause
app.post('/bulk-update', async (req, res) => {
  const ids = req.body.ids; // Expecting array like [1, 2, 3]
  const status = req.body.status;

  // Line 76: High SQLi - array join without proper sanitization
  const idList = ids.join(',');
  const query = `UPDATE orders SET status = '${status}' WHERE id IN (${idList})`;

  try {
    const [result] = await pool.query(query);
    res.json({ updated: result.affectedRows });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// VULN: SQL Injection - custom filter expression
app.get('/filter', async (req, res) => {
  const filterExpr = req.query.filter; // e.g., "price > 100 AND category = 'electronics'"

  // Line 93: Critical SQLi - directly using user filter expression
  const query = `SELECT * FROM products WHERE ${filterExpr}`;

  try {
    const [rows] = await pool.query(query);
    res.json(rows);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.listen(3001, () => {
  console.log('Complex example server running on port 3001');
});

module.exports = app;
