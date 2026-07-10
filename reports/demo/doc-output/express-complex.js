// Complex Express.js example with multiple SQL injection vulnerabilities

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

/**
 * Handles an asynchronous request to fetch products based on various filters.
 *
 * @param {Object} req - The request object containing query parameters.
 * @param {Object} req.query - The query parameters for the request.
 * @param {string} [req.query.q] - The search term to filter product names.
 * @param {string} [req.query.category] - The category to filter products.
 * @param {number} [req.query.min_price] - The minimum price to filter products.
 * @param {number} [req.query.max_price] - The maximum price to filter products.
 * @returns {Promise<void>} - Responds with the filtered products in JSON format.
 */
app.get('/search', async (req, res) => {
  const searchTerm = req.query.q;
  const category = req.query.category;
  const minPrice = req.query.min_price;
  const maxPrice = req.query.max_price;

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

/**
 * Handles an HTTP request to retrieve data from a specified database table.
 *
 * @param {Object} req - The request object containing parameters and query.
 * @param {Object} res - The response object used to send the response back.
 * @returns {Promise<void>} A promise that resolves when the response is sent.
 * @throws {Error} If the database query fails, a 500 status code is returned with an error message.
 */
app.get('/report/:table', async (req, res) => {
  const tableName = req.params.table;
  const year = req.query.year;

  const query = `SELECT * FROM ${tableName} WHERE year = ${year}`;

  try {
    const [rows] = await pool.query(query);
    res.json({ table: tableName, data: rows });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

/**
 * Updates the status of multiple orders in the database.
 *
 * @param {Object} req - The request object containing the parameters.
 * @param {Array<number>} req.body.ids - An array of order IDs to be updated.
 * @param {string} req.body.status - The new status to set for the specified orders.
 * @returns {Promise<void>} - A promise that resolves to void when the update is complete.
 * @throws {Error} - If there is an issue with the database query.
 */
app.post('/bulk-update', async (req, res) => {
  const ids = req.body.ids; // Expecting array like [1, 2, 3]
  const status = req.body.status;

  const idList = ids.join(',');
  const query = `UPDATE orders SET status = '${status}' WHERE id IN (${idList})`;

  try {
    const [result] = await pool.query(query);
    res.json({ updated: result.affectedRows });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.get('/filter', async (req, res) => {
  const filterExpr = req.query.filter; // e.g., "price > 100 AND category = 'electronics'"

  const query = `SELECT * FROM products WHERE ${filterExpr}`;

  try {
    const [rows] = await pool.query(query);
    res.json(rows);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

/**
 * Logs a message indicating that a complex example server is running.
 *
 * @function
 * @returns {void} This function does not return a value.
 */
app.listen(3001, () => {
  console.log('Complex example server running on port 3001');
});

module.exports = app;
