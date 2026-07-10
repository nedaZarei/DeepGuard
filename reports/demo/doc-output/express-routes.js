
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

/**
 * Retrieves user information based on the provided user ID from the request query.
 *
 * @param {Object} req - The request object containing the query parameters.
 * @param {Object} res - The response object used to send the JSON response.
 *
 * @returns {void} - Sends a JSON response with user data or an error if the query fails.
 */
app.get('/user', (req, res) => {
  const userId = req.query.id;
  const query = 'SELECT * FROM users WHERE id = ' + userId;

  db.query(query, (err, results) => {
    if (err) throw err;
    res.json(results);
  });
});

/**
 * Handles the request to retrieve a product by its ID from the database.
 *
 * @param {Object} req - The request object containing the parameters.
 * @param {Object} req.params - The parameters object of the request.
 * @param {string} req.params.id - The ID of the product to be retrieved.
 * @param {Object} res - The response object used to send back the desired output.
 * @returns {void} - Sends the retrieved product rows as a response.
 */
app.get('/product/:id', (req, res) => {
  const productId = req.params.id;
  const sql = `SELECT * FROM products WHERE id = ${productId}`;

  db.query(sql, (error, rows) => {
    if (error) throw error;
    res.send(rows);
  });
});

/**
 * Handles user authentication by querying the database.
 *
 * @param {Object} req - The request object containing user credentials.
 * @param {Object} req.body - The body of the request.
 * @param {string} req.body.username - The username provided by the user.
 * @param {string} req.body.password - The password provided by the user.
 * @param {Object} res - The response object used to send back the result.
 * @returns {void}
 * @throws {Error} Throws an error if the database query fails.
 */
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

/**
 * Retrieves users from the database, sorted by a specified column and order.
 *
 * @param {Object} req - The request object containing query parameters.
 * @param {Object} res - The response object used to send the results.
 * @param {string} [req.query.sort='id'] - The column to sort by (default is 'id').
 * @param {string} [req.query.order='ASC'] - The sorting order (default is 'ASC').
 * @returns {void} - Returns the results as a JSON response.
 */
app.get('/users', (req, res) => {
  const sortBy = req.query.sort || 'id';
  const order = req.query.order || 'ASC';
  const query = `SELECT * FROM users ORDER BY ${sortBy} ${order}`;

  db.query(query, (err, results) => {
    if (err) throw err;
    res.json(results);
  });
});

/**
 * Starts the server and logs the status to the console.
 *
 * @function
 * @returns {void} This function does not return a value.
 */
app.listen(3000, () => {
  console.log('Server running on port 3000');
});

module.exports = app;
