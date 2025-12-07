// Sequelize models with SQL injection vulnerabilities
// Demonstrates unsafe raw query usage in Sequelize

const { Sequelize, DataTypes } = require('sequelize');

const sequelize = new Sequelize('database', 'username', 'password', {
  host: 'localhost',
  dialect: 'mysql'
});

// Define models
const User = sequelize.define('User', {
  username: DataTypes.STRING,
  email: DataTypes.STRING,
  role: DataTypes.STRING
});

const Product = sequelize.define('Product', {
  name: DataTypes.STRING,
  price: DataTypes.DECIMAL,
  category: DataTypes.STRING
});

// VULN: SQL Injection - sequelize.query with string concatenation
async function getUserById(userId) {
  // Line 27: Critical SQLi - direct concatenation in sequelize.query
  const query = 'SELECT * FROM users WHERE id = ' + userId;
  const [results] = await sequelize.query(query);
  return results;
}

// VULN: SQL Injection - template literal in raw query
async function searchProducts(searchTerm) {
  // Line 35: Critical SQLi - template literal with user input
  const sql = `SELECT * FROM products WHERE name LIKE '%${searchTerm}%'`;
  const [products] = await sequelize.query(sql);
  return products;
}

// VULN: SQL Injection - WHERE clause construction
async function getFilteredUsers(role, status) {
  // Line 44: Critical SQLi - building WHERE clause with concatenation
  let query = 'SELECT * FROM users WHERE 1=1';

  if (role) {
    query += ` AND role = '${role}'`;
  }

  if (status) {
    query += ` AND status = '${status}'`;
  }

  const [results] = await sequelize.query(query);
  return results;
}

// VULN: SQL Injection - ORDER BY with user input
async function getProductsSorted(sortBy, order) {
  // Line 61: High SQLi - dynamic ORDER BY clause
  const query = `SELECT * FROM products ORDER BY ${sortBy} ${order}`;
  const [products] = await sequelize.query(query);
  return products;
}

// VULN: SQL Injection - UPDATE with concatenation
async function updateUserRole(userId, newRole) {
  // Line 69: Critical SQLi - UPDATE statement with concatenation
  const query = `UPDATE users SET role = '${newRole}' WHERE id = ${userId}`;
  await sequelize.query(query);
  return true;
}

module.exports = {
  User,
  Product,
  getUserById,
  searchProducts,
  getFilteredUsers,
  getProductsSorted,
  updateUserRole
};
