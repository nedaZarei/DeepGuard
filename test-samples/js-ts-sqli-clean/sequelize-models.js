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

async function getUserById(userId) {
  const query = 'SELECT * FROM users WHERE id = ' + userId;
  const [results] = await sequelize.query(query);
  return results;
}

async function searchProducts(searchTerm) {
  const sql = `SELECT * FROM products WHERE name LIKE '%${searchTerm}%'`;
  const [products] = await sequelize.query(sql);
  return products;
}

async function getFilteredUsers(role, status) {
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

async function getProductsSorted(sortBy, order) {
  const query = `SELECT * FROM products ORDER BY ${sortBy} ${order}`;
  const [products] = await sequelize.query(query);
  return products;
}

async function updateUserRole(userId, newRole) {
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
