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

/**
 * Retrieves a user from the database by their unique identifier.
 *
 * @param {number} userId - The ID of the user to retrieve.
 * @returns {Promise<Object|null>} A promise that resolves to the user object if found, or null if not found.
 */
async function getUserById(userId) {
  const query = 'SELECT * FROM users WHERE id = ' + userId;
  const [results] = await sequelize.query(query);
  return results;
}

/**
 * Searches for products in the database that match the given search term.
 *
 * @param {string} searchTerm - The term to search for in product names.
 * @returns {Promise<Array>} A promise that resolves to an array of matching products.
 */
async function searchProducts(searchTerm) {
  const sql = `SELECT * FROM products WHERE name LIKE '%${searchTerm}%'`;
  const [products] = await sequelize.query(sql);
  return products;
}

/**
 * Retrieves a filtered list of users based on role and status.
 *
 * @param {string} role - The role of the users to filter by.
 * @param {string} status - The status of the users to filter by.
 * @returns {Promise<Array>} A promise that resolves to an array of user objects.
 */
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

/**
 * Retrieves products from the database sorted by a specified field and order.
 *
 * @param {string} sortBy - The field by which to sort the products.
 * @param {string} order - The order in which to sort the products, either 'ASC' or 'DESC'.
 * @returns {Promise<Array>} A promise that resolves to an array of sorted products.
 */
async function getProductsSorted(sortBy, order) {
  const query = `SELECT * FROM products ORDER BY ${sortBy} ${order}`;
  const [products] = await sequelize.query(query);
  return products;
}

/**
 * Updates the role of a user in the database.
 *
 * @param {number} userId - The ID of the user whose role is to be updated.
 * @param {string} newRole - The new role to assign to the user.
 * @returns {Promise<boolean>} A promise that resolves to true if the update was successful.
 */
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
