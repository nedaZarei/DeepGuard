// Sample vulnerable Sequelize code with SQL injection vulnerabilities

const { Sequelize } = require('sequelize');
const sequelize = new Sequelize('database', 'username', 'password', {
  host: 'localhost',
  dialect: 'mysql'
});

// VULNERABLE: Raw query with string concatenation
async function getUserUnsafe(userId) {
  const results = await sequelize.query('SELECT * FROM users WHERE id = ' + userId); // SQLi vulnerability
  return results[0];
}

// VULNERABLE: Raw query with template literal
async function searchUsersUnsafe(searchTerm) {
  const users = await sequelize.query(`SELECT * FROM users WHERE name LIKE '%${searchTerm}%'`); // SQLi vulnerability
  return users[0];
}

// VULNERABLE: Raw query with string formatting
async function getOrdersUnsafe(customerId, status) {
  const query = `SELECT * FROM orders WHERE customer_id = ${customerId} AND status = '${status}'`; // SQLi vulnerability
  const orders = await sequelize.query(query);
  return orders[0];
}

// VULNERABLE: Using bind without proper parameterization
async function loginUnsafe(username, password) {
  const query = 'SELECT * FROM users WHERE username = \'' + username + '\' AND password = \'' + password + '\''; // SQLi vulnerability
  const user = await sequelize.query(query);
  return user[0];
}

// SAFE: Using replacements parameter (should not trigger SQLi detection)
async function getUserSafe(userId) {
  const results = await sequelize.query(
    'SELECT * FROM users WHERE id = :id',
    {
      replacements: { id: userId },
      type: Sequelize.QueryTypes.SELECT
    }
  );
  return results[0];
}

// SAFE: Using ORM method (should not trigger SQLi detection)
async function getUserORM(userId) {
  const User = sequelize.define('User', {
    name: Sequelize.STRING,
    email: Sequelize.STRING
  });

  const user = await User.findOne({ where: { id: userId } });
  return user;
}

module.exports = {
  getUserUnsafe,
  searchUsersUnsafe,
  getOrdersUnsafe,
  loginUnsafe,
  getUserSafe,
  getUserORM
};
