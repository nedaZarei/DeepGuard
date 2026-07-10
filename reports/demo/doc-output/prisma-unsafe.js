// Additional Prisma unsafe patterns
// More complex scenarios with raw SQL vulnerabilities

const { PrismaClient } = require('@prisma/client');

const prisma = new PrismaClient();

/**
 * Retrieves users from the database by their role.
 *
 * @param {string} role - The role of the users to retrieve.
 * @returns {Promise<Array>} A promise that resolves to an array of users with the specified role.
 */
async function getUsersByRole(role) {
  return await prisma.$queryRaw`SELECT * FROM users WHERE role = ${role}`;
}

/**
 * Fetches a user along with their associated orders from the database.
 *
 * @param {string|number} userId - The ID of the user to retrieve.
 * @returns {Promise<Object>} A promise that resolves to the user object with their orders.
 * @throws {Error} Throws an error if the query fails.
 */
async function getUserWithOrders(userId) {
  const query = `
    SELECT u.*, o.*
    FROM users u
    LEFT JOIN orders o ON u.id = o.user_id
    WHERE u.id = ${userId}
  `;
  return await prisma.$queryRawUnsafe(query);
}

/**
 * Retrieves records from a specified table based on the given filters.
 *
 * @param {string} tableName - The name of the table to query.
 * @param {Object} filters - The filters to apply to the query.
 * @param {string} [filters.status] - The status filter for the records.
 * @param {string} [filters.date] - The date filter for the records.
 * @returns {Promise<Object[]>} - A promise that resolves to the records retrieved from the database.
 */
async function getRecordsByTable(tableName, filters) {
  let query = `SELECT * FROM ${tableName} WHERE 1=1`;

  if (filters.status) {
    query += ` AND status = '${filters.status}'`;
  }

  if (filters.date) {
    query += ` AND created_at >= '${filters.date}'`;
  }

  return await prisma.$queryRawUnsafe(query);
}

/**
 * Retrieves statistics for a specific category based on the provided metric.
 *
 * @param {string} category - The category of products to query.
 * @param {string} metric - The metric to group the results by.
 * @returns {Promise<object[]>} - A promise that resolves to an array of objects containing the metric and count.
 */
async function getStatsByCategory(category, metric) {
  const query = `
    SELECT ${metric}, COUNT(*) as count
    FROM products
    WHERE category = '${category}'
    GROUP BY ${metric}
  `;
  return await prisma.$queryRawUnsafe(query);
}

/**
 * Retrieves the top users based on the specified conditions and limit.
 *
 * @param {number} limit - The maximum number of users to retrieve.
 * @param {string} condition - The condition to filter users based on their orders.
 * @returns {Promise<Array>} A promise that resolves to an array of users.
 */
async function getTopUsers(limit, condition) {
  const query = `
    SELECT * FROM users
    WHERE id IN (
      SELECT user_id FROM orders
      WHERE ${condition}
    )
    LIMIT ${limit}
  `;
  return await prisma.$queryRawUnsafe(query);
}

module.exports = {
  getUsersByRole,
  getUserWithOrders,
  getRecordsByTable,
  getStatsByCategory,
  getTopUsers
};
