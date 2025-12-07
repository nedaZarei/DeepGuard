// Additional Prisma unsafe patterns
// More complex scenarios with raw SQL vulnerabilities

const { PrismaClient } = require('@prisma/client');

const prisma = new PrismaClient();

// VULN: SQL Injection - raw query in async function
async function getUsersByRole(role) {
  // Line 11: Critical SQLi - role parameter directly in query
  return await prisma.$queryRaw`SELECT * FROM users WHERE role = ${role}`;
}

// VULN: SQL Injection - JOIN with user input
async function getUserWithOrders(userId) {
  // Line 17: Critical SQLi - userId in complex JOIN query
  const query = `
    SELECT u.*, o.*
    FROM users u
    LEFT JOIN orders o ON u.id = o.user_id
    WHERE u.id = ${userId}
  `;
  return await prisma.$queryRawUnsafe(query);
}

// VULN: SQL Injection - dynamic table name
async function getRecordsByTable(tableName, filters) {
  // Line 29: Critical SQLi - dynamic table name from parameter
  let query = `SELECT * FROM ${tableName} WHERE 1=1`;

  if (filters.status) {
    query += ` AND status = '${filters.status}'`;
  }

  if (filters.date) {
    query += ` AND created_at >= '${filters.date}'`;
  }

  return await prisma.$queryRawUnsafe(query);
}

// VULN: SQL Injection - aggregation query with user input
async function getStatsByCategory(category, metric) {
  // Line 46: High SQLi - dynamic aggregation with user inputs
  const query = `
    SELECT ${metric}, COUNT(*) as count
    FROM products
    WHERE category = '${category}'
    GROUP BY ${metric}
  `;
  return await prisma.$queryRawUnsafe(query);
}

// VULN: SQL Injection - subquery with concatenation
async function getTopUsers(limit, condition) {
  // Line 58: Critical SQLi - limit and condition both user-controlled
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
