// Additional Prisma unsafe patterns
// More complex scenarios with raw SQL vulnerabilities

const { PrismaClient } = require('@prisma/client');

const prisma = new PrismaClient();

async function getUsersByRole(role) {
  return await prisma.$queryRaw`SELECT * FROM users WHERE role = ${role}`;
}

async function getUserWithOrders(userId) {
  const query = `
    SELECT u.*, o.*
    FROM users u
    LEFT JOIN orders o ON u.id = o.user_id
    WHERE u.id = ${userId}
  `;
  return await prisma.$queryRawUnsafe(query);
}

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

async function getStatsByCategory(category, metric) {
  const query = `
    SELECT ${metric}, COUNT(*) as count
    FROM products
    WHERE category = '${category}'
    GROUP BY ${metric}
  `;
  return await prisma.$queryRawUnsafe(query);
}

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
