// Prisma service with SQL injection vulnerabilities
// Demonstrates unsafe usage of Prisma raw query methods

const { PrismaClient } = require('@prisma/client');

const prisma = new PrismaClient();

class UserService {
  // VULN: SQL Injection - $queryRaw with template literal
  async getUserById(userId) {
    // Line 12: Critical SQLi - user input in $queryRaw template literal
    const user = await prisma.$queryRaw`SELECT * FROM users WHERE id = ${userId}`;
    return user;
  }

  // VULN: SQL Injection - $executeRaw with dynamic values
  async updateUserEmail(userId, newEmail) {
    // Line 19: Critical SQLi - $executeRaw with unsanitized input
    const result = await prisma.$executeRaw`UPDATE users SET email = ${newEmail} WHERE id = ${userId}`;
    return result;
  }

  // VULN: SQL Injection - dynamic column name in raw query
  async searchUsers(fieldName, searchValue) {
    // Line 26: Critical SQLi - dynamic column name without validation
    const query = `SELECT * FROM users WHERE ${fieldName} = '${searchValue}'`;
    const users = await prisma.$queryRawUnsafe(query);
    return users;
  }

  // VULN: SQL Injection - $queryRawUnsafe with string concatenation
  async getFilteredUsers(ageMin, ageMax, country) {
    // Line 34: Critical SQLi - building query string with concatenation
    let sql = 'SELECT * FROM users WHERE age >= ' + ageMin;
    if (ageMax) {
      sql += ' AND age <= ' + ageMax;
    }
    if (country) {
      sql += ` AND country = '${country}'`;
    }

    const users = await prisma.$queryRawUnsafe(sql);
    return users;
  }
}

class OrderService {
  // VULN: SQL Injection - raw SQL in transaction
  async processOrder(orderId, status) {
    // Line 52: High SQLi - unsafe raw query in transaction
    return await prisma.$transaction(async (tx) => {
      const query = `UPDATE orders SET status = '${status}' WHERE id = ${orderId}`;
      await tx.$executeRawUnsafe(query);

      const orders = await tx.$queryRawUnsafe(`SELECT * FROM orders WHERE id = ${orderId}`);
      return orders;
    });
  }

  // VULN: SQL Injection - dynamic ORDER BY in raw query
  async getOrdersSorted(sortField, sortOrder) {
    // Line 65: High SQLi - dynamic ORDER BY clause
    const query = `SELECT * FROM orders ORDER BY ${sortField} ${sortOrder}`;
    const orders = await prisma.$queryRawUnsafe(query);
    return orders;
  }
}

module.exports = { UserService, OrderService };
