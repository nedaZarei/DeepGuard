// Prisma service with SQL injection vulnerabilities
// Demonstrates unsafe usage of Prisma raw query methods

const { PrismaClient } = require('@prisma/client');

const prisma = new PrismaClient();

class UserService {
  async getUserById(userId) {
    const user = await prisma.$queryRaw`SELECT * FROM users WHERE id = ${userId}`;
    return user;
  }

  async updateUserEmail(userId, newEmail) {
    const result = await prisma.$executeRaw`UPDATE users SET email = ${newEmail} WHERE id = ${userId}`;
    return result;
  }

  async searchUsers(fieldName, searchValue) {
    const query = `SELECT * FROM users WHERE ${fieldName} = '${searchValue}'`;
    const users = await prisma.$queryRawUnsafe(query);
    return users;
  }

  async getFilteredUsers(ageMin, ageMax, country) {
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
  async processOrder(orderId, status) {
    return await prisma.$transaction(async (tx) => {
      const query = `UPDATE orders SET status = '${status}' WHERE id = ${orderId}`;
      await tx.$executeRawUnsafe(query);

      const orders = await tx.$queryRawUnsafe(`SELECT * FROM orders WHERE id = ${orderId}`);
      return orders;
    });
  }

  async getOrdersSorted(sortField, sortOrder) {
    const query = `SELECT * FROM orders ORDER BY ${sortField} ${sortOrder}`;
    const orders = await prisma.$queryRawUnsafe(query);
    return orders;
  }
}

module.exports = { UserService, OrderService };
