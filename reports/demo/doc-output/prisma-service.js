// Prisma service with SQL injection vulnerabilities
// Demonstrates unsafe usage of Prisma raw query methods

const { PrismaClient } = require('@prisma/client');

const prisma = new PrismaClient();

class UserService {
/**
 * Retrieves a user from the database by their unique identifier.
 *
 * @param {number|string} userId - The unique identifier of the user to retrieve.
 * @returns {Promise<Object>} A promise that resolves to the user object if found, or null if not.
 */
  async getUserById(userId) {
    const user = await prisma.$queryRaw`SELECT * FROM users WHERE id = ${userId}`;
    return user;
  }

/**
 * Updates the email address of a user in the database.
 *
 * @param {string} userId - The ID of the user whose email is to be updated.
 * @param {string} newEmail - The new email address for the user.
 * @returns {Promise<any>} The result of the database update operation.
 */
  async updateUserEmail(userId, newEmail) {
    const result = await prisma.$executeRaw`UPDATE users SET email = ${newEmail} WHERE id = ${userId}`;
    return result;
  }

/**
 * Searches for users in the database based on a specific field and value.
 *
 * @param {string} fieldName - The name of the field to search in the users table.
 * @param {string} searchValue - The value to search for in the specified field.
 * @returns {Promise<Array>} A promise that resolves to an array of user objects matching the search criteria.
 */
  async searchUsers(fieldName, searchValue) {
    const query = `SELECT * FROM users WHERE ${fieldName} = '${searchValue}'`;
    const users = await prisma.$queryRawUnsafe(query);
    return users;
  }

/**\n * Retrieves a list of users filtered by age and country.\n *\n * @param {number} ageMin - The minimum age to filter users.\n * @param {number} [ageMax] - The maximum age to filter users.\n * @param {string} [country] - The country to filter users by.\n * @returns {Promise<Array>} A promise that resolves to an array of users.\n */
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
/**
 * Processes an order by updating its status and retrieving the updated order.
 *
 * @param {number} orderId - The ID of the order to process.
 * @param {string} status - The new status to set for the order.
 * @returns {Promise<Array>} A promise that resolves to an array of the updated order details.
 */
  async processOrder(orderId, status) {
    return await prisma.$transaction(async (tx) => {
      const query = `UPDATE orders SET status = '${status}' WHERE id = ${orderId}`;
      await tx.$executeRawUnsafe(query);

      const orders = await tx.$queryRawUnsafe(`SELECT * FROM orders WHERE id = ${orderId}`);
      return orders;
    });
  }

/**
 * Retrieves a list of orders sorted by a specified field and order.
 *
 * @param {string} sortField - The field by which to sort the orders.
 * @param {string} sortOrder - The order direction ('ASC' or 'DESC').
 * @returns {Promise<Array>} A promise that resolves to an array of order objects.
 */
  async getOrdersSorted(sortField, sortOrder) {
    const query = `SELECT * FROM orders ORDER BY ${sortField} ${sortOrder}`;
    const orders = await prisma.$queryRawUnsafe(query);
    return orders;
  }
}

module.exports = { UserService, OrderService };
