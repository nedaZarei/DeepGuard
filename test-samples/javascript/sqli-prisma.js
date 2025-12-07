// Sample vulnerable Prisma code with SQL injection vulnerabilities

const { PrismaClient } = require('@prisma/client');
const prisma = new PrismaClient();

// VULNERABLE: Unsafe raw query with template literal
async function getUserUnsafe(userId) {
  const user = await prisma.$queryRaw(`SELECT * FROM users WHERE id = ${userId}`); // SQLi vulnerability
  return user;
}

// VULNERABLE: Unsafe executeRaw with string concatenation
async function deleteUserUnsafe(userId) {
  const result = await prisma.$executeRaw('DELETE FROM users WHERE id = ' + userId); // SQLi vulnerability
  return result;
}

// VULNERABLE: Unsafe raw query with interpolated search term
async function searchUsersUnsafe(searchTerm) {
  const users = await prisma.$queryRaw(
    `SELECT * FROM users WHERE name LIKE '%${searchTerm}%'` // SQLi vulnerability
  );
  return users;
}

// SAFE: Parameterized raw query (should not trigger SQLi detection)
async function getUserSafe(userId) {
  const user = await prisma.$queryRaw`SELECT * FROM users WHERE id = ${userId}`;
  return user;
}

// SAFE: ORM method (should not trigger SQLi detection)
async function getUserORM(userId) {
  const user = await prisma.user.findUnique({
    where: { id: userId }
  });
  return user;
}

module.exports = {
  getUserUnsafe,
  deleteUserUnsafe,
  searchUsersUnsafe,
  getUserSafe,
  getUserORM
};
