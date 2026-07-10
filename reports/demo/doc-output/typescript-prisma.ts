// TypeScript Prisma service with SQL injection vulnerabilities
// Shows that TypeScript types don't prevent Prisma raw query SQLi

import { PrismaClient } from '@prisma/client';

const prisma = new PrismaClient();

interface UserFilter {
  role?: string;
  status?: string;
  ageMin?: number;
  ageMax?: number;
}

interface SearchParams {
  field: string;
  value: string;
  operator?: string;
}

class TypedUserService {
/**
 * Retrieves a user from the database by their unique identifier.
 * 
 * @param {number} userId - The unique identifier of the user to retrieve.
 * @returns {Promise<any>} A promise that resolves to the user data if found, otherwise null.
 */
  async findUserById(userId: number): Promise<any> {
    return await prisma.$queryRaw`SELECT * FROM users WHERE id = ${userId}`;
  }

/**
 * Updates the status of a user in the database.
 *
 * @param {number} userId - The ID of the user whose status is to be updated.
 * @param {string} status - The new status to set for the user.
 * @returns {Promise<number>} The number of rows affected by the update operation.
 */
  async updateUserStatus(userId: number, status: string): Promise<number> {
    return await prisma.$executeRaw`UPDATE users SET status = ${status} WHERE id = ${userId}`;
  }

/**
 * Filters users based on the provided criteria.
 *
 * @param {UserFilter} filter - The filter criteria which includes optional properties such as role, status, ageMin, and ageMax.
 * @returns {Promise<any[]>} - A promise that resolves to an array of users matching the filter criteria.
 */
  async filterUsers(filter: UserFilter): Promise<any[]> {
    let query: string = 'SELECT * FROM users WHERE 1=1';

    if (filter.role) {
      query += ` AND role = '${filter.role}'`;
    }

    if (filter.status) {
      query += ` AND status = '${filter.status}'`;
    }

    if (filter.ageMin !== undefined) {
      query += ` AND age >= ${filter.ageMin}`;
    }

    if (filter.ageMax !== undefined) {
      query += ` AND age <= ${filter.ageMax}`;
    }

    return await prisma.$queryRawUnsafe(query);
  }

/**
 * Performs a database search based on the provided parameters.
 *
 * @param {SearchParams} params - The search parameters including field, operator, and value.
 * @param {string} params.field - The field to search in the database.
 * @param {string} [params.operator='='] - The operator to use in the search (default is '=').
 * @param {string} params.value - The value to compare against in the search.
 * @returns {Promise<any[]>} A promise that resolves to an array of results from the database.
 */
  async search(params: SearchParams): Promise<any[]> {
    const operator: string = params.operator || '=';
    const query: string = `SELECT * FROM users WHERE ${params.field} ${operator} '${params.value}'`;
    return await prisma.$queryRawUnsafe(query);
  }
}

/**
 * Retrieves a list of users belonging to a specified department.
 *
 * @param {string} department - The department name to filter users.
 * @param {number} limit - The maximum number of users to return.
 * @returns {Promise<any[]>} A promise that resolves to an array of users from the specified department.
 */
async function getUsersByDepartment(department: string, limit: number): Promise<any[]> {
  const query: string = `
    SELECT * FROM users
    WHERE department = '${department}'
    LIMIT ${limit}
  `;
  return await prisma.$queryRawUnsafe(query);
}

interface QueryBuilder {
  select?: string[];
  from: string;
  where?: Record<string, any>;
  orderBy?: { field: string; direction: 'ASC' | 'DESC' };
}

/**
 * Executes a SQL query based on the provided QueryBuilder configuration.
 * 
 * @param {QueryBuilder} builder - The configuration object that defines the SQL query.
 * @returns {Promise<any[]>} A promise that resolves to an array of results from the executed query.
 */
async function executeQuery(builder: QueryBuilder): Promise<any[]> {
  const columns: string = builder.select?.join(', ') || '*';
  let query: string = `SELECT ${columns} FROM ${builder.from}`;

  if (builder.where) {
    const conditions: string[] = Object.entries(builder.where).map(
      ([key, value]) => `${key} = '${value}'`
    );
    query += ` WHERE ${conditions.join(' AND ')}`;
  }

  if (builder.orderBy) {
    query += ` ORDER BY ${builder.orderBy.field} ${builder.orderBy.direction}`;
  }

  return await prisma.$queryRawUnsafe(query);
}

class GenericRepository<T> {
/**
 * Creates an instance of a class with a specific table name.
 *
 * @param tableName - The name of the database table associated with this instance.
 * @returns An instance of the class with the provided table name.
 */
  constructor(private tableName: string) {}

/**
 * Finds records in the database by a specified field and value.
 *
 * @param {string} fieldName - The name of the field to query.
 * @param {string | number} value - The value to match against the specified field.
 * @returns {Promise<T[]>} - A promise that resolves to an array of records matching the criteria.
 */
  async findByField(fieldName: string, value: string | number): Promise<T[]> {
    const query: string = `SELECT * FROM ${this.tableName} WHERE ${fieldName} = '${value}'`;
    return await prisma.$queryRawUnsafe(query);
  }

/**
 * Deletes records from the database table based on the specified condition.
 *
 * @param condition - The condition used to filter which records to delete.
 *                      This should be a valid SQL WHERE clause.
 * @returns A Promise that resolves to the number of rows deleted.
 */
  async deleteWhere(condition: string): Promise<number> {
    const query: string = `DELETE FROM ${this.tableName} WHERE ${condition}`;
    return await prisma.$executeRawUnsafe(query);
  }
}

export { TypedUserService, getUsersByDepartment, executeQuery, GenericRepository };
