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

// VULN: SQL Injection - typed Prisma service
class TypedUserService {
  // VULN: SQL Injection - $queryRaw with typed parameter
  async findUserById(userId: number): Promise<any> {
    // Line 26: Critical SQLi - type doesn't prevent injection in raw query
    return await prisma.$queryRaw`SELECT * FROM users WHERE id = ${userId}`;
  }

  // VULN: SQL Injection - $executeRaw with typed parameters
  async updateUserStatus(userId: number, status: string): Promise<number> {
    // Line 32: Critical SQLi - typed parameters in $executeRaw
    return await prisma.$executeRaw`UPDATE users SET status = ${status} WHERE id = ${userId}`;
  }

  // VULN: SQL Injection - dynamic query with interface
  async filterUsers(filter: UserFilter): Promise<any[]> {
    // Line 39: Critical SQLi - building query from typed interface
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

  // VULN: SQL Injection - generic search method
  async search(params: SearchParams): Promise<any[]> {
    const operator: string = params.operator || '=';
    // Line 63: Critical SQLi - typed search parameters don't prevent SQLi
    const query: string = `SELECT * FROM users WHERE ${params.field} ${operator} '${params.value}'`;
    return await prisma.$queryRawUnsafe(query);
  }
}

// VULN: SQL Injection - async function with typed params
async function getUsersByDepartment(department: string, limit: number): Promise<any[]> {
  // Line 72: High SQLi - typed function parameters still vulnerable
  const query: string = `
    SELECT * FROM users
    WHERE department = '${department}'
    LIMIT ${limit}
  `;
  return await prisma.$queryRawUnsafe(query);
}

// VULN: SQL Injection - complex typed query builder
interface QueryBuilder {
  select?: string[];
  from: string;
  where?: Record<string, any>;
  orderBy?: { field: string; direction: 'ASC' | 'DESC' };
}

async function executeQuery(builder: QueryBuilder): Promise<any[]> {
  // Line 91: Critical SQLi - type-safe interface doesn't prevent SQL injection
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

// VULN: SQL Injection - generic repository pattern
class GenericRepository<T> {
  constructor(private tableName: string) {}

  async findByField(fieldName: string, value: string | number): Promise<T[]> {
    // Line 116: Critical SQLi - generic repository with dynamic field
    const query: string = `SELECT * FROM ${this.tableName} WHERE ${fieldName} = '${value}'`;
    return await prisma.$queryRawUnsafe(query);
  }

  async deleteWhere(condition: string): Promise<number> {
    // Line 122: Critical SQLi - generic delete with condition string
    const query: string = `DELETE FROM ${this.tableName} WHERE ${condition}`;
    return await prisma.$executeRawUnsafe(query);
  }
}

export { TypedUserService, getUsersByDepartment, executeQuery, GenericRepository };
