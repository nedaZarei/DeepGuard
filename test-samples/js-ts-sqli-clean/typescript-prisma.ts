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
  async findUserById(userId: number): Promise<any> {
    return await prisma.$queryRaw`SELECT * FROM users WHERE id = ${userId}`;
  }

  async updateUserStatus(userId: number, status: string): Promise<number> {
    return await prisma.$executeRaw`UPDATE users SET status = ${status} WHERE id = ${userId}`;
  }

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

  async search(params: SearchParams): Promise<any[]> {
    const operator: string = params.operator || '=';
    const query: string = `SELECT * FROM users WHERE ${params.field} ${operator} '${params.value}'`;
    return await prisma.$queryRawUnsafe(query);
  }
}

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
  constructor(private tableName: string) {}

  async findByField(fieldName: string, value: string | number): Promise<T[]> {
    const query: string = `SELECT * FROM ${this.tableName} WHERE ${fieldName} = '${value}'`;
    return await prisma.$queryRawUnsafe(query);
  }

  async deleteWhere(condition: string): Promise<number> {
    const query: string = `DELETE FROM ${this.tableName} WHERE ${condition}`;
    return await prisma.$executeRawUnsafe(query);
  }
}

export { TypedUserService, getUsersByDepartment, executeQuery, GenericRepository };
