# JavaScript/TypeScript SQL Injection Test Samples

This directory contains vulnerable JavaScript and TypeScript code samples for testing SQL injection detection capabilities. All samples demonstrate realistic but intentionally insecure patterns across three popular Node.js database frameworks: Express with raw SQL, Prisma, and Sequelize.

## Purpose

These samples are designed to:
- Test DeepGuard's SQL injection detection across multiple frameworks
- Demonstrate common SQLi vulnerability patterns in modern JavaScript/TypeScript applications
- Provide realistic examples of unsafe database query construction
- Verify that type annotations (TypeScript) don't prevent SQL injection vulnerabilities

## Setup

Install dependencies:

```bash
npm install
```

For TypeScript type checking:

```bash
npm run typecheck
```

**Note**: These samples are intentionally vulnerable and should never be used in production code.

## Vulnerability Summary

| File | Line | Vulnerability Type | Severity | Description |
|------|------|-------------------|----------|-------------|
| `express-routes.js` | 19 | SQL Injection | Critical | Direct concatenation of `req.query.id` into SELECT query |
| `express-routes.js` | 31 | SQL Injection | Critical | URL parameter `req.params.id` concatenated in template literal |
| `express-routes.js` | 45 | SQL Injection | Critical | POST body parameters (`username`, `password`) in authentication query |
| `express-routes.js` | 63 | SQL Injection | High | Dynamic ORDER BY clause with user-controlled `sort` and `order` |
| `express-complex.js` | 25-41 | SQL Injection | Critical | Complex search building WHERE clause with multiple concatenations |
| `express-complex.js` | 58 | SQL Injection | Critical | Dynamic table name from URL parameter |
| `express-complex.js` | 76 | SQL Injection | High | Bulk update with array join without sanitization |
| `express-complex.js` | 93 | SQL Injection | Critical | Direct use of user filter expression in WHERE clause |
| `prisma-service.js` | 12 | SQL Injection | Critical | User input in `$queryRaw` template literal |
| `prisma-service.js` | 19 | SQL Injection | Critical | Unsanitized input in `$executeRaw` |
| `prisma-service.js` | 26 | SQL Injection | Critical | Dynamic column name in `$queryRawUnsafe` |
| `prisma-service.js` | 34 | SQL Injection | Critical | String concatenation in `$queryRawUnsafe` query builder |
| `prisma-service.js` | 52 | SQL Injection | High | Unsafe raw query in transaction |
| `prisma-service.js` | 65 | SQL Injection | High | Dynamic ORDER BY in raw query |
| `prisma-unsafe.js` | 11 | SQL Injection | Critical | Role parameter in `$queryRaw` |
| `prisma-unsafe.js` | 17 | SQL Injection | Critical | UserId in complex JOIN query |
| `prisma-unsafe.js` | 29 | SQL Injection | Critical | Dynamic table name with filter concatenation |
| `prisma-unsafe.js` | 46 | SQL Injection | High | Dynamic aggregation with user-controlled metric and category |
| `prisma-unsafe.js` | 58 | SQL Injection | Critical | Subquery with user-controlled condition and limit |
| `sequelize-models.js` | 27 | SQL Injection | Critical | Direct concatenation in `sequelize.query` |
| `sequelize-models.js` | 35 | SQL Injection | Critical | Template literal with LIKE pattern |
| `sequelize-models.js` | 44 | SQL Injection | Critical | WHERE clause builder with concatenation |
| `sequelize-models.js` | 61 | SQL Injection | High | Dynamic ORDER BY clause |
| `sequelize-models.js` | 69 | SQL Injection | Critical | UPDATE statement with concatenation |
| `sequelize-dynamic.js` | 14 | SQL Injection | Critical | Dynamic column list and table name |
| `sequelize-dynamic.js` | 23 | SQL Injection | Critical | Dynamic JOIN condition |
| `sequelize-dynamic.js` | 35 | SQL Injection | High | Dynamic GROUP BY and aggregate function |
| `sequelize-dynamic.js` | 47 | SQL Injection | High | Dynamic HAVING clause |
| `sequelize-dynamic.js` | 61 | SQL Injection | Critical | UNION injection with dynamic table names |
| `sequelize-dynamic.js` | 72 | SQL Injection | Critical | DELETE with dynamic condition |
| `typescript-express.ts` | 34 | SQL Injection | Critical | Typed parameter still vulnerable to SQLi |
| `typescript-express.ts` | 52 | SQL Injection | Critical | Typed interface doesn't prevent SQLi |
| `typescript-express.ts` | 73 | SQL Injection | Critical | Arrow function with types, LIKE injection |
| `typescript-express.ts` | 96 | SQL Injection | High | Class method with typed parameters |
| `typescript-prisma.ts` | 26 | SQL Injection | Critical | Typed parameter in `$queryRaw` |
| `typescript-prisma.ts` | 32 | SQL Injection | Critical | Typed parameters in `$executeRaw` |
| `typescript-prisma.ts` | 39 | SQL Injection | Critical | Building query from typed interface |
| `typescript-prisma.ts` | 63 | SQL Injection | Critical | Typed search parameters in dynamic query |
| `typescript-prisma.ts` | 72 | SQL Injection | High | Typed function parameters with LIMIT injection |
| `typescript-prisma.ts` | 91 | SQL Injection | Critical | Type-safe query builder interface |
| `typescript-prisma.ts` | 116 | SQL Injection | Critical | Generic repository with dynamic field |
| `typescript-prisma.ts` | 122 | SQL Injection | Critical | Generic delete with condition string |

## Expected Detection Results

DeepGuard should detect **45 SQL injection vulnerabilities** across these samples:

- **Express vulnerabilities**: 10 findings (4 in express-routes.js, 6 in express-complex.js)
- **Prisma vulnerabilities**: 12 findings (7 in prisma-service.js, 5 in prisma-unsafe.js)
- **Sequelize vulnerabilities**: 11 findings (5 in sequelize-models.js, 6 in sequelize-dynamic.js)
- **TypeScript vulnerabilities**: 12 findings (4 in typescript-express.ts, 8 in typescript-prisma.ts)

### Severity Breakdown

- **Critical**: 34 vulnerabilities
- **High**: 11 vulnerabilities

## Vulnerability Patterns Covered

### Express Patterns
- `req.query` parameter concatenation
- `req.params` URL parameter injection
- `req.body` POST data in queries
- Dynamic ORDER BY clauses
- Complex search filter construction
- Dynamic table names
- Bulk operations with arrays
- User-controlled filter expressions

### Prisma Patterns
- `$queryRaw` with template literals
- `$executeRaw` with unsanitized input
- `$queryRawUnsafe` with string concatenation
- Dynamic column/table names
- Raw queries in transactions
- JOIN queries with user input
- Aggregation queries with dynamic metrics
- Subqueries with user-controlled conditions

### Sequelize Patterns
- `sequelize.query()` with concatenation
- Template literals in raw queries
- Dynamic WHERE clause construction
- ORDER BY injection
- UPDATE/DELETE with concatenation
- Dynamic column selection
- JOIN with dynamic conditions
- GROUP BY and HAVING injection
- UNION-based injection

### TypeScript-Specific Observations
- Type annotations (`string`, `number`) don't prevent SQL injection
- Typed interfaces don't sanitize input
- Arrow functions with type signatures remain vulnerable
- Class methods with types are still at risk
- Generic types and repositories can propagate SQLi risks

## Framework Detection

The `package.json` includes all three frameworks, ensuring DeepGuard's framework detection identifies:
- `express` - Express.js web framework
- `@prisma/client` - Prisma ORM
- `sequelize` - Sequelize ORM

## Safe Alternatives (Not Implemented Here)

These samples intentionally avoid safe patterns. In real code, use:

**Express/MySQL**:
```javascript
// Safe: parameterized query
db.query('SELECT * FROM users WHERE id = ?', [userId], callback);
```

**Prisma**:
```javascript
// Safe: Prisma Client queries (not raw SQL)
await prisma.user.findUnique({ where: { id: userId } });
```

**Sequelize**:
```javascript
// Safe: Sequelize replacements
await sequelize.query('SELECT * FROM users WHERE id = :id', {
  replacements: { id: userId }
});
```

## License

These samples are provided for security testing purposes only. Do not use in production.
