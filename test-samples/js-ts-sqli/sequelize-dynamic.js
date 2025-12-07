// Sequelize dynamic query construction with SQLi vulnerabilities
// Advanced patterns showing unsafe dynamic SQL building

const { Sequelize } = require('sequelize');

const sequelize = new Sequelize('database', 'username', 'password', {
  host: 'localhost',
  dialect: 'mysql'
});

// VULN: SQL Injection - dynamic column selection
async function getCustomColumns(tableName, columns) {
  // Line 14: Critical SQLi - dynamic column list and table name
  const columnList = columns.join(', ');
  const query = `SELECT ${columnList} FROM ${tableName}`;
  const [results] = await sequelize.query(query);
  return results;
}

// VULN: SQL Injection - complex JOIN with user input
async function getJoinedData(table1, table2, joinCondition) {
  // Line 23: Critical SQLi - dynamic JOIN condition
  const query = `
    SELECT *
    FROM ${table1} t1
    INNER JOIN ${table2} t2 ON ${joinCondition}
  `;
  const [results] = await sequelize.query(query);
  return results;
}

// VULN: SQL Injection - GROUP BY with aggregation
async function getAggregatedData(groupByField, aggregateFunc, tableName) {
  // Line 35: High SQLi - dynamic GROUP BY and aggregate function
  const query = `
    SELECT ${groupByField}, ${aggregateFunc}(value) as result
    FROM ${tableName}
    GROUP BY ${groupByField}
  `;
  const [results] = await sequelize.query(query);
  return results;
}

// VULN: SQL Injection - HAVING clause with user input
async function getFilteredAggregates(category, havingCondition) {
  // Line 47: High SQLi - dynamic HAVING clause
  const query = `
    SELECT category, COUNT(*) as count
    FROM products
    WHERE category = '${category}'
    GROUP BY category
    HAVING ${havingCondition}
  `;
  const [results] = await sequelize.query(query);
  return results;
}

// VULN: SQL Injection - UNION injection vulnerability
async function searchAcrossTables(searchValue, tables) {
  // Line 61: Critical SQLi - UNION with dynamic table names
  const queries = tables.map(table =>
    `SELECT * FROM ${table} WHERE name LIKE '%${searchValue}%'`
  );
  const query = queries.join(' UNION ALL ');
  const [results] = await sequelize.query(query);
  return results;
}

// VULN: SQL Injection - DELETE with user condition
async function deleteRecords(tableName, condition) {
  // Line 72: Critical SQLi - DELETE with dynamic condition
  const query = `DELETE FROM ${tableName} WHERE ${condition}`;
  await sequelize.query(query);
  return true;
}

module.exports = {
  getCustomColumns,
  getJoinedData,
  getAggregatedData,
  getFilteredAggregates,
  searchAcrossTables,
  deleteRecords
};
