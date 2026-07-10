// Sequelize dynamic query construction with SQLi vulnerabilities
// Advanced patterns showing unsafe dynamic SQL building

const { Sequelize } = require('sequelize');

const sequelize = new Sequelize('database', 'username', 'password', {
  host: 'localhost',
  dialect: 'mysql'
});

async function getCustomColumns(tableName, columns) {
  const columnList = columns.join(', ');
  const query = `SELECT ${columnList} FROM ${tableName}`;
  const [results] = await sequelize.query(query);
  return results;
}

async function getJoinedData(table1, table2, joinCondition) {
  const query = `
    SELECT *
    FROM ${table1} t1
    INNER JOIN ${table2} t2 ON ${joinCondition}
  `;
  const [results] = await sequelize.query(query);
  return results;
}

async function getAggregatedData(groupByField, aggregateFunc, tableName) {
  const query = `
    SELECT ${groupByField}, ${aggregateFunc}(value) as result
    FROM ${tableName}
    GROUP BY ${groupByField}
  `;
  const [results] = await sequelize.query(query);
  return results;
}

async function getFilteredAggregates(category, havingCondition) {
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

async function searchAcrossTables(searchValue, tables) {
  const queries = tables.map(table =>
    `SELECT * FROM ${table} WHERE name LIKE '%${searchValue}%'`
  );
  const query = queries.join(' UNION ALL ');
  const [results] = await sequelize.query(query);
  return results;
}

async function deleteRecords(tableName, condition) {
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
