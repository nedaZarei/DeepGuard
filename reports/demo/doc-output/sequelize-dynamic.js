// Sequelize dynamic query construction with SQLi vulnerabilities
// Advanced patterns showing unsafe dynamic SQL building

const { Sequelize } = require('sequelize');

const sequelize = new Sequelize('database', 'username', 'password', {
  host: 'localhost',
  dialect: 'mysql'
});

/**
 * Retrieves specific columns from a specified table in the database.
 *
 * @param {string} tableName - The name of the table to query.
 * @param {Array<string>} columns - An array of column names to select.
 * @returns {Promise<Array<object>>} - A promise that resolves to an array of objects, each representing a row of the selected columns.
 */
async function getCustomColumns(tableName, columns) {
  const columnList = columns.join(', ');
  const query = `SELECT ${columnList} FROM ${tableName}`;
  const [results] = await sequelize.query(query);
  return results;
}

/**
 * Retrieves joined data from two tables based on a specified join condition.
 *
 * @param {string} table1 - The first table to join.
 * @param {string} table2 - The second table to join.
 * @param {string} joinCondition - The condition to join the tables.
 * @returns {Promise<Array>} A promise that resolves to an array of joined results.
 */
async function getJoinedData(table1, table2, joinCondition) {
  const query = `
    SELECT *
    FROM ${table1} t1
    INNER JOIN ${table2} t2 ON ${joinCondition}
  `;
  const [results] = await sequelize.query(query);
  return results;
}

/**
 * Retrieves aggregated data from a specified database table.
 *
 * @param {string} groupByField - The field to group the results by.
 * @param {string} aggregateFunc - The aggregate function to apply (e.g., SUM, AVG).
 * @param {string} tableName - The name of the table to query.
 * @returns {Promise<Array>} A promise that resolves to an array of aggregated results.
 */
async function getAggregatedData(groupByField, aggregateFunc, tableName) {
  const query = `
    SELECT ${groupByField}, ${aggregateFunc}(value) as result
    FROM ${tableName}
    GROUP BY ${groupByField}
  `;
  const [results] = await sequelize.query(query);
  return results;
}

/**
 * Retrieves filtered aggregate counts of products by category.
 *
 * @param {string} category - The category of products to filter.
 * @param {string} havingCondition - The HAVING clause to apply to the aggregates.
 * @returns {Promise<Array>} A promise that resolves to an array of aggregate results.
 */
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

/**
 * Searches across multiple tables for entries matching the given search value.
 *
 * @param {string} searchValue - The value to search for in the name column.
 * @param {string[]} tables - An array of table names to include in the search.
 * @returns {Promise<Object[]>} A promise that resolves to an array of results matching the search criteria.
 */
async function searchAcrossTables(searchValue, tables) {
  const queries = tables.map(table =>
    `SELECT * FROM ${table} WHERE name LIKE '%${searchValue}%'`
  );
  const query = queries.join(' UNION ALL ');
  const [results] = await sequelize.query(query);
  return results;
}

/**
 * Deletes records from a specified table in the database based on a condition.
 *
 * @param {string} tableName - The name of the table from which to delete records.
 * @param {string} condition - The condition to be met for records to be deleted.
 * @returns {Promise<boolean>} Returns a promise that resolves to true if deletion is successful.
 */
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
