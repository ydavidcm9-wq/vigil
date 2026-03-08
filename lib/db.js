// Vigil — PostgreSQL pool wrapper with graceful degradation
const { Pool } = require('pg');

let pool = null;
let vpsPool = null;

// Primary pool
if (process.env.DATABASE_URL) {
  try {
    pool = new Pool({
      connectionString: process.env.DATABASE_URL,
      max: 20,
      idleTimeoutMillis: 30000,
      connectionTimeoutMillis: 5000
    });

    pool.on('error', (err) => {
      console.error('  Database pool error:', err.message);
    });

    // Test connection
    pool.query('SELECT 1').then(() => {
      console.log('  Database: connected');
    }).catch(err => {
      console.warn('  Database: connection failed —', err.message);
      pool = null;
    });
  } catch (err) {
    console.warn('  Database: pool creation failed —', err.message);
    pool = null;
  }
} else {
  console.warn('  Database: no DATABASE_URL — running without DB');
}

// Secondary pool (VPS)
if (process.env.VPS_DATABASE_URL) {
  try {
    vpsPool = new Pool({
      connectionString: process.env.VPS_DATABASE_URL,
      max: 10,
      idleTimeoutMillis: 30000,
      connectionTimeoutMillis: 5000
    });

    vpsPool.on('error', (err) => {
      console.error('  VPS database pool error:', err.message);
    });
  } catch (err) {
    console.warn('  VPS Database: pool creation failed —', err.message);
    vpsPool = null;
  }
}

/**
 * Execute a database query with parameter binding
 * @param {string} text - SQL query text
 * @param {Array} params - Query parameters
 * @param {object} [usePool] - Pool to use (defaults to primary)
 * @returns {Array} - Result rows
 */
async function dbQuery(text, params = [], usePool = null) {
  const p = usePool || pool;
  if (!p) {
    throw new Error('Database not available');
  }
  try {
    const result = await p.query(text, params);
    return result.rows;
  } catch (err) {
    console.error('  DB query error:', err.message);
    console.error('  Query:', text.substring(0, 200));
    throw err;
  }
}

/**
 * VPS database query shorthand
 */
async function vpsQuery(text, params = []) {
  return dbQuery(text, params, vpsPool);
}

module.exports = { pool, vpsPool, dbQuery, vpsQuery };
