const { Pool } = require('pg');

const pool = new Pool({
    user: 'postgres',
    host: 'localhost',
    database: 'rsac',
    password: 'admin',  
    port: 5432,
})

pool
.connect()
.then(() => console.log('DB connected'))
.catch(e => console.log('CONNECTION Failed', '\n', e));

module.exports = pool;