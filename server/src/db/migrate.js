const { initDb } = require('./client');

async function migrate() {
    try {
        await initDb();
        console.log('Migration completed successfully');
        process.exit(0);
    } catch (err) {
        console.error('Migration failed:', err.message);
        process.exit(1);
    }
}

migrate();
