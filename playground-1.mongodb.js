// MongoDB Playground - NetFlow Analysis DB
// Select the database to use.
use('netflow_analysis');

// ---- View last 5 analysis runs ----
// db.runs.find().sort({ timestamp: -1 }).limit(5);

// ---- View alerts from last run ----
// db.alerts.find().sort({ timestamp: -1 }).limit(20);

// ---- Count total runs ----
// db.runs.countDocuments();

// ---- Count total alerts ----
// db.alerts.countDocuments();

// ---- Get alerts by severity ----
// db.alerts.find({ severity: "HIGH" }).limit(10);

// ---- Get a specific run by ID ----
// db.runs.findOne({ run_id: "<paste-run-id-here>" });

// ---- View all collections in the DB ----
db.getCollectionNames();
