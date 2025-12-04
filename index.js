// ------------------- MODULES -------------------
require('dotenv').config();
const express = require('express');
const session = require('express-session');
// FIX 1: Added missing library for session storage
const pgSession = require('connect-pg-simple')(session); 
const bcrypt = require('bcrypt');
const { Pool } = require('pg');
const path = require('path');

// ------------------- APP SETUP -------------------
const app = express();

// Serve static files (CSS, JS, images)
app.use(express.static(path.join(__dirname, 'public')));

// PostgreSQL connections – ONLY ONE AT A TIME

// FOR AWS –––––––––––––––––––––––––––––––––––––––––––––––––––––––––––––––––––––––––––––––––


// const pool = new Pool({
//   host: process.env.DB_HOST,
//   port: process.env.DB_PORT,
//   user: process.env.DB_USER,
//   password: process.env.DB_PASSWORD,
//   database: process.env.DB_NAME,
//   // The Switch: Only use SSL if the environment variable asks for it
//   ssl: {
//     rejectUnauthorized: false  // For RDS
//   }   // { rejectUnauthorized: false } : false
// });


// FOR LOCALHOST ––––––––––––––––––––––––––––––––––––––––––––––––––––––––––––––––––––––––––––


const pool = new Pool({
  host: process.env.DB_HOST,
  port: process.env.DB_PORT,
  user: process.env.DB_USER,
  password: process.env.DB_PASSWORD,
  database: process.env.DB_NAME,
  // SSL is completely removed for local development
});

// ––––––––––––––––––––––––––––––––––––––––––––––––––––––––––––––––––––––––––––––––––––––––––


// Test database connection
pool.connect((err) => {
  if (err) {
    console.error('❌ Database connection failed:', err);
  } else {
    console.log('✅ Database connected successfully');
  }
});

// ------------------- SESSION SETUP -------------------
app.use(
  session({
    store: new pgSession({
      pool, // Use your PostgreSQL connection
      tableName: 'session',
      createTableIfMissing: true,
    }),
    secret: process.env.SESSION_SECRET || 'intex',
    resave: false,
    saveUninitialized: false,
    cookie: {
      secure: false, // false for localhost
      httpOnly: false, // allow cookies in browser during dev
      sameSite: 'lax',
      maxAge: 24 * 60 * 60 * 1000, // 24 hours
    },
  })
);

// ------------------- MIDDLEWARE -------------------
app.use(express.urlencoded({ extended: true }));
app.use(express.json());
app.use(express.static(path.join(__dirname, 'public')));

// Set EJS view engine
app.set('view engine', 'ejs');
app.set('views', path.join(__dirname, 'views'));

// Debugging middleware to track session
app.use((req, res, next) => {
  res.locals.currentUser = req.session.user || null;
  console.log(
    'Session check:',
    req.session.user
      ? `✅ logged in as ${req.session.user.email}`
      : '❌ not logged in'
  );
  next();
});

// ------------------- AUTH MIDDLEWARE -------------------
function requireLogin(req, res, next) {
  if (req.session.user) next();
  else res.redirect('/login');
}

function requireManager(req, res, next) {
  if (req.session.user && req.session.user.role === 'admin') next();
  else res.status(403).send('Unauthorized: Admins only');
}

// Allow managers OR the logged-in user to access their own data
function requireSelfOrManager(req, res, next) {
  if (!req.session.user) return res.redirect('/login');

  const loggedInUserId = req.session.user.id;  // comes from session
  const targetUserId = parseInt(req.params.id); // comes from route like /participants/:id

  if (req.session.user.role === 'admin' || loggedInUserId === targetUserId) {
    next();
  } else {
    res.status(403).send('Access denied: you can only view your own data.');
  }
}


// ------------------- PUBLIC ROUTES -------------------
app.get('/', (req, res) => {
  res.render('index', { user: req.session.user || null });
});

// ------------------- LOGIN ROUTES -------------------
app.get('/login', (req, res) => {
  if (req.session.user) return res.redirect('/dashboard');
  res.render('login', { error_message: null, success_message: null });
});

app.post('/login', async (req, res) => {
  const { email, password } = req.body;

  try {
    // Query user from the database
    const result = await pool.query(
      'SELECT user_id, email, password, role, first_name, last_name, is_active FROM users WHERE email = $1',
      [email]
    );

    if (result.rows.length === 0) {
      return res.render('login', {
        error_message: 'Invalid email or password',
        success_message: null,
      });
    }

    const user = result.rows[0];

    if (!user.is_active) {
      return res.render('login', {
        error_message: 'Your account has been deactivated',
        success_message: null,
      });
    }

    const isValidPassword = await bcrypt.compare(password, user.password);

    if (!isValidPassword) {
      return res.render('login', {
        error_message: 'Invalid email or password',
        success_message: null,
      });
    }

    // Update last login time
    await pool.query('UPDATE users SET last_login = NOW() WHERE user_id = $1', [
      user.user_id,
    ]);

    // Store session data
    req.session.user = {
      id: user.user_id,
      email: user.email,
      role: user.role,
      first_name: user.first_name,
      last_name: user.last_name,
    };

    console.log('✅ Login successful:', user.email);
    req.session.save((err) => {
      if (err) console.error('❌ Session save error:', err);
     
      else console.log('💾 Session saved for:', user.email);
     
      res.redirect('/dashboard');
    });
  } catch (err) {
    console.error('❌ Login error:', err);
    res.render('login', {
      error_message: 'An error occurred. Please try again.',
      success_message: null,
    });
  }
});

// Registering view
app.get('/register', (req, res) => {
  if (req.session.user) return res.redirect('/dashboard');
  res.render('register', { error_message: null, success_message: null });
});

app.post('/register', async (req, res) => {
  const { first_name, last_name, email, password } = req.body;

  try {
    const userCheck = await pool.query('SELECT * FROM users WHERE email = $1', [email]);
    if (userCheck.rows.length > 0) {
      return res.render('register', { message: 'Email already registered' });
    }

    // --- CHANGE STARTS HERE ---
    // Hash the password with a salt round of 10
    const hashedPassword = await bcrypt.hash(password, 10);

    const insertQuery = `
      INSERT INTO users (first_name, last_name, email, password)
      VALUES ($1, $2, $3, $4)
    `;
   
    // Insert 'hashedPassword' instead of the plain 'password'
    await pool.query(insertQuery, [first_name, last_name, email, email, hashedPassword]);
    // --- CHANGE ENDS HERE ---

    res.redirect('/login');
  } catch (err) {
    console.error(err);
    res.status(500).send("Server Error");
  }
});

// ------------------- LOGOUT -------------------
app.get('/logout', (req, res) => {
  req.session.destroy((err) => {
    if (err) console.error('Logout error:', err);
    res.redirect('/');
  });
});

// ------------------- DASHBOARD -------------------
app.get('/dashboard', requireLogin, async (req, res) => {
  try {
    // Query your database for the statistics
    const totalParticipants = await pool.query('SELECT COUNT(*) as count FROM users');
    const regularUsers = await pool.query('SELECT COUNT(*) as count FROM users WHERE role = $1', ['user']);
    const admins = await pool.query('SELECT COUNT(*) as count FROM users WHERE role = $1', ['admin']);
    const totalDonations = await pool.query('SELECT SUM(amount) as total FROM donations');

    // Debug logging
    console.log('Total Participants:', totalParticipants.rows);
    console.log('Regular Users:', regularUsers.rows);
    console.log('Admins:', admins.rows);
    console.log('Total Donations:', totalDonations.rows);

    // Pass the data to your EJS template with safety checks
    res.render('dashboard', {
      user: req.session.user,
      stats: {
        totalParticipants: totalParticipants.rows[0]?.count || 0,
        regularUsers: regularUsers.rows[0]?.count || 0,
        admins: admins.rows[0]?.count || 0,
        totalDonations: totalDonations.rows[0]?.total || 0
      }
    });
  } catch (error) {
    console.error('Error fetching statistics:', error);
    res.status(500).send('Error loading statistics');
  }
});

// ------------------- USER/PARTICIPANT MANAGEMENT -------------------
// Note: Since we merged tables, managing "users" and "participants" is the same thing.

app.get('/participants', requireLogin, async (req, res) => {
  try {
    const { search = '' } = req.query;
    let result;

    if (req.session.user.role === 'admin') {
      // Managers view all users who are NOT managers (participants)
      const params = [];
      let p = 1;
      let where = [];

      if (search && search.trim() !== '') {
        where.push(`(first_name ILIKE $${p} OR last_name ILIKE $${p} OR email ILIKE $${p})`);
        params.push(`%${search.trim()}%`);
        p++;
      }

      const sql = `
        SELECT user_id, first_name, last_name, email, phone, school_or_employer, field_of_interest, date_of_birth
        FROM users
        ${where.length ? 'WHERE ' + where.join(' AND ') : ''}
        ORDER BY last_name ASC
      `;
      result = await pool.query(sql, params);

    } else {
      // Regular users view themselves
      result = await pool.query(`
        SELECT user_id, first_name, last_name, email, phone, school_or_employer, field_of_interest, date_of_birth
        FROM users
        WHERE user_id = $1
      `, [req.session.user.id]);
    }

    // Mapping fields to match EJS expectations
    const participants = result.rows.map(u => ({
      user_id: u.user_id,
      first_name: u.first_name,
      last_name: u.last_name,
      email: u.email,
      phone: u.phone,
      school_or_employer: u.school_or_employer,
      field_of_interest: u.field_of_interest,
      date_of_birth: u.date_of_birth
    }));

    res.render('participants', { participants, filters: { search } });
  } catch (err) {
    console.error('❌ Error fetching participants:', err.message);
    res.status(500).send('Error loading participants page.');
  }
});

// GET route to show the add user form
app.get('/add_user', requireLogin, requireManager, (req, res) => {
  res.render('add_user', { user: req.session.user });
});

// Your existing POST route
app.post('/add_user', requireLogin, requireManager, async (req, res) => {
  // Added password and role to destructuring
  const { first_name, last_name, email, password, role, phone, date_of_birth, school_or_employer, field_of_interest } = req.body;
  try {
    // Generate the hash from the password provided in the form
    const saltRounds = 10;
    const hashedPassword = await bcrypt.hash(password, saltRounds);
    
    await pool.query(
      // FIXED: 
      // 1. Used proper hash logic.
      // 2. Used role from dropdown instead of hardcoded 'user'
      `INSERT INTO users (email, password, first_name, last_name, phone, date_of_birth, school_or_employer, field_of_interest, role, is_active)
       VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, true)`,
      // Array matches the values
      [email, hashedPassword, first_name, last_name, phone, date_of_birth, school_or_employer, field_of_interest, role]
    );
    
    res.redirect('/participants');
  } catch (err) {
    console.error('Error adding participant:', err);
    res.status(500).send('Error adding participant');
  }
});

app.get('/edit-user/:id', requireLogin, requireManager, async (req, res) => {
  const id = req.params.id;
  try {
    const result = await pool.query('SELECT * FROM users WHERE user_id = $1', [id]);
    if (result.rows.length > 0)
      // FIX HERE: Change 'participant' to 'user'
      res.render('edit-user', { user: result.rows[0] }); 
    else res.send('User not found');
  } catch (err) {
    console.error(err);
    res.send('Error loading user'); // Cleaned up the message too
  }
});

app.post('/edit-user/:id', requireLogin, requireManager, async (req, res) => {
  const id = req.params.id;
  const { first_name, last_name, email, phone, school_or_employer, field_of_interest } = req.body;
  try {
    await pool.query(
      `UPDATE users 
       SET first_name=$1, last_name=$2, email=$3, phone=$4, school_or_employer=$5, field_of_interest=$6 
       WHERE user_id=$7`,
      [first_name, last_name, email, phone, school_or_employer, field_of_interest, id]
    );
    res.redirect('/participants');
  } catch (err) {
    console.error(err);
    res.send('Error updating participant');
  }
});

app.post('/delete-user/:id', requireLogin, requireManager, async (req, res) => {
  const id = req.params.id;
  try {
    await pool.query('DELETE FROM users WHERE user_id=$1', [id]);
    res.redirect('/participants');
  } catch (err) {
    console.error(err);
    res.send('Error deleting participant');
  }
});


// ===============================================================
// EVENTS PAGE (PAGINATION + SEARCH)
// ===============================================================
app.get('/events', requireLogin, async (req, res) => {
  try {
    const { search = '', category = 'All', page = 1 } = req.query;
   
    // Pagination Settings
    const limit = 20; // Number of events per "chunk"
    const offset = (page - 1) * limit;

    const where = [];
    const params = [];
    let p = 1;

    // Filter Logic
    if (category && category !== 'All') {
      where.push(`m.event_type = $${p++}`);
      params.push(category);
    }
   
    if (search && search.trim() !== '') {
      where.push(`(m.event_name ILIKE $${p} OR m.event_description ILIKE $${p} OR ei.location ILIKE $${p})`);
      params.push(`%${search.trim()}%`);
      p++;
    }

    // Add Limit and Offset to Params
    params.push(limit);
    params.push(offset);
    // The indices for LIMIT and OFFSET in the SQL query
    const limitIdx = p;
    const offsetIdx = p + 1;

    const sql = `
      SELECT
        ei.event_instance_id,
        m.event_name AS title,
        m.event_type AS category,
        m.event_description AS description,
        ei.start_time AS start_at,
        ei.end_time AS end_at,
        ei.location AS location_name,
        ei.capacity
      FROM event_instances ei
      JOIN master_events m ON ei.master_event_id = m.master_event_id
      ${where.length ? 'WHERE ' + where.join(' AND ') : ''}
      ORDER BY ei.start_time ASC
      LIMIT $${limitIdx} OFFSET $${offsetIdx}
    `;

    const result = await pool.query(sql, params);

    // If the client asks for JSON (via AJAX scroll), send JSON
    if (req.xhr || req.headers.accept.indexOf('json') > -1) {
      return res.json({ events: result.rows, user: req.session.user });
    }

    // Otherwise, render the full HTML page (First load)
    res.render('events', {
        user: req.session.user,
        events: result.rows,
        filters: { search, category }
    });

  } catch (err) {
    console.error('❌ Error loading events:', err);
    res.status(500).send('Error loading events page.');
  }
});

// 2. ADD EVENT FORM
app.get('/events/add', requireLogin, requireManager, (req, res) => {
    res.render('add_event', { user: req.session.user });
});

// 3. CREATE EVENT (POST)
app.post('/events/add', requireLogin, requireManager, async (req, res) => {
    const { title, category, description, start_time, end_time, location, capacity } = req.body;
    
    try {
        // Step 1: Insert into master_events
        const masterRes = await pool.query(
            `INSERT INTO master_events (event_name, event_type, event_description) 
             VALUES ($1, $2, $3) RETURNING master_event_id`,
            [title, category, description]
        );
        const masterId = masterRes.rows[0].master_event_id;

        // Step 2: Insert into event_instances
        // Handle optional end_time (pass null if empty)
        const endTimeVal = end_time ? end_time : null;

        await pool.query(
            `INSERT INTO event_instances (master_event_id, start_time, end_time, location, capacity) 
             VALUES ($1, $2, $3, $4, $5)`,
            [masterId, start_time, endTimeVal, location, capacity]
        );

        res.redirect('/events');
    } catch (err) {
        console.error('❌ Error creating event:', err);
        res.status(500).send('Error creating event.');
    }
});

// 4. EDIT EVENT FORM
app.get('/events/edit/:id', requireLogin, requireManager, async (req, res) => {
    const instanceId = req.params.id;
    try {
        const sql = `
            SELECT 
                ei.event_instance_id,
                ei.master_event_id,
                m.event_name AS title,
                m.event_type AS category,
                m.event_description AS description,
                ei.start_time AS start_at,
                ei.end_time AS end_at,
                ei.location AS location_name,
                ei.capacity
            FROM event_instances ei
            JOIN master_events m ON ei.master_event_id = m.master_event_id
            WHERE ei.event_instance_id = $1
        `;
        const result = await pool.query(sql, [instanceId]);
        
        if (result.rows.length === 0) return res.status(404).send("Event not found");

        res.render('edit_event', { user: req.session.user, event: result.rows[0] });
    } catch (err) {
        console.error('❌ Error loading edit event:', err);
        res.status(500).send('Error loading edit page.');
    }
});

// 5. UPDATE EVENT (POST)
app.post('/events/edit/:id', requireLogin, requireManager, async (req, res) => {
    const instanceId = req.params.id;
    const { master_event_id, title, category, description, start_time, end_time, location, capacity } = req.body;

    try {
        // Step 1: Update Master Details
        await pool.query(
            `UPDATE master_events 
             SET event_name = $1, event_type = $2, event_description = $3 
             WHERE master_event_id = $4`,
            [title, category, description, master_event_id]
        );

        // Step 2: Update Instance Details
        const endTimeVal = end_time ? end_time : null;
        
        await pool.query(
            `UPDATE event_instances 
             SET start_time = $1, end_time = $2, location = $3, capacity = $4 
             WHERE event_instance_id = $5`,
            [start_time, endTimeVal, location, capacity, instanceId]
        );

        res.redirect('/events');
    } catch (err) {
        console.error('❌ Error updating event:', err);
        res.status(500).send('Error updating event.');
    }
});

// 6. DELETE EVENT (POST)
app.post('/events/delete/:id', requireLogin, requireManager, async (req, res) => {
    const instanceId = req.params.id;
    try {
        // Note: This only deletes the instance. The master description remains in DB.
        await pool.query('DELETE FROM event_instances WHERE event_instance_id = $1', [instanceId]);
        res.redirect('/events');
    } catch (err) {
        console.error('❌ Error deleting event:', err);
        res.status(500).send('Error deleting event.');
    }
});



// ------------------- DONATIONS PAGE -------------------
app.get('/donations', async (req, res) => { // You might want to add 'requireLogin' here
  try {
    const result = await pool.query(`
        SELECT 
            d.donation_id,
            u.first_name || ' ' || u.last_name AS donor_name,
            d.amount,
            d.donation_date AS date
        FROM donations d
        JOIN users u ON d.user_id = u.user_id
        ORDER BY d.donation_date DESC
        LIMIT 50
    `);

    const donations = result.rows.length > 0 ? result.rows : [];

    // UPDATED LINE BELOW:
    // Pass 'user: req.session.user' so the EJS file can read first_name and last_name
    res.render('donations', { donations, user: req.session.user });

  } catch (err) {
    console.error('Error loading donations page:', err);
    res.send('Error loading donations page.');
  }
});

// ==================================================================
// DONATION LIST ROUTES (Admin CRUD)
// ==================================================================

// 1. LIST ALL DONATIONS (Search by Name, Amount, or Date)
app.get('/donation_list', requireLogin, async (req, res) => {
  try {
    const { search } = req.query;
    let queryText = `
      SELECT 
        d.donation_id,
        d.amount,
        d.donation_date AS date,
        d.user_id,
        u.first_name || ' ' || u.last_name AS donor_name
      FROM donations d
      JOIN users u ON d.user_id = u.user_id
    `;

    const queryParams = [];

    if (search) {
      // Search First Name OR Last Name OR Amount OR Date
      queryText += ` 
        WHERE u.first_name ILIKE $1 
        OR u.last_name ILIKE $1
        OR CAST(d.amount AS TEXT) ILIKE $1
        OR CAST(d.donation_date AS TEXT) ILIKE $1
      `;
      queryParams.push(`%${search}%`);
    }

    queryText += ` ORDER BY d.donation_date DESC NULLS LAST`;

    const result = await pool.query(queryText, queryParams);
    
    // UPDATED: Used req.session.user instead of req.user
    res.render('donation_list', { 
        user: req.session.user, 
        donations: result.rows,
        searchTerm: search || '' 
    });
  } catch (err) {
    console.error('❌ Error loading donation list:', err);
    res.status(500).send('Error loading donation list.');
  }
});


// 2. SHOW "ADD DONATION" FORM
app.get('/donations/add', requireLogin, async (req, res) => {
  try {
    const userResult = await pool.query(`
      SELECT user_id, first_name, last_name 
      FROM users 
      ORDER BY last_name ASC
    `);

    // UPDATED: Used req.session.user instead of req.user
    res.render('add_donation', { 
        user: req.session.user, 
        users: userResult.rows 
    });
  } catch (err) {
    console.error('❌ Error loading add donation form:', err);
    res.status(500).send('Error loading form.');
  }
});

// 3. PROCESS "ADD DONATION" SUBMISSION
app.post('/donations/add', requireLogin, async (req, res) => {
  const { user_id, amount, donation_date } = req.body;
  try {
    await pool.query(
      `INSERT INTO donations (user_id, amount, donation_date) VALUES ($1, $2, $3)`,
      [user_id, amount, donation_date]
    );
    // Redirect back to the list
    res.redirect('/donation_list'); 
  } catch (err) {
    console.error('❌ Error saving donation:', err);
    res.status(500).send('Error saving donation.');
  }
});

// 4. SHOW "EDIT DONATION" FORM
// UPDATED: Added requireManager, changed req.user to req.session.user
app.get('/donations/edit/:id', requireLogin, requireManager, async (req, res) => {
  const donationId = req.params.id;
  try {
    const donationResult = await pool.query(
      `SELECT * FROM donations WHERE donation_id = $1`, 
      [donationId]
    );

    if (donationResult.rows.length === 0) {
      return res.status(404).send('Donation not found');
    }

    const userResult = await pool.query(`
      SELECT user_id, first_name, last_name 
      FROM users 
      ORDER BY last_name ASC
    `);

    res.render('edit_donation', { 
        user: req.session.user, 
        donation: donationResult.rows[0],
        users: userResult.rows 
    });
  } catch (err) {
    console.error('❌ Error loading edit donation page:', err);
    res.status(500).send('Error loading edit page.');
  }
});

// 5. PROCESS "EDIT DONATION" UPDATE
// UPDATED: Added requireManager
app.post('/donations/edit/:id', requireLogin, requireManager, async (req, res) => {
  const donationId = req.params.id;
  const { user_id, amount, donation_date } = req.body;
  try {
    await pool.query(`
      UPDATE donations 
      SET user_id = $1, amount = $2, donation_date = $3 
      WHERE donation_id = $4`,
      [user_id, amount, donation_date, donationId]
    );
    // Redirect back to the list
    res.redirect('/donation_list');
  } catch (err) {
    console.error('❌ Error updating donation:', err);
    res.status(500).send('Error updating donation.');
  }
});

// 6. DELETE DONATION
// UPDATED: Added requireManager
app.post('/donations/delete/:id', requireLogin, requireManager, async (req, res) => {
  const donationId = req.params.id;
  try {
    await pool.query('DELETE FROM donations WHERE donation_id = $1', [donationId]);
    // Redirect back to the list
    res.redirect('/donation_list');
  } catch (err) {
    console.error('❌ Error deleting donation:', err);
    res.status(500).send('Error deleting donation.');
  }
});



// Surveys

app.get('/surveys', requireLogin, async (req, res) => {
  try {
    const search = req.query.search || "";
    const date = req.query.date || "";
    const satisfaction = req.query.satisfaction || "";
    let params = [];

    const baseQuery = `
        SELECT
            r.registration_id,
            r.status AS registration_status,
            r.check_in_time,
            r.survey_satisfaction,
            r.survey_comments,
            u.user_id,
            u.first_name,
            u.last_name,
            me.event_name AS event_title,
            ei.start_time AS event_date
        FROM registrations r
        JOIN users u ON r.user_id = u.user_id
        JOIN event_instances ei ON r.event_instance_id = ei.event_instance_id
        JOIN master_events me ON ei.master_event_id = me.master_event_id
    `;

    let finalQuery = baseQuery;
    let whereConditions = [];

    // ---------- ADMIN ----------
    if (req.session.user.role === 'admin') {
      let paramIndex = 1;

      // Text search
      if (search) {
        whereConditions.push(`(
          LOWER(u.first_name) LIKE LOWER($${paramIndex})
          OR LOWER(u.last_name) LIKE LOWER($${paramIndex})
          OR LOWER(me.event_name) LIKE LOWER($${paramIndex})
          OR LOWER(r.status) LIKE LOWER($${paramIndex})
          OR CAST(r.registration_id AS TEXT) LIKE $${paramIndex}
          OR LOWER(r.survey_comments) LIKE LOWER($${paramIndex})
        )`);
        params.push(`%${search}%`);
        paramIndex++;
      }

      // Date filter
      if (date) {
        whereConditions.push(`DATE(ei.start_time) = $${paramIndex}`);
        params.push(date);
        paramIndex++;
      }

      // Satisfaction filter
      if (satisfaction) {
        if (satisfaction === 'N/A') {
          whereConditions.push(`r.survey_satisfaction IS NULL`);
        } else {
          whereConditions.push(`r.survey_satisfaction = $${paramIndex}`);
          params.push(parseInt(satisfaction));
          paramIndex++;
        }
      }

      if (whereConditions.length > 0) {
        finalQuery += ` WHERE ${whereConditions.join(' AND ')}`;
      }

      finalQuery += ` ORDER BY r.created_at DESC`;

      const result = await pool.query(finalQuery, params);

      return res.render('surveys', {
        user: req.session.user,
        surveys: result.rows,
        search,
        date,
        satisfaction
      });
    }

    // ---------- NON-ADMIN ----------
    whereConditions.push(`r.user_id = $1`);
    params.push(req.session.user.id);
    let paramIndex = 2;

    // Text search
    if (search) {
      whereConditions.push(`(
        LOWER(me.event_name) LIKE LOWER($${paramIndex})
        OR LOWER(r.status) LIKE LOWER($${paramIndex})
        OR CAST(r.registration_id AS TEXT) LIKE $${paramIndex}
        OR LOWER(r.survey_comments) LIKE LOWER($${paramIndex})
      )`);
      params.push(`%${search}%`);
      paramIndex++;
    }

    // Date filter
    if (date) {
      whereConditions.push(`DATE(ei.start_time) = $${paramIndex}`);
      params.push(date);
      paramIndex++;
    }

    // Satisfaction filter
    if (satisfaction) {
      if (satisfaction === 'N/A') {
        whereConditions.push(`r.survey_satisfaction IS NULL`);
      } else {
        whereConditions.push(`r.survey_satisfaction = $${paramIndex}`);
        params.push(parseInt(satisfaction));
        paramIndex++;
      }
    }

    finalQuery += ` WHERE ${whereConditions.join(' AND ')}`;
    finalQuery += ` ORDER BY r.created_at DESC`;

    const result = await pool.query(finalQuery, params);

    res.render('surveys', {
      user: req.session.user,
      surveys: result.rows,
      search,
      date,
      satisfaction
    });

  } catch (err) {
    console.error('❌ Error loading registrations/surveys:', err);
    res.status(500).send('Error loading registration and survey data.');
  }
});

app.post('/surveys', requireLogin, async (req, res) => {
  // FIX 1: Destructure 'milestones' from the request body
  const { event_id, satisfaction, usefulness, recommendation, milestones, comments } = req.body;
 
  try {
    const user_id = req.session.user.id;

    // 1. Ensure the user is registered for this event
    const registrationCheck = await pool.query(
      'SELECT registration_id FROM registrations WHERE user_id = $1 AND event_instance_id = $2',
      [user_id, event_id]
    );

    if (registrationCheck.rows.length === 0) {
         await pool.query(
            'INSERT INTO registrations (user_id, event_instance_id, status) VALUES ($1, $2, $3)',
            [user_id, event_id, 'registered']
        );
    }
   
    // 2. Update the registration with survey data
    // Note: We are saving 'satisfaction' into 'survey_instructor' as well, assuming that was your intent.
    await pool.query(
      `UPDATE registrations
       SET survey_satisfaction = $1,
           survey_usefulness = $2,
           survey_instructor = $1, 
           survey_recommendation = $3,
           survey_comments = $4
       WHERE user_id = $5 AND event_instance_id = $6`,
      [satisfaction, usefulness, recommendation, comments, user_id, event_id]
    );

    // FIX 2: If the user wrote a milestone, save it to the 'milestones' table
    if (milestones && milestones.trim() !== '') {
        await pool.query(
            'INSERT INTO milestones (user_id, title, milestone_date) VALUES ($1, $2, NOW())',
            [user_id, milestones.trim()]
        );
    }

    res.redirect('/surveys');
  } catch (err) {
    console.error('❌ Error submitting survey:', err);
    res.status(500).send('Error submitting survey.');
  }
});

// ------------------- EDIT SURVEY (ADMIN ONLY) -------------------
app.get('/edit-survey/:id', requireLogin, requireManager, async (req, res) => {
  const registration_id = req.params.id;
  try {
    // Get the registration/survey data
    const surveyResult = await pool.query(`
      SELECT
        r.registration_id,
        r.user_id,
        r.event_instance_id,
        r.status,
        r.survey_satisfaction,
        r.survey_usefulness,
        r.survey_recommendation,
        r.survey_comments,
        u.first_name,
        u.last_name,
        me.event_name AS event_title
      FROM registrations r
      JOIN users u ON r.user_id = u.user_id
      JOIN event_instances ei ON r.event_instance_id = ei.event_instance_id
      JOIN master_events me ON ei.master_event_id = me.master_event_id
      WHERE r.registration_id = $1
    `, [registration_id]);

    if (surveyResult.rows.length === 0) {
      return res.status(404).send('Survey not found');
    }

    const survey = surveyResult.rows[0];

    // Get all events for dropdown (if needed for future expansion)
    const eventsResult = await pool.query(`
      SELECT
        ei.event_instance_id AS event_id,
        me.event_name AS title
      FROM event_instances ei
      JOIN master_events me ON ei.master_event_id = me.master_event_id
      ORDER BY me.event_name
    `);

    res.render('edit-survey', {
      user: req.session.user,
      survey: survey,
      events: eventsResult.rows
    });
  } catch (err) {
    console.error('Error loading survey for editing:', err);
    res.status(500).send('Error loading survey');
  }
});

app.post('/edit-survey/:id', requireLogin, requireManager, async (req, res) => {
  const registration_id = req.params.id;
  const { status, satisfaction, usefulness, recommendation, comments } = req.body;
 
  try {
    await pool.query(
      `UPDATE registrations
       SET status = $1,
           survey_satisfaction = $2,
           survey_usefulness = $3,
           survey_recommendation = $4,
           survey_comments = $5
       WHERE registration_id = $6`,
      [status, satisfaction || null, usefulness || null, recommendation || null, comments || null, registration_id]
    );
    res.redirect('/surveys');
  } catch (err) {
    console.error('Error updating survey:', err);
    res.status(500).send('Error updating survey');
  }
});

// ------------------- NEW SURVEY FORM -------------------
app.get('/survey_new', requireLogin, async (req, res) => {
  try {
    const events = await pool.query(`
        SELECT
            ei.event_instance_id AS event_id,
            me.event_name || ' - ' || TO_CHAR(ei.start_time, 'MM/DD/YYYY') AS title
        FROM event_instances ei
        JOIN master_events me ON ei.master_event_id = me.master_event_id
        ORDER BY me.event_name, ei.start_time
    `);
    res.render('survey_new', { user: req.session.user, events: events.rows });
  } catch (err) {
    console.error('Error loading new survey form:', err);
    res.status(500).send('Error loading survey form.');
  }
});

// ------------------- DELETE SURVEY (ADMIN ONLY) -------------------
app.post('/delete-survey/:id', requireLogin, requireManager, async (req, res) => {
  const registration_id = req.params.id;
  try {
    await pool.query('DELETE FROM registrations WHERE registration_id = $1', [registration_id]);
    res.redirect('/surveys');
  } catch (err) {
    console.error('Error deleting survey:', err);
    res.status(500).send('Error deleting survey');
  }
});

// ==================== MILESTONES ====================

// 1. LIST Milestones
app.get('/milestones', requireLogin, async (req, res) => {
  try {
    // UPDATED: Everyone sees all milestones
    const query = `
        SELECT m.milestone_id, m.title, m.milestone_date, u.first_name, u.last_name
        FROM milestones m
        JOIN users u ON m.user_id = u.user_id
        ORDER BY m.milestone_date DESC
    `;

    const result = await pool.query(query);
    
    // We do NOT need to fetch 'users' here anymore because the dropdown is on the add page
    res.render('milestones', { 
        user: req.session.user, 
        milestones: result.rows 
    });

  } catch (err) {
    console.error('Error loading milestones:', err);
    res.status(500).send('Error loading milestones');
  }
});

// 2. ADD Milestone Form (GET)
app.get('/milestones/add', requireLogin, requireManager, async (req, res) => {
    try {
        // Fetch users for the dropdown
        const usersRes = await pool.query('SELECT user_id, first_name, last_name FROM users WHERE role = $1 ORDER BY last_name', ['user']);
        
        res.render('add_milestone', { 
            user: req.session.user,
            users: usersRes.rows 
        });
    } catch (err) {
        console.error('Error loading add milestone form:', err);
        res.status(500).send('Error loading form');
    }
});

// 3. CREATE Milestone (POST)
app.post('/milestones/add', requireLogin, requireManager, async (req, res) => {
    try {
        const { user_id, title, milestone_date } = req.body;
        
        // Handle optional date
        const dateVal = milestone_date ? milestone_date : null;

        await pool.query(
            'INSERT INTO milestones (user_id, title, milestone_date) VALUES ($1, $2, $3)',
            [user_id, title, dateVal]
        );
        res.redirect('/milestones');
    } catch (err) {
        console.error('Error adding milestone:', err);
        res.status(500).send('Error adding milestone');
    }
});

// 4. DELETE Milestone (POST) - Now uses ID in URL for consistency
app.post('/milestones/delete/:id', requireLogin, requireManager, async (req, res) => {
    try {
        const milestoneId = req.params.id;
        await pool.query('DELETE FROM milestones WHERE milestone_id = $1', [milestoneId]);
        res.redirect('/milestones');
    } catch (err) {
        console.error('Error deleting milestone:', err);
        res.status(500).send('Error deleting milestone');
    }
});

// ------------------- ERROR HANDLING -------------------
app.use((req, res) => res.status(404).send('Page not found'));
app.use((err, req, res, next) => {
  console.error(err.stack);
  res.status(500).send('Something went wrong!');
});

// ------------------- START SERVER -------------------
const port = process.env.PORT || 3000;
app.listen(port, () => {
  console.log(`🚀 Server running on http://localhost:${port}`);
  console.log(`📊 Environment: ${process.env.NODE_ENV || 'development'}`);
});