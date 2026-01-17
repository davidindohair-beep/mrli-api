require('dotenv').config();
const express = require('express');
const cors = require('cors');
const fetch = require('node-fetch');
const mysql = require('mysql2/promise');
const bcrypt = require('bcrypt');
const { v4: uuidv4 } = require('uuid');

// Enterprise Admin Module
const adminModule = require('./admin-module');

const app = express();
const PORT = process.env.PORT || 3001;

// Middleware
app.use(cors({
  origin: process.env.FRONTEND_URL || 'https://mr.indohaircorp.id',
  credentials: true
}));
app.use(express.json());

// Database Pool
let db;
async function initDB() {
  try {
    db = await mysql.createPool({
      host: process.env.DB_HOST || 'localhost',
      port: process.env.DB_PORT || 3306,
      user: process.env.DB_USER,
      password: process.env.DB_PASSWORD,
      database: process.env.DB_NAME,
      waitForConnections: true,
      connectionLimit: 10
    });
    console.log('✅ Database connected');

    // Create tables if not exist
    await createTables();
  } catch (err) {
    console.log('⚠️ Database not connected:', err.message);
  }
}

async function createTables() {
  const queries = [
    // ========== INVOICES (TABEL UTAMA) ==========
    `CREATE TABLE IF NOT EXISTS invoices (
      id INT AUTO_INCREMENT PRIMARY KEY,
      no_invoice VARCHAR(50) UNIQUE,
      tanggal DATE,
      pic VARCHAR(50),
      subcon VARCHAR(50),
      wilayah VARCHAR(50),
      petani_name VARCHAR(100),
      total DECIMAL(15,2),
      status ENUM('Pending', 'Selesai', 'Cancel') DEFAULT 'Pending',
      verification_status ENUM('PENDING', 'VERIFIED') DEFAULT 'PENDING',
      verified_by VARCHAR(20),
      verified_at TIMESTAMP NULL,
      created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
      updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP
    )`,

    // ========== INVOICE_ITEMS ==========
    `CREATE TABLE IF NOT EXISTS invoice_items (
      id INT AUTO_INCREMENT PRIMARY KEY,
      invoice_id INT,
      no_invoice VARCHAR(50),
      kategori VARCHAR(50),
      jenis VARCHAR(100),
      warna VARCHAR(20),
      kg DECIMAL(10,2),
      harga_per_kg DECIMAL(15,2),
      subtotal DECIMAL(15,2),
      created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
      FOREIGN KEY (invoice_id) REFERENCES invoices(id) ON DELETE CASCADE
    )`,

    // ========== INVOICE_ITEM_VERIFICATIONS ==========
    `CREATE TABLE IF NOT EXISTS invoice_item_verifications (
      id INT AUTO_INCREMENT PRIMARY KEY,
      no_invoice VARCHAR(50),
      invoice_item_id INT,
      kg_invoice DECIMAL(10,2),
      kg_received DECIMAL(10,2),
      selisih_kg DECIMAL(10,2),
      remy_grade ENUM('KW', 'ORI') NULL,
      note TEXT,
      verified_by VARCHAR(20),
      verified_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
      FOREIGN KEY (invoice_item_id) REFERENCES invoice_items(id) ON DELETE CASCADE
    )`,

    // ========== RETUL_CALCULATORS ==========
    `CREATE TABLE IF NOT EXISTS retul_calculators (
      id INT AUTO_INCREMENT PRIMARY KEY,
      no_invoice VARCHAR(50) UNIQUE,
      verified_by VARCHAR(20),
      verified_at TIMESTAMP NULL,
      created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
      FOREIGN KEY (no_invoice) REFERENCES invoices(no_invoice) ON DELETE CASCADE
    )`,

    // ========== RETUL_ROWS ==========
    `CREATE TABLE IF NOT EXISTS retul_rows (
      id INT AUTO_INCREMENT PRIMARY KEY,
      retul_id INT,
      size_inch VARCHAR(10),
      kg_1 DECIMAL(10,2) DEFAULT 0,
      kg_2 DECIMAL(10,2) DEFAULT 0,
      kg_3 DECIMAL(10,2) DEFAULT 0,
      kg_4 DECIMAL(10,2) DEFAULT 0,
      total_hitam DECIMAL(10,2) DEFAULT 0,
      lus_uban DECIMAL(10,2) DEFAULT 0,
      FOREIGN KEY (retul_id) REFERENCES retul_calculators(id) ON DELETE CASCADE
    )`,

    // ========== RETUL_SUMMARY ==========
    `CREATE TABLE IF NOT EXISTS retul_summary (
      id INT AUTO_INCREMENT PRIMARY KEY,
      retul_id INT,
      label VARCHAR(50),
      hitam DECIMAL(10,2) DEFAULT 0,
      uban DECIMAL(10,2) DEFAULT 0,
      total DECIMAL(10,2) DEFAULT 0,
      FOREIGN KEY (retul_id) REFERENCES retul_calculators(id) ON DELETE CASCADE
    )`,

    // ========== DEPOSITS ==========
    `CREATE TABLE IF NOT EXISTS deposits (
      id INT AUTO_INCREMENT PRIMARY KEY,
      no_deposit VARCHAR(50) UNIQUE,
      tanggal DATE,
      pic VARCHAR(50),
      subcon VARCHAR(50),
      wilayah VARCHAR(50),
      jumlah DECIMAL(15,2),
      status ENUM('AKTIF', 'USED') DEFAULT 'AKTIF',
      created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )`,

    // ========== SUBCONS ==========
    `CREATE TABLE IF NOT EXISTS subcons (
      id INT AUTO_INCREMENT PRIMARY KEY,
      nama VARCHAR(100),
      wilayah VARCHAR(50),
      pic VARCHAR(50),
      status ENUM('LOCKED', 'UNLOCKED') DEFAULT 'LOCKED'
    )`,

    // ========== WILAYAH ==========
    `CREATE TABLE IF NOT EXISTS wilayah (
      id INT AUTO_INCREMENT PRIMARY KEY,
      kode VARCHAR(10),
      nama VARCHAR(100),
      pic VARCHAR(50)
    )`,

    // ========== BARANG ==========
    `CREATE TABLE IF NOT EXISTS barang (
      id INT AUTO_INCREMENT PRIMARY KEY,
      kategori VARCHAR(50),
      jenis VARCHAR(100),
      pic_jawa VARCHAR(50),
      pic_sumatra VARCHAR(50),
      keterangan TEXT
    )`,

    // ========== PRICE_INTERNAL (Master harga internal per kategori/grade/size) ==========
    `CREATE TABLE IF NOT EXISTS price_internal (
      id INT AUTO_INCREMENT PRIMARY KEY,
      kategori VARCHAR(50),
      grade VARCHAR(20),
      size_inch VARCHAR(10),
      harga_per_kg DECIMAL(15,2),
      keterangan TEXT,
      updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP
    )`,

    // ========== KPI_THRESHOLDS (Ambang batas untuk exception alerts) ==========
    `CREATE TABLE IF NOT EXISTS kpi_thresholds (
      id INT AUTO_INCREMENT PRIMARY KEY,
      metric_name VARCHAR(50) UNIQUE,
      threshold_value DECIMAL(10,2),
      threshold_type ENUM('MAX', 'MIN') DEFAULT 'MAX',
      description TEXT
    )`,

    // ========== RETUL_PICS_MASTER (Master PIC Retul - ERD v3) ==========
    `CREATE TABLE IF NOT EXISTS retul_pics_master (
      id VARCHAR(20) PRIMARY KEY,
      name VARCHAR(50) NOT NULL,
      active BOOLEAN DEFAULT TRUE,
      created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )`,

    // ========== RETUL_CALCULATOR_PICS (Relasi Retul - PIC) ==========
    `CREATE TABLE IF NOT EXISTS retul_calculator_pics (
      id INT AUTO_INCREMENT PRIMARY KEY,
      retul_id INT,
      retul_pic_id VARCHAR(20),
      FOREIGN KEY (retul_id) REFERENCES retul_calculators(id) ON DELETE CASCADE,
      FOREIGN KEY (retul_pic_id) REFERENCES retul_pics_master(id) ON DELETE CASCADE,
      UNIQUE KEY unique_retul_pic (retul_id, retul_pic_id)
    )`,

    // ========== RETUL_LEGACY_COL_MAP (Mapping kg_1-kg_4 ke PIC untuk migrasi) ==========
    `CREATE TABLE IF NOT EXISTS retul_legacy_col_map (
      id INT AUTO_INCREMENT PRIMARY KEY,
      legacy_col VARCHAR(10) NOT NULL,
      retul_pic_id VARCHAR(20) NOT NULL,
      UNIQUE KEY unique_legacy_col (legacy_col),
      FOREIGN KEY (retul_pic_id) REFERENCES retul_pics_master(id) ON DELETE CASCADE
    )`,

    // ========== AUTH: USERS ==========
    `CREATE TABLE IF NOT EXISTS users (
      id BIGINT AUTO_INCREMENT PRIMARY KEY,
      username VARCHAR(50) UNIQUE NOT NULL,
      password_hash VARCHAR(255) NOT NULL,
      full_name VARCHAR(100),
      role ENUM('OWNER','ADMIN','STAFF_PURCHASE','STAFF_GUDANG','VIEWER') DEFAULT 'VIEWER',
      is_active TINYINT DEFAULT 1,
      last_login_at DATETIME NULL,
      created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
      updated_at DATETIME DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP
    )`,

    // ========== AUTH: SESSIONS ==========
    `CREATE TABLE IF NOT EXISTS sessions (
      id BIGINT AUTO_INCREMENT PRIMARY KEY,
      user_id BIGINT NOT NULL,
      token_hash VARCHAR(255) NOT NULL,
      expires_at DATETIME NOT NULL,
      ip_address VARCHAR(45),
      user_agent VARCHAR(255),
      created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
      FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
      INDEX idx_token_hash (token_hash),
      INDEX idx_expires_at (expires_at)
    )`,

    // ========== AUTH: PERMISSIONS ==========
    `CREATE TABLE IF NOT EXISTS permissions (
      id INT AUTO_INCREMENT PRIMARY KEY,
      code VARCHAR(50) UNIQUE NOT NULL,
      name VARCHAR(100) NOT NULL,
      description TEXT,
      module VARCHAR(50)
    )`,

    // ========== AUTH: ROLE_PERMISSIONS ==========
    `CREATE TABLE IF NOT EXISTS role_permissions (
      id INT AUTO_INCREMENT PRIMARY KEY,
      role ENUM('OWNER','ADMIN','STAFF_PURCHASE','STAFF_GUDANG','VIEWER') NOT NULL,
      permission_code VARCHAR(50) NOT NULL,
      UNIQUE KEY unique_role_permission (role, permission_code),
      FOREIGN KEY (permission_code) REFERENCES permissions(code) ON DELETE CASCADE
    )`,

    // ========== AUDIT_LOGS ==========
    `CREATE TABLE IF NOT EXISTS audit_logs (
      id BIGINT AUTO_INCREMENT PRIMARY KEY,
      user_id BIGINT,
      username VARCHAR(50),
      action VARCHAR(50) NOT NULL,
      entity_type VARCHAR(50),
      entity_id VARCHAR(100),
      before_json JSON,
      after_json JSON,
      ip_address VARCHAR(45),
      user_agent VARCHAR(255),
      created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
      INDEX idx_user_id (user_id),
      INDEX idx_action (action),
      INDEX idx_entity (entity_type, entity_id),
      INDEX idx_created_at (created_at)
    )`
  ];

  // Run ALTER TABLE for existing tables (add new columns if not exist)
  const alterQueries = [
    `ALTER TABLE invoices ADD COLUMN IF NOT EXISTS petani_name VARCHAR(100) AFTER wilayah`,
    `ALTER TABLE invoices ADD COLUMN IF NOT EXISTS verification_status ENUM('PENDING', 'VERIFIED') DEFAULT 'PENDING' AFTER status`,
    `ALTER TABLE invoices ADD COLUMN IF NOT EXISTS verified_by VARCHAR(20) AFTER verification_status`,
    `ALTER TABLE invoices ADD COLUMN IF NOT EXISTS verified_at TIMESTAMP NULL AFTER verified_by`,
    `ALTER TABLE invoices ADD COLUMN IF NOT EXISTS updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP AFTER created_at`,
    `ALTER TABLE invoice_items ADD COLUMN IF NOT EXISTS no_invoice VARCHAR(50) AFTER invoice_id`,
    `ALTER TABLE invoice_items ADD COLUMN IF NOT EXISTS warna VARCHAR(20) AFTER jenis`,
    `ALTER TABLE invoice_items CHANGE COLUMN qty kg DECIMAL(10,2)`,
    `ALTER TABLE invoice_items CHANGE COLUMN harga harga_per_kg DECIMAL(15,2)`,
    // ERD v3 - Add hitam_by_pic JSON column to retul_rows
    `ALTER TABLE retul_rows ADD COLUMN IF NOT EXISTS hitam_by_pic JSON AFTER kg_4`,
    // Migration flag for tracking migrated rows
    `ALTER TABLE retul_rows ADD COLUMN IF NOT EXISTS migrated TINYINT DEFAULT 0 AFTER hitam_by_pic`,
    // Soft delete columns for invoices
    `ALTER TABLE invoices ADD COLUMN IF NOT EXISTS deleted_at DATETIME NULL`,
    `ALTER TABLE invoices ADD COLUMN IF NOT EXISTS deleted_by BIGINT NULL`,
    `ALTER TABLE invoices ADD COLUMN IF NOT EXISTS delete_reason TEXT NULL`
  ];

  // Seed default PIC Retul master data
  const seedPics = [
    { id: 'PICR-001', name: 'LEHAN' },
    { id: 'PICR-002', name: 'MUN' },
    { id: 'PICR-003', name: 'RIGEN' },
    { id: 'PICR-004', name: 'PAKDE' }
  ];

  // Legacy column mapping (kg_1-kg_4 ke PIC)
  const legacyColMap = [
    { legacy_col: 'kg_1', retul_pic_id: 'PICR-001' }, // LEHAN
    { legacy_col: 'kg_2', retul_pic_id: 'PICR-002' }, // MUN
    { legacy_col: 'kg_3', retul_pic_id: 'PICR-003' }, // RIGEN
    { legacy_col: 'kg_4', retul_pic_id: 'PICR-004' }  // PAKDE
  ];

  for (const query of queries) {
    try {
      await db.execute(query);
    } catch (err) {
      // Ignore "table already exists" errors
      if (!err.message.includes('already exists')) {
        console.log('Table create error:', err.message);
      }
    }
  }

  // Run ALTER queries (silently ignore errors for existing columns)
  for (const query of alterQueries) {
    try {
      await db.execute(query);
    } catch (err) {
      // Silently ignore ALTER errors (column already exists, etc)
    }
  }

  // Seed default PIC Retul master data (insert if not exists)
  for (const pic of seedPics) {
    try {
      await db.execute(
        'INSERT IGNORE INTO retul_pics_master (id, name, active) VALUES (?, ?, TRUE)',
        [pic.id, pic.name]
      );
    } catch (err) {
      // Silently ignore duplicate key errors
    }
  }

  // Seed legacy column mapping (for migration from kg_1-kg_4)
  for (const mapping of legacyColMap) {
    try {
      await db.execute(
        'INSERT IGNORE INTO retul_legacy_col_map (legacy_col, retul_pic_id) VALUES (?, ?)',
        [mapping.legacy_col, mapping.retul_pic_id]
      );
    } catch (err) {
      // Silently ignore duplicate key errors
    }
  }

  // Seed default permissions
  const defaultPermissions = [
    // Invoice permissions
    { code: 'invoice.view', name: 'View Invoices', module: 'invoice' },
    { code: 'invoice.create', name: 'Create Invoice', module: 'invoice' },
    { code: 'invoice.edit', name: 'Edit Invoice', module: 'invoice' },
    { code: 'invoice.delete', name: 'Delete Invoice (Soft)', module: 'invoice' },
    { code: 'invoice.restore', name: 'Restore Deleted Invoice', module: 'invoice' },
    { code: 'invoice.hard_delete', name: 'Permanently Delete Invoice', module: 'invoice' },
    // Verification permissions
    { code: 'verification.view', name: 'View Verifications', module: 'verification' },
    { code: 'verification.create', name: 'Create Verification', module: 'verification' },
    // Retul permissions
    { code: 'retul.view', name: 'View Retul Calculator', module: 'retul' },
    { code: 'retul.create', name: 'Create Retul Data', module: 'retul' },
    { code: 'retul.edit', name: 'Edit Retul Data', module: 'retul' },
    // Deposit permissions
    { code: 'deposit.view', name: 'View Deposits', module: 'deposit' },
    { code: 'deposit.create', name: 'Create Deposit', module: 'deposit' },
    { code: 'deposit.delete', name: 'Delete Deposit', module: 'deposit' },
    // Master data permissions
    { code: 'master.view', name: 'View Master Data', module: 'master' },
    { code: 'master.edit', name: 'Edit Master Data', module: 'master' },
    // Report permissions
    { code: 'report.view', name: 'View Reports', module: 'report' },
    { code: 'report.export', name: 'Export Reports', module: 'report' },
    // User management permissions
    { code: 'user.view', name: 'View Users', module: 'user' },
    { code: 'user.create', name: 'Create User', module: 'user' },
    { code: 'user.edit', name: 'Edit User', module: 'user' },
    { code: 'user.delete', name: 'Delete User', module: 'user' },
    // Audit log permissions
    { code: 'audit.view', name: 'View Audit Logs', module: 'audit' }
  ];

  for (const perm of defaultPermissions) {
    try {
      await db.execute(
        'INSERT IGNORE INTO permissions (code, name, description, module) VALUES (?, ?, ?, ?)',
        [perm.code, perm.name, perm.description || null, perm.module]
      );
    } catch (err) {
      // Silently ignore duplicate key errors
    }
  }

  // Seed role-permission mappings
  const rolePermissions = {
    'OWNER': defaultPermissions.map(p => p.code), // OWNER gets all permissions
    'ADMIN': [
      'invoice.view', 'invoice.create', 'invoice.edit', 'invoice.delete', 'invoice.restore',
      'verification.view', 'verification.create',
      'retul.view', 'retul.create', 'retul.edit',
      'deposit.view', 'deposit.create', 'deposit.delete',
      'master.view', 'master.edit',
      'report.view', 'report.export',
      'user.view',
      'audit.view'
    ],
    'STAFF_PURCHASE': [
      'invoice.view', 'invoice.create', 'invoice.edit',
      'deposit.view', 'deposit.create',
      'master.view',
      'report.view'
    ],
    'STAFF_GUDANG': [
      'invoice.view',
      'verification.view', 'verification.create',
      'retul.view', 'retul.create', 'retul.edit',
      'master.view',
      'report.view'
    ],
    'VIEWER': [
      'invoice.view',
      'verification.view',
      'retul.view',
      'deposit.view',
      'master.view',
      'report.view'
    ]
  };

  for (const [role, permissions] of Object.entries(rolePermissions)) {
    for (const permCode of permissions) {
      try {
        await db.execute(
          'INSERT IGNORE INTO role_permissions (role, permission_code) VALUES (?, ?)',
          [role, permCode]
        );
      } catch (err) {
        // Silently ignore duplicate key errors
      }
    }
  }

  // Seed default OWNER user (password: admin123)
  try {
    const [existingOwner] = await db.execute('SELECT id FROM users WHERE username = ?', ['owner']);
    if (existingOwner.length === 0) {
      const hashedPassword = await bcrypt.hash('admin123', 10);
      await db.execute(
        'INSERT INTO users (username, password_hash, full_name, role, is_active) VALUES (?, ?, ?, ?, ?)',
        ['owner', hashedPassword, 'System Owner', 'OWNER', 1]
      );
      console.log('✅ Default OWNER user created (username: owner, password: admin123)');
    }
  } catch (err) {
    // Silently ignore errors
  }

  console.log('✅ Tables ready (ERD v3 + Auth + Permissions)');

  // Setup enterprise tables (enhanced user management)
  await adminModule.setupEnterpriseTables(db);
}

// ============ AUTH HELPERS ============

// Generate session token
function generateToken() {
  return uuidv4() + '-' + uuidv4();
}

// Hash token for storage
async function hashToken(token) {
  return await bcrypt.hash(token, 5);
}

// Audit log helper
async function logAudit(userId, username, action, entityType, entityId, beforeData, afterData, req) {
  if (!db) return;
  try {
    await db.execute(
      `INSERT INTO audit_logs (user_id, username, action, entity_type, entity_id, before_json, after_json, ip_address, user_agent)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
      [
        userId || null,
        username || 'system',
        action,
        entityType || null,
        entityId || null,
        beforeData ? JSON.stringify(beforeData) : null,
        afterData ? JSON.stringify(afterData) : null,
        req?.ip || req?.connection?.remoteAddress || null,
        req?.get?.('User-Agent') || null
      ]
    );
  } catch (err) {
    console.log('Audit log error:', err.message);
  }
}

// ============ AUTH MIDDLEWARE ============

// Optional auth - populates req.user if valid token, but doesn't block
async function optionalAuth(req, res, next) {
  const authHeader = req.headers.authorization;
  if (!authHeader || !authHeader.startsWith('Bearer ')) {
    return next();
  }

  const token = authHeader.substring(7);
  if (!token || !db) return next();

  try {
    // Find valid session
    const [sessions] = await db.execute(
      `SELECT s.*, u.id as user_id, u.username, u.full_name, u.role, u.is_active
       FROM sessions s
       JOIN users u ON u.id = s.user_id
       WHERE s.expires_at > NOW() AND u.is_active = 1
       ORDER BY s.created_at DESC`
    );

    // Check token against stored hashes
    for (const session of sessions) {
      const isValid = await bcrypt.compare(token, session.token_hash);
      if (isValid) {
        req.user = {
          id: session.user_id,
          username: session.username,
          full_name: session.full_name,
          role: session.role,
          sessionId: session.id
        };
        break;
      }
    }
  } catch (err) {
    console.log('Auth check error:', err.message);
  }

  next();
}

// Required auth - blocks if no valid token
async function requireAuth(req, res, next) {
  await optionalAuth(req, res, () => {
    if (!req.user) {
      return res.status(401).json({ error: 'Unauthorized', code: 'AUTH_REQUIRED' });
    }
    next();
  });
}

// Permission check middleware factory (with user override support)
function requirePermission(permissionCode) {
  return async (req, res, next) => {
    if (!req.user) {
      return res.status(401).json({ error: 'Unauthorized', code: 'AUTH_REQUIRED' });
    }

    if (!db) return next(); // Skip permission check if no DB

    try {
      // Check user-specific override first
      const [override] = await db.execute(
        `SELECT allowed FROM user_permission_overrides WHERE user_id = ? AND permission_code = ?`,
        [req.user.id, permissionCode]
      );

      if (override.length > 0) {
        // User has override
        if (override[0].allowed === 0) {
          return res.status(403).json({
            error: 'Forbidden',
            code: 'PERMISSION_DENIED_OVERRIDE',
            required: permissionCode,
            message: 'Permission explicitly denied for this user'
          });
        }
        // Override allows this permission
        return next();
      }

      // No override, check role permissions
      const [perms] = await db.execute(
        `SELECT 1 FROM role_permissions WHERE role = ? AND permission_code = ?`,
        [req.user.role, permissionCode]
      );

      if (perms.length === 0) {
        return res.status(403).json({
          error: 'Forbidden',
          code: 'PERMISSION_DENIED',
          required: permissionCode,
          your_role: req.user.role
        });
      }

      next();
    } catch (err) {
      return res.status(500).json({ error: err.message });
    }
  };
}

// Get user permissions (role + overrides)
async function getUserPermissions(role, userId = null) {
  if (!db) return [];
  try {
    // Get base role permissions
    const [rows] = await db.execute(
      `SELECT permission_code FROM role_permissions WHERE role = ?`,
      [role]
    );
    let permissions = rows.map(r => r.permission_code);

    // Apply user-specific overrides if userId provided
    if (userId) {
      const [overrides] = await db.execute(
        `SELECT permission_code, allowed FROM user_permission_overrides WHERE user_id = ?`,
        [userId]
      );

      for (const override of overrides) {
        if (override.allowed === 1 && !permissions.includes(override.permission_code)) {
          // Add granted permission
          permissions.push(override.permission_code);
        } else if (override.allowed === 0) {
          // Remove denied permission
          permissions = permissions.filter(p => p !== override.permission_code);
        }
      }
    }

    return permissions;
  } catch (err) {
    return [];
  }
}

// ============ AUTH ROUTES ============

// POST /api/auth/login (Enterprise version with lockout + login history)
app.post('/api/auth/login', async (req, res) => {
  try {
    const { username, password } = req.body;
    const clientInfo = adminModule.getClientInfo(req);

    if (!username || !password) {
      return res.status(400).json({ error: 'Username and password required' });
    }

    if (!db) {
      return res.status(500).json({ error: 'Database not available' });
    }

    // Get lockout policy
    let lockoutPolicy = adminModule.DEFAULT_LOCKOUT_POLICY;
    try {
      const [settings] = await db.execute(
        "SELECT setting_value FROM security_settings WHERE setting_key = 'lockout_policy'"
      );
      if (settings.length > 0) {
        lockoutPolicy = JSON.parse(settings[0].setting_value);
      }
    } catch (e) {}

    // Find user (include inactive to show proper error)
    const [users] = await db.execute(
      'SELECT * FROM users WHERE username = ?',
      [username]
    );

    // Log login attempt helper
    const logLoginAttempt = async (userId, success, failureReason = null) => {
      try {
        await db.execute(
          `INSERT INTO login_history (user_id, username, success, ip_address, user_agent, device_info, failure_reason)
           VALUES (?, ?, ?, ?, ?, ?, ?)`,
          [userId, username, success ? 1 : 0, clientInfo.ip, clientInfo.user_agent,
           `${clientInfo.browser}/${clientInfo.os}/${clientInfo.device}`, failureReason]
        );
      } catch (e) {}
    };

    if (users.length === 0) {
      await logLoginAttempt(null, false, 'user_not_found');
      await logAudit(null, username, 'LOGIN_FAILED', 'user', null, null, { reason: 'user_not_found' }, req);
      return res.status(401).json({ error: 'Invalid username or password' });
    }

    const user = users[0];

    // OWNER bypasses all security restrictions
    const isOwner = user.role === 'OWNER';

    // Check if user is inactive (OWNER bypasses this)
    if (!isOwner && (!user.is_active || user.status === 'inactive')) {
      await logLoginAttempt(user.id, false, 'account_inactive');
      await logAudit(user.id, username, 'LOGIN_FAILED', 'user', user.id, null, { reason: 'account_inactive' }, req);
      return res.status(401).json({ error: 'Account is inactive. Please contact administrator.' });
    }

    // Check if account is locked (OWNER bypasses this)
    if (!isOwner && (user.status === 'locked' || (user.locked_until && new Date(user.locked_until) > new Date()))) {
      const lockedUntil = user.locked_until ? new Date(user.locked_until) : null;
      await logLoginAttempt(user.id, false, 'account_locked');
      await logAudit(user.id, username, 'LOGIN_FAILED', 'user', user.id, null, { reason: 'account_locked' }, req);
      return res.status(401).json({
        error: 'Account is locked due to too many failed login attempts.',
        locked_until: lockedUntil?.toISOString(),
        code: 'ACCOUNT_LOCKED'
      });
    }

    // Check password
    const isValidPassword = await bcrypt.compare(password, user.password_hash);
    if (!isValidPassword) {
      // OWNER never gets locked out, just return invalid password
      if (isOwner) {
        await logLoginAttempt(user.id, false, 'invalid_password');
        await logAudit(user.id, username, 'LOGIN_FAILED', 'user', user.id, null, { reason: 'invalid_password', owner_bypass: true }, req);
        return res.status(401).json({ error: 'Invalid username or password' });
      }

      // Increment failed attempts for non-OWNER users
      const newAttempts = (user.failed_login_attempts || 0) + 1;

      if (newAttempts >= lockoutPolicy.max_attempts) {
        // Lock account
        const lockUntil = new Date(Date.now() + lockoutPolicy.lockout_minutes * 60 * 1000);
        await db.execute(
          'UPDATE users SET failed_login_attempts = ?, locked_until = ?, status = ? WHERE id = ?',
          [newAttempts, lockUntil, 'locked', user.id]
        );
        await logLoginAttempt(user.id, false, 'account_locked_now');
        await logAudit(user.id, username, 'ACCOUNT_LOCKED', 'user', user.id, null,
          { attempts: newAttempts, locked_until: lockUntil.toISOString() }, req);
        return res.status(401).json({
          error: `Account locked for ${lockoutPolicy.lockout_minutes} minutes due to too many failed attempts.`,
          locked_until: lockUntil.toISOString(),
          code: 'ACCOUNT_LOCKED'
        });
      } else {
        await db.execute(
          'UPDATE users SET failed_login_attempts = ? WHERE id = ?',
          [newAttempts, user.id]
        );
        await logLoginAttempt(user.id, false, 'invalid_password');
        await logAudit(user.id, username, 'LOGIN_FAILED', 'user', user.id, null, { reason: 'invalid_password', attempts: newAttempts }, req);
        const remaining = lockoutPolicy.max_attempts - newAttempts;
        return res.status(401).json({
          error: 'Invalid username or password',
          attempts_remaining: remaining
        });
      }
    }

    // Successful login - reset failed attempts and unlock if needed
    const sessionExpiry = 7 * 24 * 60 * 60 * 1000; // 7 days default
    const token = generateToken();
    const tokenHash = await hashToken(token);
    const expiresAt = new Date(Date.now() + sessionExpiry);

    // Update user: reset attempts, unlock, update last login info
    await db.execute(
      `UPDATE users SET
        failed_login_attempts = 0,
        locked_until = NULL,
        status = CASE WHEN status = 'locked' THEN 'active' ELSE status END,
        last_login_at = NOW(),
        last_ip = ?,
        last_user_agent = ?
       WHERE id = ?`,
      [clientInfo.ip, clientInfo.user_agent, user.id]
    );

    // Create session with device info
    await db.execute(
      `INSERT INTO sessions (user_id, token_hash, expires_at, ip_address, user_agent, device_info, last_seen_at)
       VALUES (?, ?, ?, ?, ?, ?, NOW())`,
      [
        user.id,
        tokenHash,
        expiresAt,
        clientInfo.ip,
        clientInfo.user_agent,
        `${clientInfo.browser}/${clientInfo.os}/${clientInfo.device}`
      ]
    );

    // Get permissions (with user overrides)
    const permissions = await getUserPermissions(user.role, user.id);

    await logLoginAttempt(user.id, true);
    await logAudit(user.id, username, 'LOGIN_SUCCESS', 'user', user.id, null, { ip: clientInfo.ip }, req);

    res.json({
      success: true,
      token,
      expires_at: expiresAt.toISOString(),
      user: {
        id: user.id,
        username: user.username,
        full_name: user.full_name,
        role: user.role,
        force_password_change: user.force_password_change === 1,
        mfa_enabled: user.mfa_enabled === 1
      },
      permissions
    });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// POST /api/auth/logout
app.post('/api/auth/logout', requireAuth, async (req, res) => {
  try {
    // Delete current session
    await db.execute('DELETE FROM sessions WHERE id = ?', [req.user.sessionId]);

    await logAudit(req.user.id, req.user.username, 'LOGOUT', 'user', req.user.id, null, null, req);

    res.json({ success: true, message: 'Logged out successfully' });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// GET /api/auth/me
app.get('/api/auth/me', requireAuth, async (req, res) => {
  try {
    // Get user with extended info
    const [users] = await db.execute(
      `SELECT id, username, full_name, role, status, force_password_change, mfa_enabled
       FROM users WHERE id = ?`,
      [req.user.id]
    );

    if (users.length === 0) {
      return res.status(404).json({ error: 'User not found' });
    }

    const user = users[0];
    const permissions = await getUserPermissions(user.role, user.id);

    res.json({
      user: {
        id: user.id,
        username: user.username,
        full_name: user.full_name,
        role: user.role,
        status: user.status || 'active',
        force_password_change: user.force_password_change === 1,
        mfa_enabled: user.mfa_enabled === 1
      },
      permissions
    });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// POST /api/auth/change-password (with password policy validation)
app.post('/api/auth/change-password', requireAuth, async (req, res) => {
  try {
    const { current_password, new_password } = req.body;

    if (!current_password || !new_password) {
      return res.status(400).json({ error: 'Current password and new password required' });
    }

    // Get password policy
    let passwordPolicy = adminModule.DEFAULT_PASSWORD_POLICY;
    try {
      const [settings] = await db.execute(
        "SELECT setting_value FROM security_settings WHERE setting_key = 'password_policy'"
      );
      if (settings.length > 0) {
        passwordPolicy = JSON.parse(settings[0].setting_value);
      }
    } catch (e) {}

    // Validate password against policy
    const validation = adminModule.validatePassword(new_password, passwordPolicy);
    if (!validation.valid) {
      return res.status(400).json({
        error: 'Password does not meet requirements',
        validation_errors: validation.errors
      });
    }

    // Get user
    const [users] = await db.execute('SELECT password_hash FROM users WHERE id = ?', [req.user.id]);
    if (users.length === 0) {
      return res.status(404).json({ error: 'User not found' });
    }

    // Verify current password
    const isValid = await bcrypt.compare(current_password, users[0].password_hash);
    if (!isValid) {
      await logAudit(req.user.id, req.user.username, 'CHANGE_PASSWORD_FAILED', 'user', req.user.id, null, { reason: 'invalid_current_password' }, req);
      return res.status(401).json({ error: 'Current password is incorrect' });
    }

    // Hash new password
    const newHash = await bcrypt.hash(new_password, 10);

    // Update password and clear force_password_change flag
    await db.execute(
      'UPDATE users SET password_hash = ?, password_changed_at = NOW(), force_password_change = 0 WHERE id = ?',
      [newHash, req.user.id]
    );

    // Invalidate all other sessions (keep current)
    await db.execute('DELETE FROM sessions WHERE user_id = ? AND id != ?', [req.user.id, req.user.sessionId]);

    await logAudit(req.user.id, req.user.username, 'CHANGE_PASSWORD', 'user', req.user.id, null, null, req);

    res.json({ success: true, message: 'Password changed successfully' });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// GET /api/auth/permissions
app.get('/api/auth/permissions', async (req, res) => {
  try {
    if (!db) return res.json([]);

    const [rows] = await db.execute(
      'SELECT * FROM permissions ORDER BY module, code'
    );
    res.json(rows);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// GET /api/auth/role-permissions
app.get('/api/auth/role-permissions', async (req, res) => {
  try {
    if (!db) return res.json({});

    const [rows] = await db.execute(
      'SELECT role, permission_code FROM role_permissions ORDER BY role, permission_code'
    );

    // Group by role
    const result = {};
    for (const row of rows) {
      if (!result[row.role]) result[row.role] = [];
      result[row.role].push(row.permission_code);
    }

    res.json(result);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// ============ USER MANAGEMENT ROUTES (Basic) ============

// POST /api/users - Create user (requires user.create)
app.post('/api/users', requireAuth, requirePermission('user.create'), async (req, res) => {
  try {
    const { username, password, full_name, role } = req.body;

    if (!username || !password) {
      return res.status(400).json({ error: 'Username and password required' });
    }

    if (password.length < 6) {
      return res.status(400).json({ error: 'Password must be at least 6 characters' });
    }

    // Only OWNER can create OWNER/ADMIN
    if ((role === 'OWNER' || role === 'ADMIN') && req.user.role !== 'OWNER') {
      return res.status(403).json({ error: 'Only OWNER can create OWNER or ADMIN users' });
    }

    // Hash password
    const passwordHash = await bcrypt.hash(password, 10);

    const [result] = await db.execute(
      `INSERT INTO users (username, password_hash, full_name, role, is_active)
       VALUES (?, ?, ?, ?, 1)`,
      [username, passwordHash, full_name || null, role || 'VIEWER']
    );

    await logAudit(req.user.id, req.user.username, 'USER_CREATE', 'user', result.insertId, null, { username, full_name, role }, req);

    res.json({ success: true, id: result.insertId, username });
  } catch (error) {
    if (error.code === 'ER_DUP_ENTRY') {
      return res.status(400).json({ error: 'Username already exists' });
    }
    res.status(500).json({ error: error.message });
  }
});

// PUT /api/users/:id - Update user (requires user.edit)
app.put('/api/users/:id', requireAuth, requirePermission('user.edit'), async (req, res) => {
  try {
    const { full_name, role, is_active } = req.body;
    const userId = req.params.id;

    // Get current user data
    const [current] = await db.execute('SELECT * FROM users WHERE id = ?', [userId]);
    if (current.length === 0) {
      return res.status(404).json({ error: 'User not found' });
    }

    const currentUser = current[0];

    // Only OWNER can modify OWNER/ADMIN
    if ((currentUser.role === 'OWNER' || currentUser.role === 'ADMIN') && req.user.role !== 'OWNER') {
      return res.status(403).json({ error: 'Only OWNER can modify OWNER or ADMIN users' });
    }

    // Only OWNER can assign OWNER/ADMIN role
    if ((role === 'OWNER' || role === 'ADMIN') && req.user.role !== 'OWNER') {
      return res.status(403).json({ error: 'Only OWNER can assign OWNER or ADMIN role' });
    }

    // Prevent deactivating self
    if (userId == req.user.id && is_active === 0) {
      return res.status(400).json({ error: 'Cannot deactivate your own account' });
    }

    await db.execute(
      `UPDATE users SET full_name = ?, role = ?, is_active = ? WHERE id = ?`,
      [
        full_name !== undefined ? full_name : currentUser.full_name,
        role !== undefined ? role : currentUser.role,
        is_active !== undefined ? is_active : currentUser.is_active,
        userId
      ]
    );

    await logAudit(req.user.id, req.user.username, 'USER_UPDATE', 'user', userId,
      { full_name: currentUser.full_name, role: currentUser.role, is_active: currentUser.is_active },
      { full_name, role, is_active }, req);

    res.json({ success: true });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// PUT /api/users/:id/reset-password - Reset user password (requires user.edit)
app.put('/api/users/:id/reset-password', requireAuth, requirePermission('user.edit'), async (req, res) => {
  try {
    const { new_password } = req.body;
    const userId = req.params.id;

    if (!new_password || new_password.length < 6) {
      return res.status(400).json({ error: 'New password must be at least 6 characters' });
    }

    // Get current user data
    const [current] = await db.execute('SELECT role FROM users WHERE id = ?', [userId]);
    if (current.length === 0) {
      return res.status(404).json({ error: 'User not found' });
    }

    // Only OWNER can reset OWNER/ADMIN password
    if ((current[0].role === 'OWNER' || current[0].role === 'ADMIN') && req.user.role !== 'OWNER') {
      return res.status(403).json({ error: 'Only OWNER can reset OWNER or ADMIN passwords' });
    }

    const passwordHash = await bcrypt.hash(new_password, 10);

    await db.execute('UPDATE users SET password_hash = ? WHERE id = ?', [passwordHash, userId]);

    // Invalidate all sessions for this user
    await db.execute('DELETE FROM sessions WHERE user_id = ?', [userId]);

    await logAudit(req.user.id, req.user.username, 'USER_RESET_PASSWORD', 'user', userId, null, null, req);

    res.json({ success: true, message: 'Password reset successfully' });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// DELETE /api/users/:id - Delete user (requires user.delete)
app.delete('/api/users/:id', requireAuth, requirePermission('user.delete'), async (req, res) => {
  try {
    const userId = req.params.id;

    // Prevent deleting self
    if (userId == req.user.id) {
      return res.status(400).json({ error: 'Cannot delete your own account' });
    }

    // Get user data
    const [current] = await db.execute('SELECT * FROM users WHERE id = ?', [userId]);
    if (current.length === 0) {
      return res.status(404).json({ error: 'User not found' });
    }

    // Only OWNER can delete OWNER/ADMIN
    if ((current[0].role === 'OWNER' || current[0].role === 'ADMIN') && req.user.role !== 'OWNER') {
      return res.status(403).json({ error: 'Only OWNER can delete OWNER or ADMIN users' });
    }

    await db.execute('DELETE FROM users WHERE id = ?', [userId]);

    await logAudit(req.user.id, req.user.username, 'USER_DELETE', 'user', userId, current[0], null, req);

    res.json({ success: true });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// ============ ENTERPRISE USER MANAGEMENT ROUTES ============

// GET /api/users - Enhanced list with enterprise fields
app.get('/api/users', requireAuth, requirePermission('user.view'), async (req, res) => {
  try {
    const { search, status, role, sort_by, sort_order, page, per_page } = req.query;

    let query = `SELECT id, username, full_name, role, is_active, status,
                 last_login_at, last_ip, last_user_agent, mfa_enabled,
                 failed_login_attempts, locked_until, created_at, updated_at
                 FROM users WHERE 1=1`;
    const params = [];

    // Search filter
    if (search) {
      query += ` AND (username LIKE ? OR full_name LIKE ?)`;
      params.push(`%${search}%`, `%${search}%`);
    }

    // Status filter
    if (status) {
      if (status === 'active') {
        query += ` AND (status = 'active' OR (status IS NULL AND is_active = 1))`;
      } else if (status === 'inactive') {
        query += ` AND (status = 'inactive' OR is_active = 0)`;
      } else if (status === 'locked') {
        query += ` AND status = 'locked'`;
      }
    }

    // Role filter
    if (role) {
      query += ` AND role = ?`;
      params.push(role);
    }

    // Sorting
    const validSortColumns = ['username', 'full_name', 'role', 'status', 'last_login_at', 'created_at'];
    const sortColumn = validSortColumns.includes(sort_by) ? sort_by : 'created_at';
    const sortDir = sort_order === 'asc' ? 'ASC' : 'DESC';
    query += ` ORDER BY ${sortColumn} ${sortDir}`;

    // Pagination
    const pageNum = Math.max(1, parseInt(page) || 1);
    const perPageNum = Math.min(100, Math.max(1, parseInt(per_page) || 20));
    const offset = (pageNum - 1) * perPageNum;
    query += ` LIMIT ${perPageNum} OFFSET ${offset}`;

    const [users] = await db.execute(query, params);

    // Get total count
    let countQuery = `SELECT COUNT(*) as total FROM users WHERE 1=1`;
    const countParams = [];
    if (search) {
      countQuery += ` AND (username LIKE ? OR full_name LIKE ?)`;
      countParams.push(`%${search}%`, `%${search}%`);
    }
    if (status) {
      if (status === 'active') countQuery += ` AND (status = 'active' OR (status IS NULL AND is_active = 1))`;
      else if (status === 'inactive') countQuery += ` AND (status = 'inactive' OR is_active = 0)`;
      else if (status === 'locked') countQuery += ` AND status = 'locked'`;
    }
    if (role) {
      countQuery += ` AND role = ?`;
      countParams.push(role);
    }
    const [countResult] = await db.execute(countQuery, countParams);

    // Parse device info for each user
    const usersWithParsedInfo = users.map(u => ({
      ...u,
      device_info: u.last_user_agent ? adminModule.parseUserAgent(u.last_user_agent) : null
    }));

    res.json({
      users: usersWithParsedInfo,
      pagination: {
        page: pageNum,
        per_page: perPageNum,
        total: countResult[0].total,
        total_pages: Math.ceil(countResult[0].total / perPageNum)
      }
    });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// GET /api/users/:id/detail - Get user with full details including activity
app.get('/api/users/:id/detail', requireAuth, requirePermission('user.view'), async (req, res) => {
  try {
    const userId = req.params.id;

    // Get user
    const [users] = await db.execute(
      `SELECT id, username, full_name, role, is_active, status,
       last_login_at, last_ip, last_user_agent, mfa_enabled, mfa_secret,
       failed_login_attempts, locked_until, password_changed_at,
       force_password_change, created_at, updated_at, created_by
       FROM users WHERE id = ?`,
      [userId]
    );

    if (users.length === 0) {
      return res.status(404).json({ error: 'User not found' });
    }

    const user = users[0];

    // Get active sessions
    const [sessions] = await db.execute(
      `SELECT id, ip_address, user_agent, device_info, created_at, expires_at, last_seen_at
       FROM sessions WHERE user_id = ? AND expires_at > NOW()
       ORDER BY created_at DESC`,
      [userId]
    );

    // Get login history (last 20)
    const [loginHistory] = await db.execute(
      `SELECT id, success, ip_address, device_info, failure_reason, created_at
       FROM login_history WHERE user_id = ? ORDER BY created_at DESC LIMIT 20`,
      [userId]
    );

    // Get permission overrides
    const [overrides] = await db.execute(
      `SELECT id, permission_code, allowed, created_at FROM user_permission_overrides WHERE user_id = ?`,
      [userId]
    );

    // Get effective permissions
    const permissions = await getUserPermissions(user.role, userId);

    res.json({
      user: {
        ...user,
        device_info: user.last_user_agent ? adminModule.parseUserAgent(user.last_user_agent) : null
      },
      sessions,
      login_history: loginHistory,
      permission_overrides: overrides,
      effective_permissions: permissions
    });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// PUT /api/users/:id/status - Change user status (activate/deactivate/unlock)
app.put('/api/users/:id/status', requireAuth, requirePermission('user.edit'), async (req, res) => {
  try {
    const { status } = req.body; // 'active', 'inactive', 'locked'
    const userId = req.params.id;

    if (!['active', 'inactive'].includes(status)) {
      return res.status(400).json({ error: 'Invalid status. Use: active, inactive' });
    }

    // Prevent self deactivation
    if (userId == req.user.id && status !== 'active') {
      return res.status(400).json({ error: 'Cannot deactivate your own account' });
    }

    // Get current user
    const [current] = await db.execute('SELECT * FROM users WHERE id = ?', [userId]);
    if (current.length === 0) {
      return res.status(404).json({ error: 'User not found' });
    }

    // Only OWNER can modify OWNER/ADMIN
    if ((current[0].role === 'OWNER' || current[0].role === 'ADMIN') && req.user.role !== 'OWNER') {
      return res.status(403).json({ error: 'Only OWNER can modify OWNER or ADMIN users' });
    }

    await db.execute(
      `UPDATE users SET status = ?, is_active = ?, locked_until = NULL, failed_login_attempts = 0 WHERE id = ?`,
      [status, status === 'active' ? 1 : 0, userId]
    );

    // If deactivating, invalidate all sessions
    if (status === 'inactive') {
      await db.execute('DELETE FROM sessions WHERE user_id = ?', [userId]);
    }

    await logAudit(req.user.id, req.user.username, 'USER_STATUS_CHANGE', 'user', userId,
      { status: current[0].status, is_active: current[0].is_active },
      { status, is_active: status === 'active' ? 1 : 0 }, req);

    res.json({ success: true, status });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// PUT /api/users/:id/unlock - Unlock a locked user account
app.put('/api/users/:id/unlock', requireAuth, requirePermission('user.edit'), async (req, res) => {
  try {
    const userId = req.params.id;

    const [current] = await db.execute('SELECT * FROM users WHERE id = ?', [userId]);
    if (current.length === 0) {
      return res.status(404).json({ error: 'User not found' });
    }

    if (current[0].status !== 'locked' && !current[0].locked_until) {
      return res.status(400).json({ error: 'User is not locked' });
    }

    await db.execute(
      `UPDATE users SET status = 'active', locked_until = NULL, failed_login_attempts = 0 WHERE id = ?`,
      [userId]
    );

    await logAudit(req.user.id, req.user.username, 'USER_UNLOCK', 'user', userId,
      { status: current[0].status, locked_until: current[0].locked_until }, { status: 'active' }, req);

    res.json({ success: true, message: 'User account unlocked' });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// PUT /api/users/:id/force-password-change - Force user to change password on next login
app.put('/api/users/:id/force-password-change', requireAuth, requirePermission('user.edit'), async (req, res) => {
  try {
    const userId = req.params.id;

    const [current] = await db.execute('SELECT role FROM users WHERE id = ?', [userId]);
    if (current.length === 0) {
      return res.status(404).json({ error: 'User not found' });
    }

    // Only OWNER can modify OWNER/ADMIN
    if ((current[0].role === 'OWNER' || current[0].role === 'ADMIN') && req.user.role !== 'OWNER') {
      return res.status(403).json({ error: 'Only OWNER can modify OWNER or ADMIN users' });
    }

    await db.execute('UPDATE users SET force_password_change = 1 WHERE id = ?', [userId]);

    await logAudit(req.user.id, req.user.username, 'USER_FORCE_PASSWORD_CHANGE', 'user', userId, null, null, req);

    res.json({ success: true, message: 'User will be required to change password on next login' });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// DELETE /api/users/:id/sessions - Terminate all user sessions (force logout)
app.delete('/api/users/:id/sessions', requireAuth, requirePermission('user.manage_sessions'), async (req, res) => {
  try {
    const userId = req.params.id;

    const [current] = await db.execute('SELECT username, role FROM users WHERE id = ?', [userId]);
    if (current.length === 0) {
      return res.status(404).json({ error: 'User not found' });
    }

    // Only OWNER can logout OWNER/ADMIN
    if ((current[0].role === 'OWNER' || current[0].role === 'ADMIN') && req.user.role !== 'OWNER') {
      return res.status(403).json({ error: 'Only OWNER can force logout OWNER or ADMIN users' });
    }

    const [result] = await db.execute('DELETE FROM sessions WHERE user_id = ?', [userId]);

    await logAudit(req.user.id, req.user.username, 'USER_FORCE_LOGOUT', 'user', userId,
      null, { sessions_terminated: result.affectedRows }, req);

    res.json({ success: true, sessions_terminated: result.affectedRows });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// DELETE /api/users/:id/sessions/:sessionId - Terminate specific session
app.delete('/api/users/:id/sessions/:sessionId', requireAuth, requirePermission('user.manage_sessions'), async (req, res) => {
  try {
    const { id: userId, sessionId } = req.params;

    const [session] = await db.execute(
      'SELECT s.*, u.role FROM sessions s JOIN users u ON u.id = s.user_id WHERE s.id = ? AND s.user_id = ?',
      [sessionId, userId]
    );

    if (session.length === 0) {
      return res.status(404).json({ error: 'Session not found' });
    }

    // Only OWNER can terminate OWNER/ADMIN sessions
    if ((session[0].role === 'OWNER' || session[0].role === 'ADMIN') && req.user.role !== 'OWNER') {
      return res.status(403).json({ error: 'Only OWNER can terminate OWNER or ADMIN sessions' });
    }

    await db.execute('DELETE FROM sessions WHERE id = ?', [sessionId]);

    await logAudit(req.user.id, req.user.username, 'SESSION_TERMINATE', 'session', sessionId,
      { user_id: userId, ip: session[0].ip_address }, null, req);

    res.json({ success: true });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// ============ PERMISSION OVERRIDE ROUTES ============

// GET /api/users/:id/permissions - Get user effective permissions
app.get('/api/users/:id/permissions', requireAuth, requirePermission('user.view'), async (req, res) => {
  try {
    const userId = req.params.id;

    const [user] = await db.execute('SELECT role FROM users WHERE id = ?', [userId]);
    if (user.length === 0) {
      return res.status(404).json({ error: 'User not found' });
    }

    // Get role base permissions
    const [rolePerms] = await db.execute(
      'SELECT permission_code FROM role_permissions WHERE role = ?',
      [user[0].role]
    );

    // Get overrides
    const [overrides] = await db.execute(
      'SELECT permission_code, allowed FROM user_permission_overrides WHERE user_id = ?',
      [userId]
    );

    // Calculate effective permissions
    const effective = await getUserPermissions(user[0].role, userId);

    res.json({
      role: user[0].role,
      role_permissions: rolePerms.map(p => p.permission_code),
      overrides: overrides,
      effective_permissions: effective,
      permission_groups: adminModule.PERMISSION_GROUPS
    });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// POST /api/users/:id/permissions/override - Add/update permission override
app.post('/api/users/:id/permissions/override', requireAuth, requirePermission('user.manage_permissions'), async (req, res) => {
  try {
    const userId = req.params.id;
    const { permission_code, allowed } = req.body;

    // Only OWNER can manage permission overrides
    if (req.user.role !== 'OWNER') {
      return res.status(403).json({ error: 'Only OWNER can manage permission overrides' });
    }

    const [user] = await db.execute('SELECT role FROM users WHERE id = ?', [userId]);
    if (user.length === 0) {
      return res.status(404).json({ error: 'User not found' });
    }

    // Validate permission code exists
    const allPerms = Object.values(adminModule.PERMISSION_GROUPS).flat().map(p => p.code);
    if (!allPerms.includes(permission_code)) {
      return res.status(400).json({ error: 'Invalid permission code' });
    }

    // Insert or update override
    await db.execute(
      `INSERT INTO user_permission_overrides (user_id, permission_code, allowed, created_by)
       VALUES (?, ?, ?, ?)
       ON DUPLICATE KEY UPDATE allowed = ?, created_by = ?`,
      [userId, permission_code, allowed ? 1 : 0, req.user.id, allowed ? 1 : 0, req.user.id]
    );

    await logAudit(req.user.id, req.user.username, 'PERMISSION_OVERRIDE_SET', 'user_permission', userId,
      null, { permission_code, allowed }, req);

    res.json({ success: true, permission_code, allowed });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// DELETE /api/users/:id/permissions/override/:permCode - Remove permission override
app.delete('/api/users/:id/permissions/override/:permCode', requireAuth, requirePermission('user.manage_permissions'), async (req, res) => {
  try {
    const { id: userId, permCode } = req.params;

    // Only OWNER can manage permission overrides
    if (req.user.role !== 'OWNER') {
      return res.status(403).json({ error: 'Only OWNER can manage permission overrides' });
    }

    const [result] = await db.execute(
      'DELETE FROM user_permission_overrides WHERE user_id = ? AND permission_code = ?',
      [userId, permCode]
    );

    if (result.affectedRows === 0) {
      return res.status(404).json({ error: 'Override not found' });
    }

    await logAudit(req.user.id, req.user.username, 'PERMISSION_OVERRIDE_REMOVE', 'user_permission', userId,
      { permission_code: permCode }, null, req);

    res.json({ success: true });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// ============ BULK USER ACTIONS ============

// POST /api/users/bulk/status - Bulk change status
app.post('/api/users/bulk/status', requireAuth, requirePermission('user.edit'), async (req, res) => {
  try {
    const { user_ids, status } = req.body;

    if (!Array.isArray(user_ids) || user_ids.length === 0) {
      return res.status(400).json({ error: 'user_ids must be a non-empty array' });
    }

    if (!['active', 'inactive'].includes(status)) {
      return res.status(400).json({ error: 'Invalid status' });
    }

    // Filter out current user
    const filteredIds = user_ids.filter(id => id != req.user.id);

    if (filteredIds.length === 0) {
      return res.status(400).json({ error: 'Cannot change status of your own account' });
    }

    // Check for protected users (OWNER/ADMIN) if not OWNER
    if (req.user.role !== 'OWNER') {
      const [protected_] = await db.execute(
        `SELECT id FROM users WHERE id IN (${filteredIds.map(() => '?').join(',')}) AND role IN ('OWNER', 'ADMIN')`,
        filteredIds
      );
      if (protected_.length > 0) {
        return res.status(403).json({ error: 'Only OWNER can modify OWNER or ADMIN users' });
      }
    }

    const placeholders = filteredIds.map(() => '?').join(',');
    await db.execute(
      `UPDATE users SET status = ?, is_active = ? WHERE id IN (${placeholders})`,
      [status, status === 'active' ? 1 : 0, ...filteredIds]
    );

    // If deactivating, remove sessions
    if (status === 'inactive') {
      await db.execute(`DELETE FROM sessions WHERE user_id IN (${placeholders})`, filteredIds);
    }

    await logAudit(req.user.id, req.user.username, 'BULK_USER_STATUS_CHANGE', 'user', null,
      null, { user_ids: filteredIds, status }, req);

    res.json({ success: true, affected: filteredIds.length });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// POST /api/users/bulk/role - Bulk change role
app.post('/api/users/bulk/role', requireAuth, requirePermission('user.edit'), async (req, res) => {
  try {
    const { user_ids, role } = req.body;

    if (!Array.isArray(user_ids) || user_ids.length === 0) {
      return res.status(400).json({ error: 'user_ids must be a non-empty array' });
    }

    if (!adminModule.ROLES.includes(role)) {
      return res.status(400).json({ error: 'Invalid role' });
    }

    // Only OWNER can assign OWNER/ADMIN role
    if (['OWNER', 'ADMIN'].includes(role) && req.user.role !== 'OWNER') {
      return res.status(403).json({ error: 'Only OWNER can assign OWNER or ADMIN role' });
    }

    const filteredIds = user_ids.filter(id => id != req.user.id);

    if (filteredIds.length === 0) {
      return res.status(400).json({ error: 'Cannot change role of your own account' });
    }

    // Check for protected users if not OWNER
    if (req.user.role !== 'OWNER') {
      const [protected_] = await db.execute(
        `SELECT id FROM users WHERE id IN (${filteredIds.map(() => '?').join(',')}) AND role IN ('OWNER', 'ADMIN')`,
        filteredIds
      );
      if (protected_.length > 0) {
        return res.status(403).json({ error: 'Only OWNER can modify OWNER or ADMIN users' });
      }
    }

    const placeholders = filteredIds.map(() => '?').join(',');
    await db.execute(
      `UPDATE users SET role = ? WHERE id IN (${placeholders})`,
      [role, ...filteredIds]
    );

    await logAudit(req.user.id, req.user.username, 'BULK_USER_ROLE_CHANGE', 'user', null,
      null, { user_ids: filteredIds, role }, req);

    res.json({ success: true, affected: filteredIds.length });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// POST /api/users/bulk/logout - Bulk force logout
app.post('/api/users/bulk/logout', requireAuth, requirePermission('user.manage_sessions'), async (req, res) => {
  try {
    const { user_ids } = req.body;

    if (!Array.isArray(user_ids) || user_ids.length === 0) {
      return res.status(400).json({ error: 'user_ids must be a non-empty array' });
    }

    // Check for protected users if not OWNER
    if (req.user.role !== 'OWNER') {
      const [protected_] = await db.execute(
        `SELECT id FROM users WHERE id IN (${user_ids.map(() => '?').join(',')}) AND role IN ('OWNER', 'ADMIN')`,
        user_ids
      );
      if (protected_.length > 0) {
        return res.status(403).json({ error: 'Only OWNER can force logout OWNER or ADMIN users' });
      }
    }

    const placeholders = user_ids.map(() => '?').join(',');
    const [result] = await db.execute(`DELETE FROM sessions WHERE user_id IN (${placeholders})`, user_ids);

    await logAudit(req.user.id, req.user.username, 'BULK_FORCE_LOGOUT', 'session', null,
      null, { user_ids, sessions_terminated: result.affectedRows }, req);

    res.json({ success: true, sessions_terminated: result.affectedRows });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// ============ LOGIN HISTORY ROUTES ============

// GET /api/login-history - Get login history (for audit)
app.get('/api/login-history', requireAuth, requirePermission('audit.view'), async (req, res) => {
  try {
    const { user_id, success, start_date, end_date, limit: lim } = req.query;
    const limitNum = Math.min(parseInt(lim) || 100, 500);

    let query = `SELECT lh.*, u.full_name
                 FROM login_history lh
                 LEFT JOIN users u ON u.id = lh.user_id
                 WHERE 1=1`;
    const params = [];

    if (user_id) {
      query += ' AND lh.user_id = ?';
      params.push(user_id);
    }
    if (success !== undefined) {
      query += ' AND lh.success = ?';
      params.push(success === 'true' || success === '1' ? 1 : 0);
    }
    if (start_date) {
      query += ' AND lh.created_at >= ?';
      params.push(start_date);
    }
    if (end_date) {
      query += ' AND lh.created_at <= ?';
      params.push(end_date + ' 23:59:59');
    }

    query += ' ORDER BY lh.created_at DESC LIMIT ?';
    params.push(limitNum);

    const [rows] = await db.execute(query, params);
    res.json(rows);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// ============ SECURITY SETTINGS ROUTES ============

// GET /api/security/settings - Get all security settings
app.get('/api/security/settings', requireAuth, requirePermission('security.manage'), async (req, res) => {
  try {
    const [rows] = await db.execute('SELECT * FROM security_settings');

    const settings = {};
    for (const row of rows) {
      settings[row.setting_key] = JSON.parse(row.setting_value);
    }

    res.json(settings);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// PUT /api/security/settings/:key - Update a security setting
app.put('/api/security/settings/:key', requireAuth, requirePermission('security.manage'), async (req, res) => {
  try {
    const { key } = req.params;
    const { value } = req.body;

    // Only OWNER can change security settings
    if (req.user.role !== 'OWNER') {
      return res.status(403).json({ error: 'Only OWNER can modify security settings' });
    }

    const validKeys = ['password_policy', 'lockout_policy', 'session_expiry_hours', 'ip_allowlist_enabled', 'ip_allowlist', 'mfa_required_roles'];
    if (!validKeys.includes(key)) {
      return res.status(400).json({ error: 'Invalid setting key' });
    }

    // Get current value for audit
    const [current] = await db.execute(
      'SELECT setting_value FROM security_settings WHERE setting_key = ?',
      [key]
    );

    await db.execute(
      `INSERT INTO security_settings (setting_key, setting_value, updated_by)
       VALUES (?, ?, ?)
       ON DUPLICATE KEY UPDATE setting_value = ?, updated_by = ?`,
      [key, JSON.stringify(value), req.user.id, JSON.stringify(value), req.user.id]
    );

    await logAudit(req.user.id, req.user.username, 'SECURITY_SETTING_CHANGE', 'security_settings', key,
      current.length > 0 ? { value: JSON.parse(current[0].setting_value) } : null,
      { value }, req);

    res.json({ success: true, key, value });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// GET /api/security/password-policy - Get password policy (public for password change form)
app.get('/api/security/password-policy', async (req, res) => {
  try {
    const [rows] = await db.execute(
      "SELECT setting_value FROM security_settings WHERE setting_key = 'password_policy'"
    );

    if (rows.length > 0) {
      res.json(JSON.parse(rows[0].setting_value));
    } else {
      res.json(adminModule.DEFAULT_PASSWORD_POLICY);
    }
  } catch (error) {
    res.json(adminModule.DEFAULT_PASSWORD_POLICY);
  }
});

// ============ ROLES & PERMISSIONS INFO ============

// GET /api/roles - Get all available roles
app.get('/api/roles', requireAuth, async (req, res) => {
  res.json({
    roles: adminModule.ROLES,
    role_permissions: adminModule.ROLE_PERMISSIONS
  });
});

// GET /api/permission-groups - Get permission groups for UI
app.get('/api/permission-groups', requireAuth, async (req, res) => {
  res.json(adminModule.PERMISSION_GROUPS);
});

// ============ AUDIT LOG ROUTES ============

// GET /api/audit-logs - List audit logs (requires audit.view)
app.get('/api/audit-logs', requireAuth, requirePermission('audit.view'), async (req, res) => {
  try {
    const { user_id, action, entity_type, entity_id, start_date, end_date, limit } = req.query;
    const limitNum = Math.min(parseInt(limit) || 100, 500);

    let query = 'SELECT * FROM audit_logs WHERE 1=1';
    const params = [];

    if (user_id) {
      query += ' AND user_id = ?';
      params.push(user_id);
    }
    if (action) {
      query += ' AND action = ?';
      params.push(action);
    }
    if (entity_type) {
      query += ' AND entity_type = ?';
      params.push(entity_type);
    }
    if (entity_id) {
      query += ' AND entity_id = ?';
      params.push(entity_id);
    }
    if (start_date) {
      query += ' AND created_at >= ?';
      params.push(start_date);
    }
    if (end_date) {
      query += ' AND created_at <= ?';
      params.push(end_date + ' 23:59:59');
    }

    query += ` ORDER BY created_at DESC LIMIT ${limitNum}`;

    const [rows] = await db.execute(query, params);
    res.json(rows);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// GET /api/audit-logs/entity/:type/:id - Get audit logs for specific entity
app.get('/api/audit-logs/entity/:type/:id', requireAuth, requirePermission('audit.view'), async (req, res) => {
  try {
    const [rows] = await db.execute(
      `SELECT * FROM audit_logs WHERE entity_type = ? AND entity_id = ? ORDER BY created_at DESC LIMIT 100`,
      [req.params.type, req.params.id]
    );
    res.json(rows);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// GET /api/audit-logs/export - Export audit logs to CSV
app.get('/api/audit-logs/export', requireAuth, requirePermission('audit.export'), async (req, res) => {
  try {
    const { user_id, action, entity_type, start_date, end_date, format } = req.query;

    let query = `SELECT id, user_id, username, action, entity_type, entity_id,
                 before_json, after_json, ip_address, user_agent, created_at
                 FROM audit_logs WHERE 1=1`;
    const params = [];

    if (user_id) {
      query += ' AND user_id = ?';
      params.push(user_id);
    }
    if (action) {
      query += ' AND action = ?';
      params.push(action);
    }
    if (entity_type) {
      query += ' AND entity_type = ?';
      params.push(entity_type);
    }
    if (start_date) {
      query += ' AND created_at >= ?';
      params.push(start_date);
    }
    if (end_date) {
      query += ' AND created_at <= ?';
      params.push(end_date + ' 23:59:59');
    }

    query += ' ORDER BY created_at DESC LIMIT 10000';

    const [rows] = await db.execute(query, params);

    await logAudit(req.user.id, req.user.username, 'AUDIT_LOG_EXPORT', 'audit_logs', null,
      null, { count: rows.length, filters: { user_id, action, entity_type, start_date, end_date } }, req);

    if (format === 'json') {
      res.setHeader('Content-Disposition', 'attachment; filename=audit_logs.json');
      res.setHeader('Content-Type', 'application/json');
      return res.json(rows);
    }

    // Default: CSV format
    const csvHeaders = ['ID', 'User ID', 'Username', 'Action', 'Entity Type', 'Entity ID', 'Before', 'After', 'IP Address', 'User Agent', 'Created At'];
    const csvRows = rows.map(row => [
      row.id,
      row.user_id || '',
      row.username || '',
      row.action,
      row.entity_type || '',
      row.entity_id || '',
      row.before_json ? JSON.stringify(row.before_json).replace(/"/g, '""') : '',
      row.after_json ? JSON.stringify(row.after_json).replace(/"/g, '""') : '',
      row.ip_address || '',
      (row.user_agent || '').replace(/"/g, '""'),
      row.created_at ? new Date(row.created_at).toISOString() : ''
    ].map(v => `"${v}"`).join(','));

    const csv = [csvHeaders.join(','), ...csvRows].join('\n');

    res.setHeader('Content-Disposition', 'attachment; filename=audit_logs.csv');
    res.setHeader('Content-Type', 'text/csv');
    res.send(csv);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// ============ AI PROXY ROUTES ============

// Claude API Proxy
app.post('/api/ai/claude', async (req, res) => {
  try {
    const { messages, model, system } = req.body;

    const apiKey = process.env.ANTHROPIC_API_KEY;
    if (!apiKey) {
      return res.status(400).json({ error: 'Anthropic API key not configured' });
    }

    const response = await fetch('https://api.anthropic.com/v1/messages', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'x-api-key': apiKey,
        'anthropic-version': '2023-06-01'
      },
      body: JSON.stringify({
        model: model || 'claude-3-5-sonnet-20241022',
        max_tokens: 1024,
        system: system || '',
        messages: messages
      })
    });

    const data = await response.json();

    if (!response.ok) {
      return res.status(response.status).json(data);
    }

    res.json(data);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// OpenAI API Proxy
app.post('/api/ai/openai', async (req, res) => {
  try {
    const { messages, model } = req.body;

    const apiKey = process.env.OPENAI_API_KEY;
    if (!apiKey) {
      return res.status(400).json({ error: 'OpenAI API key not configured' });
    }

    const response = await fetch('https://api.openai.com/v1/chat/completions', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Authorization': `Bearer ${apiKey}`
      },
      body: JSON.stringify({
        model: model || 'gpt-4o',
        messages: messages,
        max_tokens: 1024
      })
    });

    const data = await response.json();

    if (!response.ok) {
      return res.status(response.status).json(data);
    }

    res.json(data);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// ============ AI DATA DICTIONARY & EXPLAIN ROUTES ============

// Data Dictionary - describes all tables and columns
const DATA_DICTIONARY = {
  invoices: {
    description: 'Tabel utama untuk menyimpan data invoice pembelian rambut dari petani/subcon',
    columns: {
      id: 'ID unik invoice (auto increment)',
      no_invoice: 'Nomor invoice unik, format: INV-YYYYMMDD-XXX',
      tanggal: 'Tanggal transaksi invoice',
      pic: 'Person In Charge (penanggung jawab) transaksi',
      subcon: 'Nama subcon (supplier perantara)',
      wilayah: 'Wilayah asal barang (JAWA/SUMATRA)',
      petani_name: 'Nama petani atau supplier langsung',
      total: 'Total nilai transaksi dalam Rupiah',
      status: 'Status invoice: Pending, Selesai, Cancel',
      verification_status: 'Status verifikasi gudang: PENDING, VERIFIED',
      verified_by: 'Nama staff gudang yang memverifikasi',
      verified_at: 'Waktu verifikasi',
      deleted_at: 'Waktu soft delete (NULL jika aktif)',
      deleted_by: 'User ID yang menghapus',
      delete_reason: 'Alasan penghapusan'
    }
  },
  invoice_items: {
    description: 'Detail item dalam invoice - jenis rambut, berat, harga',
    columns: {
      id: 'ID unik item',
      invoice_id: 'Foreign key ke invoices.id',
      no_invoice: 'Nomor invoice (denormalized)',
      kategori: 'Kategori barang: REMY, NON-REMY, BULK',
      jenis: 'Jenis rambut: Body Wave, Straight, Curly, dll',
      warna: 'Warna rambut: HITAM, UBAN',
      kg: 'Berat dalam kilogram',
      harga_per_kg: 'Harga per kilogram dalam Rupiah',
      subtotal: 'Subtotal = kg × harga_per_kg'
    }
  },
  invoice_item_verifications: {
    description: 'Data verifikasi per item oleh gudang - perbandingan berat invoice vs aktual',
    columns: {
      id: 'ID unik verifikasi',
      no_invoice: 'Nomor invoice',
      invoice_item_id: 'Foreign key ke invoice_items.id',
      kg_invoice: 'Berat sesuai invoice',
      kg_received: 'Berat aktual yang diterima gudang',
      selisih_kg: 'Selisih = kg_invoice - kg_received',
      remy_grade: 'Grade untuk REMY: KW (kualitas rendah) atau ORI (original)',
      note: 'Catatan verifikasi',
      verified_by: 'Staff yang memverifikasi'
    }
  },
  retul_calculators: {
    description: 'Header untuk kalkulator retul (pengolahan ulang rambut)',
    columns: {
      id: 'ID unik retul calculator',
      no_invoice: 'Nomor invoice yang di-retul',
      verified_by: 'Staff yang memverifikasi hasil retul',
      verified_at: 'Waktu verifikasi retul'
    }
  },
  retul_rows: {
    description: 'Detail per ukuran rambut dalam proses retul',
    columns: {
      id: 'ID unik row',
      retul_id: 'Foreign key ke retul_calculators.id',
      size_inch: 'Ukuran rambut dalam inch: 6", 8", 10", 12", 14", 16", 18", 20", 22", UP',
      hitam_by_pic: 'JSON object: {"PIC_ID": kg} - berat hitam per PIC',
      kg_1: 'Kolom legacy untuk PIC 1 (LEHAN)',
      kg_2: 'Kolom legacy untuk PIC 2 (MUN)',
      kg_3: 'Kolom legacy untuk PIC 3 (RIGEN)',
      kg_4: 'Kolom legacy untuk PIC 4 (PAKDE)',
      total_hitam: 'Total berat hitam semua PIC',
      lus_uban: 'Berat rambut uban (LUS)',
      migrated: 'Flag migrasi dari kg_1-kg_4 ke hitam_by_pic'
    }
  },
  retul_summary: {
    description: 'Ringkasan hasil retul per kategori',
    columns: {
      id: 'ID unik summary',
      retul_id: 'Foreign key ke retul_calculators.id',
      label: 'Label kategori: timbanganAwal, hasil, kowol, petit, sisa, karet, bahanCina',
      hitam: 'Total berat hitam untuk kategori ini',
      uban: 'Total berat uban untuk kategori ini',
      total: 'Total = hitam + uban'
    }
  },
  users: {
    description: 'Tabel user untuk autentikasi dan manajemen akses',
    columns: {
      id: 'ID unik user',
      username: 'Username untuk login (unik)',
      password_hash: 'Password yang di-hash dengan bcrypt',
      full_name: 'Nama lengkap user',
      role: 'Role user: OWNER, ADMIN, STAFF_PURCHASE, STAFF_GUDANG, VIEWER',
      is_active: 'Status aktif: 1=aktif, 0=nonaktif',
      last_login_at: 'Waktu login terakhir'
    }
  },
  permissions: {
    description: 'Master daftar permission yang tersedia',
    columns: {
      id: 'ID unik permission',
      code: 'Kode permission unik, contoh: invoice.view, invoice.create',
      name: 'Nama permission yang ditampilkan',
      module: 'Modul terkait: invoice, verification, retul, deposit, master, report, user, audit'
    }
  },
  audit_logs: {
    description: 'Log audit untuk tracking semua aksi sensitif',
    columns: {
      id: 'ID unik log',
      user_id: 'ID user yang melakukan aksi',
      username: 'Username untuk referensi',
      action: 'Jenis aksi: LOGIN, LOGOUT, CREATE, UPDATE, DELETE, dll',
      entity_type: 'Jenis entity: invoice, user, retul, dll',
      entity_id: 'ID entity yang diubah',
      before_json: 'Data sebelum perubahan (JSON)',
      after_json: 'Data setelah perubahan (JSON)',
      ip_address: 'IP address client',
      created_at: 'Waktu aksi'
    }
  }
};

// GET /api/ai/data-dictionary - Get all table definitions
app.get('/api/ai/data-dictionary', async (req, res) => {
  res.json(DATA_DICTIONARY);
});

// GET /api/ai/data-dictionary/:table - Get specific table definition
app.get('/api/ai/data-dictionary/:table', async (req, res) => {
  const table = req.params.table;
  if (!DATA_DICTIONARY[table]) {
    return res.status(404).json({ error: `Table '${table}' not found in dictionary` });
  }
  res.json({ table, ...DATA_DICTIONARY[table] });
});

// POST /api/ai/explain - AI explain data/angka
app.post('/api/ai/explain', async (req, res) => {
  try {
    const { context, data, question, language } = req.body;

    // Try Claude first, then OpenAI as fallback
    const claudeKey = process.env.ANTHROPIC_API_KEY;
    const openaiKey = process.env.OPENAI_API_KEY;

    if (!claudeKey && !openaiKey) {
      return res.status(400).json({ error: 'No AI API key configured' });
    }

    // Build system prompt with data dictionary context
    const systemPrompt = `Kamu adalah asisten AI untuk Indo Hair Purchase System, sistem manajemen pembelian rambut.

DATA DICTIONARY:
${JSON.stringify(DATA_DICTIONARY, null, 2)}

KONTEKS SISTEM:
- Sistem ini digunakan untuk tracking pembelian rambut dari petani/subcon
- Proses: Invoice → Verifikasi Gudang → Retul (pengolahan) → HPP
- Wilayah: JAWA dan SUMATRA
- Kategori rambut: REMY (premium), NON-REMY, BULK
- Grade REMY: ORI (original) dan KW (kualitas rendah)
- Ukuran rambut: 6" sampai 22" dan UP (lebih dari 22")
- Retul adalah proses sortir ulang rambut berdasarkan ukuran dan kualitas
- HPP = Harga Pokok Penjualan (cost per kg)

ATURAN:
1. Jawab dalam bahasa ${language || 'Indonesia'}
2. Jelaskan angka-angka dengan konteks bisnis yang relevan
3. Berikan insight jika ada anomali atau hal yang perlu diperhatikan
4. Gunakan format yang mudah dibaca`;

    const userMessage = `${context ? `KONTEKS: ${context}\n\n` : ''}DATA:
${typeof data === 'object' ? JSON.stringify(data, null, 2) : data}

PERTANYAAN: ${question || 'Jelaskan data ini'}`;

    let explanation = '';

    // Try Claude first
    if (claudeKey) {
      try {
        const claudeResponse = await fetch('https://api.anthropic.com/v1/messages', {
          method: 'POST',
          headers: {
            'Content-Type': 'application/json',
            'x-api-key': claudeKey,
            'anthropic-version': '2023-06-01'
          },
          body: JSON.stringify({
            model: 'claude-3-5-sonnet-20241022',
            max_tokens: 1024,
            system: systemPrompt,
            messages: [{ role: 'user', content: userMessage }]
          })
        });

        if (claudeResponse.ok) {
          const claudeData = await claudeResponse.json();
          explanation = claudeData.content[0]?.text || '';
        }
      } catch (err) {
        console.log('Claude API error:', err.message);
      }
    }

    // Fallback to OpenAI if Claude failed
    if (!explanation && openaiKey) {
      try {
        const openaiResponse = await fetch('https://api.openai.com/v1/chat/completions', {
          method: 'POST',
          headers: {
            'Content-Type': 'application/json',
            'Authorization': `Bearer ${openaiKey}`
          },
          body: JSON.stringify({
            model: 'gpt-4o',
            max_tokens: 1024,
            messages: [
              { role: 'system', content: systemPrompt },
              { role: 'user', content: userMessage }
            ]
          })
        });

        if (openaiResponse.ok) {
          const openaiData = await openaiResponse.json();
          explanation = openaiData.choices[0]?.message?.content || '';
        }
      } catch (err) {
        console.log('OpenAI API error:', err.message);
      }
    }

    if (!explanation) {
      return res.status(500).json({ error: 'Failed to generate explanation from AI' });
    }

    res.json({
      success: true,
      explanation,
      context: context || null,
      data_type: typeof data
    });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// POST /api/ai/ask - General AI assistant for the system
app.post('/api/ai/ask', async (req, res) => {
  try {
    const { question, include_schema, language } = req.body;

    const claudeKey = process.env.ANTHROPIC_API_KEY;
    const openaiKey = process.env.OPENAI_API_KEY;

    if (!claudeKey && !openaiKey) {
      return res.status(400).json({ error: 'No AI API key configured' });
    }

    const systemPrompt = `Kamu adalah asisten AI untuk Indo Hair Purchase System.
${include_schema ? `\nDATA DICTIONARY:\n${JSON.stringify(DATA_DICTIONARY, null, 2)}` : ''}

Jawab dalam bahasa ${language || 'Indonesia'}.
Berikan jawaban yang ringkas dan praktis.`;

    let answer = '';

    if (claudeKey) {
      try {
        const response = await fetch('https://api.anthropic.com/v1/messages', {
          method: 'POST',
          headers: {
            'Content-Type': 'application/json',
            'x-api-key': claudeKey,
            'anthropic-version': '2023-06-01'
          },
          body: JSON.stringify({
            model: 'claude-3-5-sonnet-20241022',
            max_tokens: 1024,
            system: systemPrompt,
            messages: [{ role: 'user', content: question }]
          })
        });

        if (response.ok) {
          const data = await response.json();
          answer = data.content[0]?.text || '';
        }
      } catch (err) {
        console.log('Claude error:', err.message);
      }
    }

    if (!answer && openaiKey) {
      try {
        const response = await fetch('https://api.openai.com/v1/chat/completions', {
          method: 'POST',
          headers: {
            'Content-Type': 'application/json',
            'Authorization': `Bearer ${openaiKey}`
          },
          body: JSON.stringify({
            model: 'gpt-4o',
            max_tokens: 1024,
            messages: [
              { role: 'system', content: systemPrompt },
              { role: 'user', content: question }
            ]
          })
        });

        if (response.ok) {
          const data = await response.json();
          answer = data.choices[0]?.message?.content || '';
        }
      } catch (err) {
        console.log('OpenAI error:', err.message);
      }
    }

    if (!answer) {
      return res.status(500).json({ error: 'Failed to get answer from AI' });
    }

    res.json({ success: true, answer });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// ============ INVOICE ROUTES ============

// In-memory storage (fallback when DB not available)
let memoryInvoices = [];
let memoryDeposits = [];
let memoryVerifications = [];
let memoryRetul = [];

// GET all invoices (exclude soft-deleted)
app.get('/api/invoices', async (req, res) => {
  try {
    if (db) {
      try {
        const [rows] = await db.execute(
          'SELECT * FROM invoices WHERE deleted_at IS NULL ORDER BY created_at DESC LIMIT 100'
        );
        // Combine with memory invoices
        const combined = [...rows, ...memoryInvoices].sort((a, b) =>
          new Date(b.created_at) - new Date(a.created_at)
        );
        return res.json(combined);
      } catch (dbError) {
        console.log('DB query failed, using memory only');
      }
    }
    res.json(memoryInvoices.sort((a, b) => new Date(b.created_at) - new Date(a.created_at)));
  } catch (error) {
    res.json(memoryInvoices);
  }
});

// GET invoice by ID (with items and verifications, exclude soft-deleted)
app.get('/api/invoices/:id', async (req, res) => {
  try {
    if (db) {
      const [invoice] = await db.execute(
        'SELECT * FROM invoices WHERE id = ? AND deleted_at IS NULL', [req.params.id]
      );
      if (invoice.length === 0) {
        return res.status(404).json({ error: 'Invoice not found' });
      }
      const [items] = await db.execute(
        'SELECT * FROM invoice_items WHERE invoice_id = ?', [req.params.id]
      );
      const [verifications] = await db.execute(
        'SELECT * FROM invoice_item_verifications WHERE no_invoice = ?', [invoice[0].no_invoice]
      );
      return res.json({ ...invoice[0], items, itemVerifications: verifications });
    }
    // Memory fallback
    const inv = memoryInvoices.find(i => i.id == req.params.id);
    if (!inv) return res.status(404).json({ error: 'Invoice not found' });
    res.json(inv);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// GET invoice by no_invoice (with items, verifications, retul, exclude soft-deleted)
app.get('/api/invoices/no/:noInvoice', async (req, res) => {
  try {
    const noInvoice = req.params.noInvoice;
    if (db) {
      const [invoice] = await db.execute(
        'SELECT * FROM invoices WHERE no_invoice = ? AND deleted_at IS NULL', [noInvoice]
      );
      if (invoice.length === 0) {
        // Check memory
        const memInv = memoryInvoices.find(i => i.no_invoice === noInvoice);
        if (memInv) return res.json(memInv);
        return res.status(404).json({ error: 'Invoice not found' });
      }
      const [items] = await db.execute(
        'SELECT * FROM invoice_items WHERE no_invoice = ? OR invoice_id = ?',
        [noInvoice, invoice[0].id]
      );
      const [verifications] = await db.execute(
        'SELECT * FROM invoice_item_verifications WHERE no_invoice = ?', [noInvoice]
      );

      // Get retul data if exists
      let retulCalculator = null;
      const [retul] = await db.execute(
        'SELECT * FROM retul_calculators WHERE no_invoice = ?', [noInvoice]
      );
      if (retul.length > 0) {
        const [rows] = await db.execute(
          'SELECT * FROM retul_rows WHERE retul_id = ? ORDER BY id', [retul[0].id]
        );
        const [summary] = await db.execute(
          'SELECT * FROM retul_summary WHERE retul_id = ?', [retul[0].id]
        );
        retulCalculator = { ...retul[0], rows, summary };
      }

      return res.json({
        ...invoice[0],
        items,
        itemVerifications: verifications,
        retulCalculator
      });
    }
    // Memory fallback
    const inv = memoryInvoices.find(i => i.no_invoice === noInvoice);
    if (!inv) return res.status(404).json({ error: 'Invoice not found' });
    res.json(inv);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// POST create invoice
app.post('/api/invoices', async (req, res) => {
  try {
    const { no_invoice, tanggal, pic, subcon, wilayah, petani_name, total, items } = req.body;

    if (db) {
      try {
        const [result] = await db.execute(
          `INSERT INTO invoices (no_invoice, tanggal, pic, subcon, wilayah, petani_name, total)
           VALUES (?, ?, ?, ?, ?, ?, ?)`,
          [no_invoice, tanggal, pic, subcon, wilayah, petani_name || null, total]
        );

        const invoiceId = result.insertId;

        // Insert items
        for (const item of items || []) {
          await db.execute(
            `INSERT INTO invoice_items (invoice_id, no_invoice, kategori, jenis, warna, kg, harga_per_kg, subtotal)
             VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
            [invoiceId, no_invoice, item.kategori, item.jenis, item.warna || null,
             item.qty || item.kg, item.harga || item.harga_per_kg, item.subtotal]
          );
        }

        return res.json({ success: true, id: invoiceId, no_invoice });
      } catch (dbError) {
        console.log('DB insert failed, using memory:', dbError.message);
      }
    }

    // Fallback to memory storage
    const newInvoice = {
      id: memoryInvoices.length + 1,
      no_invoice,
      tanggal,
      pic,
      subcon,
      wilayah,
      petani_name: petani_name || null,
      total,
      items: items || [],
      status: 'Pending',
      verification_status: 'PENDING',
      verified_by: null,
      verified_at: null,
      itemVerifications: [],
      created_at: new Date().toISOString()
    };
    memoryInvoices.push(newInvoice);
    console.log('Invoice saved to memory:', no_invoice);

    res.json({ success: true, id: newInvoice.id, no_invoice, storage: 'memory' });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// PUT update invoice status
app.put('/api/invoices/:id/status', async (req, res) => {
  try {
    const { status } = req.body;
    if (db) {
      await db.execute(
        'UPDATE invoices SET status = ? WHERE id = ?',
        [status, req.params.id]
      );
      return res.json({ success: true });
    }
    // Memory fallback
    const inv = memoryInvoices.find(i => i.id == req.params.id);
    if (inv) inv.status = status;
    res.json({ success: true });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// DELETE invoice (SOFT DELETE - requires auth)
app.delete('/api/invoices/:id', requireAuth, requirePermission('invoice.delete'), async (req, res) => {
  try {
    const { reason } = req.body;
    const invoiceId = req.params.id;

    if (db) {
      // Get invoice data before soft delete
      const [current] = await db.execute('SELECT * FROM invoices WHERE id = ? AND deleted_at IS NULL', [invoiceId]);
      if (current.length === 0) {
        return res.status(404).json({ error: 'Invoice not found or already deleted' });
      }

      // Soft delete
      await db.execute(
        `UPDATE invoices SET deleted_at = NOW(), deleted_by = ?, delete_reason = ? WHERE id = ?`,
        [req.user.id, reason || null, invoiceId]
      );

      await logAudit(req.user.id, req.user.username, 'INVOICE_SOFT_DELETE', 'invoice', invoiceId, current[0], { reason }, req);

      return res.json({ success: true, message: 'Invoice soft deleted' });
    }
    memoryInvoices = memoryInvoices.filter(i => i.id != invoiceId);
    res.json({ success: true });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// POST restore deleted invoice (requires auth)
app.post('/api/invoices/:id/restore', requireAuth, requirePermission('invoice.restore'), async (req, res) => {
  try {
    const invoiceId = req.params.id;

    if (!db) {
      return res.status(500).json({ error: 'Database not available' });
    }

    // Get deleted invoice
    const [current] = await db.execute('SELECT * FROM invoices WHERE id = ? AND deleted_at IS NOT NULL', [invoiceId]);
    if (current.length === 0) {
      return res.status(404).json({ error: 'Deleted invoice not found' });
    }

    // Restore
    await db.execute(
      `UPDATE invoices SET deleted_at = NULL, deleted_by = NULL, delete_reason = NULL WHERE id = ?`,
      [invoiceId]
    );

    await logAudit(req.user.id, req.user.username, 'INVOICE_RESTORE', 'invoice', invoiceId,
      { deleted_at: current[0].deleted_at, delete_reason: current[0].delete_reason },
      null, req);

    res.json({ success: true, message: 'Invoice restored' });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// DELETE invoice permanently (HARD DELETE - requires auth + special permission)
app.delete('/api/invoices/:id/permanent', requireAuth, requirePermission('invoice.hard_delete'), async (req, res) => {
  try {
    const invoiceId = req.params.id;

    if (!db) {
      return res.status(500).json({ error: 'Database not available' });
    }

    // Get invoice data before hard delete
    const [current] = await db.execute('SELECT * FROM invoices WHERE id = ?', [invoiceId]);
    if (current.length === 0) {
      return res.status(404).json({ error: 'Invoice not found' });
    }

    // Hard delete (cascade will remove items, verifications, etc)
    await db.execute('DELETE FROM invoices WHERE id = ?', [invoiceId]);

    await logAudit(req.user.id, req.user.username, 'INVOICE_HARD_DELETE', 'invoice', invoiceId, current[0], null, req);

    res.json({ success: true, message: 'Invoice permanently deleted' });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// GET deleted invoices (trash bin)
// BULK DELETE invoices (OWNER only - for AI Control)
app.delete('/api/invoices/bulk/all', requireAuth, async (req, res) => {
  try {
    // Only OWNER can bulk delete
    if (req.user.role !== 'OWNER') {
      return res.status(403).json({ error: 'Only OWNER can perform bulk delete' });
    }

    const { reason } = req.body;

    if (!db) {
      memoryInvoices = [];
      return res.json({ success: true, message: 'All invoices deleted (memory)', count: 0 });
    }

    // Get count first
    const [countResult] = await db.execute('SELECT COUNT(*) as cnt FROM invoices WHERE deleted_at IS NULL');
    const count = countResult[0].cnt;

    // Soft delete all
    await db.execute(
      `UPDATE invoices SET deleted_at = NOW(), deleted_by = ?, delete_reason = ? WHERE deleted_at IS NULL`,
      [req.user.id, reason || 'Bulk delete by OWNER via AI']
    );

    await logAudit(req.user.id, req.user.username, 'BULK_INVOICE_DELETE', 'invoice', null, { count }, { reason }, req);

    res.json({ success: true, message: `${count} invoices soft deleted`, count });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

app.get('/api/invoices/deleted/list', requireAuth, requirePermission('invoice.restore'), async (req, res) => {
  try {
    if (!db) return res.json([]);

    const [rows] = await db.execute(
      `SELECT i.*, u.username as deleted_by_username
       FROM invoices i
       LEFT JOIN users u ON u.id = i.deleted_by
       WHERE i.deleted_at IS NOT NULL
       ORDER BY i.deleted_at DESC`
    );
    res.json(rows);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// ============ VERIFICATION ROUTES ============

// POST verify invoice (by gudang LEHAN/MUN)
app.post('/api/invoices/:noInvoice/verify', async (req, res) => {
  try {
    const { verified_by, itemVerifications } = req.body;
    const noInvoice = req.params.noInvoice;

    if (db) {
      try {
        // Update invoice verification status
        await db.execute(
          `UPDATE invoices SET
           verification_status = 'VERIFIED',
           verified_by = ?,
           verified_at = NOW(),
           status = 'Selesai'
           WHERE no_invoice = ?`,
          [verified_by, noInvoice]
        );

        // Insert item verifications
        for (const verif of itemVerifications || []) {
          await db.execute(
            `INSERT INTO invoice_item_verifications
             (no_invoice, invoice_item_id, kg_invoice, kg_received, selisih_kg, remy_grade, note, verified_by)
             VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
            [noInvoice, verif.itemId, verif.kgInvoice, verif.kgReceived,
             verif.selisihKg, verif.remyGrade || null, verif.note || null, verified_by]
          );
        }

        return res.json({ success: true, message: `Invoice verified by ${verified_by}` });
      } catch (dbError) {
        console.log('DB verify failed:', dbError.message);
      }
    }

    // Memory fallback
    const inv = memoryInvoices.find(i => i.no_invoice === noInvoice);
    if (inv) {
      inv.verification_status = 'VERIFIED';
      inv.verified_by = verified_by;
      inv.verified_at = new Date().toISOString();
      inv.status = 'Selesai';
      inv.itemVerifications = itemVerifications || [];
    }
    res.json({ success: true, storage: 'memory' });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// GET verifications for invoice
app.get('/api/invoices/:noInvoice/verifications', async (req, res) => {
  try {
    if (db) {
      const [rows] = await db.execute(
        'SELECT * FROM invoice_item_verifications WHERE no_invoice = ?',
        [req.params.noInvoice]
      );
      return res.json(rows);
    }
    const inv = memoryInvoices.find(i => i.no_invoice === req.params.noInvoice);
    res.json(inv?.itemVerifications || []);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// GET laporan selisih berat (kg_invoice vs kg_received)
app.get('/api/reports/selisih', async (req, res) => {
  try {
    if (db) {
      try {
        const [rows] = await db.execute(`
          SELECT
            i.no_invoice,
            i.tanggal,
            i.subcon,
            i.petani_name,
            ii.kategori,
            ii.jenis,
            ii.warna,
            v.kg_invoice,
            v.kg_received,
            v.selisih_kg,
            v.remy_grade,
            v.note,
            v.verified_by,
            v.verified_at
          FROM invoice_item_verifications v
          JOIN invoice_items ii ON ii.id = v.invoice_item_id
          JOIN invoices i ON i.no_invoice = v.no_invoice
          ORDER BY ABS(v.selisih_kg) DESC
          LIMIT 100
        `);
        return res.json(rows);
      } catch (dbError) {
        console.log('DB selisih query failed, using memory:', dbError.message);
      }
    }
    // Memory fallback - aggregate from memoryInvoices
    const results = [];
    for (const inv of memoryInvoices) {
      for (const verif of inv.itemVerifications || []) {
        const item = (inv.items || []).find(it => it.id === verif.itemId);
        if (item) {
          results.push({
            no_invoice: inv.no_invoice,
            tanggal: inv.tanggal,
            subcon: inv.subcon,
            petani_name: inv.petani_name,
            kategori: item.kategori,
            jenis: item.jenis,
            warna: item.warna,
            kg_invoice: verif.kgInvoice,
            kg_received: verif.kgReceived,
            selisih_kg: verif.selisihKg,
            remy_grade: verif.remyGrade,
            note: verif.note,
            verified_by: inv.verified_by,
            verified_at: inv.verified_at
          });
        }
      }
    }
    results.sort((a, b) => Math.abs(b.selisih_kg) - Math.abs(a.selisih_kg));
    res.json(results);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// GET laporan sisa/waste dari retul (Kowol, Petit, Sisa, Karet, Bahan Cina)
app.get('/api/reports/retul-waste', async (req, res) => {
  try {
    if (db) {
      try {
        const [rows] = await db.execute(`
          SELECT
            i.no_invoice,
            i.tanggal,
            i.subcon,
            i.petani_name,
            i.wilayah,
            rs.label,
            rs.hitam,
            rs.uban,
            rs.total,
            rc.verified_by,
            rc.verified_at
          FROM retul_summary rs
          JOIN retul_calculators rc ON rc.id = rs.retul_id
          JOIN invoices i ON i.no_invoice = rc.no_invoice
          WHERE rs.label IN ('kowol','petit','sisa','karet','bahanCina')
          ORDER BY i.no_invoice, rs.label
        `);
        return res.json(rows);
      } catch (dbError) {
        console.log('DB retul-waste query failed, using memory:', dbError.message);
      }
    }
    // Memory fallback
    const results = [];
    const wasteLabels = ['kowol', 'petit', 'sisa', 'karet', 'bahanCina'];
    for (const inv of memoryInvoices) {
      if (inv.retulCalculator?.summary) {
        for (const label of wasteLabels) {
          const data = inv.retulCalculator.summary[label];
          if (data) {
            results.push({
              no_invoice: inv.no_invoice,
              tanggal: inv.tanggal,
              subcon: inv.subcon,
              petani_name: inv.petani_name,
              wilayah: inv.wilayah,
              label,
              hitam: data.hitam,
              uban: data.uban,
              total: data.total,
              verified_by: inv.retulCalculator.verified_by,
              verified_at: inv.retulCalculator.verified_at
            });
          }
        }
      }
    }
    res.json(results);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// GET laporan hasil retul (Timbangan Awal vs Hasil)
app.get('/api/reports/retul-hasil', async (req, res) => {
  try {
    if (db) {
      try {
        const [rows] = await db.execute(`
          SELECT
            i.no_invoice,
            i.tanggal,
            i.subcon,
            i.petani_name,
            i.wilayah,
            MAX(CASE WHEN rs.label = 'timbanganAwal' THEN rs.hitam END) as timbang_awal_hitam,
            MAX(CASE WHEN rs.label = 'timbanganAwal' THEN rs.uban END) as timbang_awal_uban,
            MAX(CASE WHEN rs.label = 'timbanganAwal' THEN rs.total END) as timbang_awal_total,
            MAX(CASE WHEN rs.label = 'hasil' THEN rs.hitam END) as hasil_hitam,
            MAX(CASE WHEN rs.label = 'hasil' THEN rs.uban END) as hasil_uban,
            MAX(CASE WHEN rs.label = 'hasil' THEN rs.total END) as hasil_total,
            rc.verified_by,
            rc.verified_at
          FROM retul_summary rs
          JOIN retul_calculators rc ON rc.id = rs.retul_id
          JOIN invoices i ON i.no_invoice = rc.no_invoice
          WHERE rs.label IN ('timbanganAwal', 'hasil')
          GROUP BY i.no_invoice, i.tanggal, i.subcon, i.petani_name, i.wilayah, rc.verified_by, rc.verified_at
          ORDER BY i.tanggal DESC
        `);
        return res.json(rows);
      } catch (dbError) {
        console.log('DB retul-hasil query failed, using memory:', dbError.message);
      }
    }
    // Memory fallback
    const results = [];
    for (const inv of memoryInvoices) {
      if (inv.retulCalculator?.summary) {
        const s = inv.retulCalculator.summary;
        results.push({
          no_invoice: inv.no_invoice,
          tanggal: inv.tanggal,
          subcon: inv.subcon,
          petani_name: inv.petani_name,
          wilayah: inv.wilayah,
          timbang_awal_hitam: s.timbanganAwal?.hitam || 0,
          timbang_awal_uban: s.timbanganAwal?.uban || 0,
          timbang_awal_total: s.timbanganAwal?.total || 0,
          hasil_hitam: s.hasil?.hitam || 0,
          hasil_uban: s.hasil?.uban || 0,
          hasil_total: s.hasil?.total || 0,
          verified_by: inv.retulCalculator.verified_by,
          verified_at: inv.retulCalculator.verified_at
        });
      }
    }
    res.json(results);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// GET laporan total waste per petani (grouped by petani_name)
app.get('/api/reports/petani-waste', async (req, res) => {
  try {
    if (db) {
      try {
        const [rows] = await db.execute(`
          SELECT
            i.petani_name,
            SUM(rs.total) AS total_waste_kg
          FROM retul_summary rs
          JOIN retul_calculators rc ON rc.id = rs.retul_id
          JOIN invoices i ON i.no_invoice = rc.no_invoice
          WHERE rs.label IN ('kowol','petit','sisa','karet')
          GROUP BY i.petani_name
          ORDER BY total_waste_kg DESC
        `);
        return res.json(rows);
      } catch (dbError) {
        console.log('DB petani-waste query failed, using memory:', dbError.message);
      }
    }
    // Memory fallback
    const wasteLabels = ['kowol', 'petit', 'sisa', 'karet'];
    const petaniMap = {};
    for (const inv of memoryInvoices) {
      if (inv.retulCalculator?.summary && inv.petani_name) {
        let totalWaste = 0;
        for (const label of wasteLabels) {
          const data = inv.retulCalculator.summary[label];
          if (data) {
            totalWaste += data.total || 0;
          }
        }
        if (!petaniMap[inv.petani_name]) {
          petaniMap[inv.petani_name] = 0;
        }
        petaniMap[inv.petani_name] += totalWaste;
      }
    }
    const results = Object.entries(petaniMap)
      .map(([petani_name, total_waste_kg]) => ({ petani_name, total_waste_kg }))
      .sort((a, b) => b.total_waste_kg - a.total_waste_kg);
    res.json(results);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// GET laporan nilai beli vs hasil (profitability analysis)
app.get('/api/reports/invoice-hasil', async (req, res) => {
  try {
    const hargaInternal = parseFloat(req.query.harga_internal) || 0;

    if (db) {
      try {
        const [rows] = await db.execute(`
          SELECT
            i.no_invoice,
            i.tanggal,
            i.subcon,
            i.petani_name,
            i.total AS nilai_beli,
            SUM(
              CASE
                WHEN rs.label = 'hasil' THEN rs.total
                ELSE 0
              END
            ) AS hasil_kg
          FROM invoices i
          JOIN retul_calculators rc ON rc.no_invoice = i.no_invoice
          JOIN retul_summary rs ON rs.retul_id = rc.id
          GROUP BY i.no_invoice, i.tanggal, i.subcon, i.petani_name, i.total
          ORDER BY i.tanggal DESC
        `);
        // Add estimasi_nilai_hasil calculation
        const results = rows.map(row => ({
          ...row,
          estimasi_nilai_hasil: (row.hasil_kg || 0) * hargaInternal
        }));
        return res.json(results);
      } catch (dbError) {
        console.log('DB invoice-hasil query failed, using memory:', dbError.message);
      }
    }
    // Memory fallback
    const results = [];
    for (const inv of memoryInvoices) {
      if (inv.retulCalculator?.summary) {
        const hasilKg = inv.retulCalculator.summary.hasil?.total || 0;
        results.push({
          no_invoice: inv.no_invoice,
          tanggal: inv.tanggal,
          subcon: inv.subcon,
          petani_name: inv.petani_name,
          nilai_beli: inv.total,
          hasil_kg: hasilKg,
          estimasi_nilai_hasil: hasilKg * hargaInternal
        });
      }
    }
    res.json(results);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// GET laporan remy grade per invoice (KW vs ORI)
app.get('/api/reports/remy-grade', async (req, res) => {
  try {
    const kategori = req.query.kategori || 'REMY';

    if (db) {
      try {
        const [rows] = await db.execute(`
          SELECT
            i.no_invoice,
            i.tanggal,
            i.subcon,
            i.petani_name,
            ii.kategori,
            v.remy_grade,
            SUM(v.kg_received) AS total_kg
          FROM invoice_item_verifications v
          JOIN invoice_items ii ON ii.id = v.invoice_item_id
          JOIN invoices i ON i.no_invoice = v.no_invoice
          WHERE ii.kategori = ?
          GROUP BY i.no_invoice, i.tanggal, i.subcon, i.petani_name, ii.kategori, v.remy_grade
          ORDER BY i.tanggal DESC, i.no_invoice
        `, [kategori]);
        return res.json(rows);
      } catch (dbError) {
        console.log('DB remy-grade query failed, using memory:', dbError.message);
      }
    }
    // Memory fallback
    const results = [];
    for (const inv of memoryInvoices) {
      const gradeMap = {};
      for (const verif of inv.itemVerifications || []) {
        const item = (inv.items || []).find(it => it.id === verif.itemId);
        if (item && item.kategori === kategori) {
          const grade = verif.remyGrade || 'UNKNOWN';
          if (!gradeMap[grade]) {
            gradeMap[grade] = 0;
          }
          gradeMap[grade] += verif.kgReceived || 0;
        }
      }
      for (const [grade, totalKg] of Object.entries(gradeMap)) {
        results.push({
          no_invoice: inv.no_invoice,
          tanggal: inv.tanggal,
          subcon: inv.subcon,
          petani_name: inv.petani_name,
          kategori,
          remy_grade: grade,
          total_kg: totalKg
        });
      }
    }
    res.json(results);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// ============ DASHBOARD KPI ROUTES ============

// GET Dashboard KPI Summary Cards
app.get('/api/dashboard/kpi-summary', async (req, res) => {
  try {
    const { start_date, end_date, pic, wilayah, subcon, petani, status, kategori } = req.query;
    const startDate = start_date || new Date(Date.now() - 30*24*60*60*1000).toISOString().split('T')[0];
    const endDate = end_date || new Date().toISOString().split('T')[0];

    if (db) {
      try {
        // Build WHERE clause
        let whereClause = `WHERE i.tanggal BETWEEN ? AND ?`;
        const params = [startDate, endDate];

        if (pic) { whereClause += ` AND i.pic = ?`; params.push(pic); }
        if (wilayah) { whereClause += ` AND i.wilayah = ?`; params.push(wilayah); }
        if (subcon) { whereClause += ` AND i.subcon = ?`; params.push(subcon); }
        if (petani) { whereClause += ` AND i.petani_name = ?`; params.push(petani); }
        if (status) { whereClause += ` AND i.verification_status = ?`; params.push(status); }

        // 1. Total Purchase (COGS)
        const [purchaseRows] = await db.execute(`
          SELECT COALESCE(SUM(i.total), 0) AS total_purchase_rp
          FROM invoices i ${whereClause}
        `, params);

        // 2. Retul metrics (Hasil, Waste, Timbangan Awal)
        const [retulRows] = await db.execute(`
          SELECT
            COALESCE(SUM(CASE WHEN rs.label = 'timbanganAwal' THEN rs.total ELSE 0 END), 0) AS awal_kg,
            COALESCE(SUM(CASE WHEN rs.label = 'hasil' THEN rs.total ELSE 0 END), 0) AS hasil_kg,
            COALESCE(SUM(CASE WHEN rs.label IN ('kowol','petit','sisa','karet','bahanCina') THEN rs.total ELSE 0 END), 0) AS waste_kg
          FROM invoices i
          JOIN retul_calculators rc ON rc.no_invoice = i.no_invoice
          JOIN retul_summary rs ON rs.retul_id = rc.id
          ${whereClause}
        `, params);

        // 3. Selisih Timbangan
        const [selisihRows] = await db.execute(`
          SELECT COALESCE(SUM(v.selisih_kg), 0) AS selisih_kg
          FROM invoice_item_verifications v
          JOIN invoices i ON i.no_invoice = v.no_invoice
          ${whereClause}
        `, params);

        // 4. KW Rate (REMY only)
        let kwParams = [...params];
        let kwWhere = whereClause;
        if (kategori) {
          kwWhere += ` AND ii.kategori = ?`;
          kwParams.push(kategori);
        } else {
          kwWhere += ` AND ii.kategori = 'REMY'`;
        }
        const [kwRows] = await db.execute(`
          SELECT
            COALESCE(SUM(CASE WHEN v.remy_grade = 'KW' THEN v.kg_received ELSE 0 END), 0) AS kg_kw,
            COALESCE(SUM(CASE WHEN v.remy_grade = 'ORI' THEN v.kg_received ELSE 0 END), 0) AS kg_ori
          FROM invoice_item_verifications v
          JOIN invoice_items ii ON ii.id = v.invoice_item_id
          JOIN invoices i ON i.no_invoice = v.no_invoice
          ${kwWhere}
        `, kwParams);

        // Calculate KPI values
        const totalPurchase = parseFloat(purchaseRows[0]?.total_purchase_rp) || 0;
        const awalKg = parseFloat(retulRows[0]?.awal_kg) || 0;
        const hasilKg = parseFloat(retulRows[0]?.hasil_kg) || 0;
        const wasteKg = parseFloat(retulRows[0]?.waste_kg) || 0;
        const selisihKg = parseFloat(selisihRows[0]?.selisih_kg) || 0;
        const kgKw = parseFloat(kwRows[0]?.kg_kw) || 0;
        const kgOri = parseFloat(kwRows[0]?.kg_ori) || 0;

        const wasteRate = awalKg > 0 ? (wasteKg / awalKg) * 100 : 0;
        const yieldRate = awalKg > 0 ? (hasilKg / awalKg) * 100 : 0;
        const kwRate = (kgKw + kgOri) > 0 ? (kgKw / (kgKw + kgOri)) * 100 : 0;

        return res.json({
          period: { start_date: startDate, end_date: endDate },
          kpi: {
            total_purchase_rp: totalPurchase,
            timbangan_awal_kg: awalKg,
            hasil_kg: hasilKg,
            waste_kg: wasteKg,
            waste_rate_pct: parseFloat(wasteRate.toFixed(2)),
            yield_rate_pct: parseFloat(yieldRate.toFixed(2)),
            selisih_kg: selisihKg,
            kg_kw: kgKw,
            kg_ori: kgOri,
            kw_rate_pct: parseFloat(kwRate.toFixed(2))
          }
        });
      } catch (dbError) {
        console.log('DB kpi-summary query failed, using memory:', dbError.message);
      }
    }

    // Memory fallback
    const filtered = memoryInvoices.filter(inv => {
      const tgl = new Date(inv.tanggal);
      return tgl >= new Date(startDate) && tgl <= new Date(endDate);
    });

    let totalPurchase = 0, awalKg = 0, hasilKg = 0, wasteKg = 0, selisihKg = 0, kgKw = 0, kgOri = 0;
    const wasteLabels = ['kowol', 'petit', 'sisa', 'karet', 'bahanCina'];

    for (const inv of filtered) {
      totalPurchase += parseFloat(inv.total) || 0;
      if (inv.retulCalculator?.summary) {
        awalKg += inv.retulCalculator.summary.timbanganAwal?.total || 0;
        hasilKg += inv.retulCalculator.summary.hasil?.total || 0;
        for (const label of wasteLabels) {
          wasteKg += inv.retulCalculator.summary[label]?.total || 0;
        }
      }
      for (const verif of inv.itemVerifications || []) {
        selisihKg += verif.selisihKg || 0;
        if (verif.remyGrade === 'KW') kgKw += verif.kgReceived || 0;
        if (verif.remyGrade === 'ORI') kgOri += verif.kgReceived || 0;
      }
    }

    res.json({
      period: { start_date: startDate, end_date: endDate },
      kpi: {
        total_purchase_rp: totalPurchase,
        timbangan_awal_kg: awalKg,
        hasil_kg: hasilKg,
        waste_kg: wasteKg,
        waste_rate_pct: awalKg > 0 ? parseFloat(((wasteKg / awalKg) * 100).toFixed(2)) : 0,
        yield_rate_pct: awalKg > 0 ? parseFloat(((hasilKg / awalKg) * 100).toFixed(2)) : 0,
        selisih_kg: selisihKg,
        kg_kw: kgKw,
        kg_ori: kgOri,
        kw_rate_pct: (kgKw + kgOri) > 0 ? parseFloat(((kgKw / (kgKw + kgOri)) * 100).toFixed(2)) : 0
      }
    });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// GET Profit Trend per day/week
app.get('/api/dashboard/profit-trend', async (req, res) => {
  try {
    const { start_date, end_date, group_by } = req.query;
    const startDate = start_date || new Date(Date.now() - 30*24*60*60*1000).toISOString().split('T')[0];
    const endDate = end_date || new Date().toISOString().split('T')[0];
    const groupBy = group_by === 'week' ? 'YEARWEEK(i.tanggal)' : 'i.tanggal';

    if (db) {
      try {
        const [rows] = await db.execute(`
          SELECT
            ${group_by === 'week' ? 'YEARWEEK(i.tanggal) AS period' : 'i.tanggal AS period'},
            MIN(i.tanggal) AS period_start,
            SUM(i.total) AS purchase_rp,
            SUM(CASE WHEN rs.label = 'hasil' THEN rs.total ELSE 0 END) AS hasil_kg,
            SUM(CASE WHEN rs.label = 'timbanganAwal' THEN rs.total ELSE 0 END) AS awal_kg,
            SUM(CASE WHEN rs.label IN ('kowol','petit','sisa','karet','bahanCina') THEN rs.total ELSE 0 END) AS waste_kg
          FROM invoices i
          LEFT JOIN retul_calculators rc ON rc.no_invoice = i.no_invoice
          LEFT JOIN retul_summary rs ON rs.retul_id = rc.id
          WHERE i.tanggal BETWEEN ? AND ?
            AND i.verification_status = 'VERIFIED'
          GROUP BY ${groupBy}
          ORDER BY period
        `, [startDate, endDate]);

        return res.json(rows.map(r => ({
          ...r,
          waste_rate_pct: r.awal_kg > 0 ? parseFloat(((r.waste_kg / r.awal_kg) * 100).toFixed(2)) : 0,
          yield_rate_pct: r.awal_kg > 0 ? parseFloat(((r.hasil_kg / r.awal_kg) * 100).toFixed(2)) : 0
        })));
      } catch (dbError) {
        console.log('DB profit-trend query failed, using memory:', dbError.message);
      }
    }
    res.json([]);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// GET Waste Composition (stacked bar data)
app.get('/api/dashboard/waste-composition', async (req, res) => {
  try {
    const { start_date, end_date, group_by } = req.query;
    const startDate = start_date || new Date(Date.now() - 30*24*60*60*1000).toISOString().split('T')[0];
    const endDate = end_date || new Date().toISOString().split('T')[0];
    const groupField = group_by === 'petani' ? 'i.petani_name' : 'i.no_invoice';

    if (db) {
      try {
        const [rows] = await db.execute(`
          SELECT
            ${groupField} AS group_key,
            SUM(CASE WHEN rs.label = 'kowol' THEN rs.total ELSE 0 END) AS kowol_kg,
            SUM(CASE WHEN rs.label = 'petit' THEN rs.total ELSE 0 END) AS petit_kg,
            SUM(CASE WHEN rs.label = 'sisa' THEN rs.total ELSE 0 END) AS sisa_kg,
            SUM(CASE WHEN rs.label = 'karet' THEN rs.total ELSE 0 END) AS karet_kg,
            SUM(CASE WHEN rs.label = 'bahanCina' THEN rs.total ELSE 0 END) AS bahan_cina_kg
          FROM invoices i
          JOIN retul_calculators rc ON rc.no_invoice = i.no_invoice
          JOIN retul_summary rs ON rs.retul_id = rc.id
          WHERE i.tanggal BETWEEN ? AND ?
            AND rs.label IN ('kowol','petit','sisa','karet','bahanCina')
          GROUP BY ${groupField}
          ORDER BY (SUM(rs.total)) DESC
          LIMIT 20
        `, [startDate, endDate]);
        return res.json(rows);
      } catch (dbError) {
        console.log('DB waste-composition query failed, using memory:', dbError.message);
      }
    }
    res.json([]);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// GET Selisih Timbangan ranking per subcon/petani
app.get('/api/dashboard/selisih-ranking', async (req, res) => {
  try {
    const { start_date, end_date, group_by } = req.query;
    const startDate = start_date || new Date(Date.now() - 30*24*60*60*1000).toISOString().split('T')[0];
    const endDate = end_date || new Date().toISOString().split('T')[0];
    const groupField = group_by === 'petani' ? 'i.petani_name' : 'i.subcon';

    if (db) {
      try {
        const [rows] = await db.execute(`
          SELECT
            ${groupField} AS group_key,
            SUM(v.selisih_kg) AS selisih_kg,
            SUM(ABS(v.selisih_kg)) AS selisih_abs_kg,
            COUNT(DISTINCT i.no_invoice) AS invoice_count
          FROM invoice_item_verifications v
          JOIN invoices i ON i.no_invoice = v.no_invoice
          WHERE i.tanggal BETWEEN ? AND ?
          GROUP BY ${groupField}
          ORDER BY selisih_abs_kg DESC
          LIMIT 20
        `, [startDate, endDate]);
        return res.json(rows);
      } catch (dbError) {
        console.log('DB selisih-ranking query failed, using memory:', dbError.message);
      }
    }
    res.json([]);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// GET Top Petani by Waste Rate
app.get('/api/dashboard/top-petani-waste', async (req, res) => {
  try {
    const { start_date, end_date, limit } = req.query;
    const startDate = start_date || new Date(Date.now() - 30*24*60*60*1000).toISOString().split('T')[0];
    const endDate = end_date || new Date().toISOString().split('T')[0];
    const limitNum = parseInt(limit) || 10;

    if (db) {
      try {
        const [rows] = await db.execute(`
          SELECT
            i.petani_name,
            SUM(CASE WHEN rs.label = 'timbanganAwal' THEN rs.total ELSE 0 END) AS awal_kg,
            SUM(CASE WHEN rs.label IN ('kowol','petit','sisa','karet','bahanCina') THEN rs.total ELSE 0 END) AS waste_kg,
            (SUM(CASE WHEN rs.label IN ('kowol','petit','sisa','karet','bahanCina') THEN rs.total ELSE 0 END) /
             NULLIF(SUM(CASE WHEN rs.label = 'timbanganAwal' THEN rs.total ELSE 0 END), 0)) * 100 AS waste_rate_pct
          FROM invoices i
          JOIN retul_calculators rc ON rc.no_invoice = i.no_invoice
          JOIN retul_summary rs ON rs.retul_id = rc.id
          WHERE i.tanggal BETWEEN ? AND ?
            AND i.verification_status = 'VERIFIED'
          GROUP BY i.petani_name
          HAVING awal_kg > 0
          ORDER BY waste_rate_pct DESC
          LIMIT ?
        `, [startDate, endDate, limitNum]);
        return res.json(rows);
      } catch (dbError) {
        console.log('DB top-petani-waste query failed, using memory:', dbError.message);
      }
    }
    res.json([]);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// GET Invoice Exceptions (abnormal selisih, waste, KW rate)
app.get('/api/dashboard/invoice-exceptions', async (req, res) => {
  try {
    const { start_date, end_date, selisih_threshold, waste_threshold, kw_threshold } = req.query;
    const startDate = start_date || new Date(Date.now() - 30*24*60*60*1000).toISOString().split('T')[0];
    const endDate = end_date || new Date().toISOString().split('T')[0];
    const selisihLimit = parseFloat(selisih_threshold) || 0.5;  // kg
    const wasteLimit = parseFloat(waste_threshold) || 25;       // %
    const kwLimit = parseFloat(kw_threshold) || 40;             // %

    if (db) {
      try {
        const [rows] = await db.execute(`
          SELECT
            i.no_invoice,
            i.tanggal,
            i.subcon,
            i.petani_name,
            i.total AS purchase_rp,
            COALESCE(SUM(CASE WHEN rs.label = 'timbanganAwal' THEN rs.total ELSE 0 END), 0) AS awal_kg,
            COALESCE(SUM(CASE WHEN rs.label IN ('kowol','petit','sisa','karet','bahanCina') THEN rs.total ELSE 0 END), 0) AS waste_kg,
            COALESCE((SELECT SUM(ABS(v2.selisih_kg)) FROM invoice_item_verifications v2 WHERE v2.no_invoice = i.no_invoice), 0) AS selisih_abs_kg,
            COALESCE((SELECT SUM(CASE WHEN v3.remy_grade = 'KW' THEN v3.kg_received ELSE 0 END) /
              NULLIF(SUM(v3.kg_received), 0) * 100
              FROM invoice_item_verifications v3
              JOIN invoice_items ii3 ON ii3.id = v3.invoice_item_id
              WHERE v3.no_invoice = i.no_invoice AND ii3.kategori = 'REMY'), 0) AS kw_rate_pct
          FROM invoices i
          LEFT JOIN retul_calculators rc ON rc.no_invoice = i.no_invoice
          LEFT JOIN retul_summary rs ON rs.retul_id = rc.id
          WHERE i.tanggal BETWEEN ? AND ?
          GROUP BY i.no_invoice, i.tanggal, i.subcon, i.petani_name, i.total
          HAVING
            selisih_abs_kg > ? OR
            (awal_kg > 0 AND (waste_kg / awal_kg * 100) > ?) OR
            kw_rate_pct > ?
          ORDER BY i.tanggal DESC
          LIMIT 50
        `, [startDate, endDate, selisihLimit, wasteLimit, kwLimit]);

        return res.json(rows.map(r => ({
          ...r,
          waste_rate_pct: r.awal_kg > 0 ? parseFloat(((r.waste_kg / r.awal_kg) * 100).toFixed(2)) : 0,
          exceptions: [
            r.selisih_abs_kg > selisihLimit ? 'SELISIH_TINGGI' : null,
            (r.awal_kg > 0 && (r.waste_kg / r.awal_kg * 100) > wasteLimit) ? 'WASTE_TINGGI' : null,
            r.kw_rate_pct > kwLimit ? 'KW_TINGGI' : null
          ].filter(Boolean)
        })));
      } catch (dbError) {
        console.log('DB invoice-exceptions query failed, using memory:', dbError.message);
      }
    }
    res.json([]);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// ============ HPP CALCULATOR ROUTES ============

// GET HPP per invoice (detailed breakdown)
app.get('/api/hpp/invoice/:noInvoice', async (req, res) => {
  try {
    const noInvoice = req.params.noInvoice;

    if (db) {
      try {
        // Get invoice data
        const [invoiceRows] = await db.execute(`
          SELECT i.*, rc.id as retul_id
          FROM invoices i
          LEFT JOIN retul_calculators rc ON rc.no_invoice = i.no_invoice
          WHERE i.no_invoice = ?
        `, [noInvoice]);

        if (invoiceRows.length === 0) {
          return res.status(404).json({ error: 'Invoice not found' });
        }

        const invoice = invoiceRows[0];

        // Get retul summary
        const [summaryRows] = await db.execute(`
          SELECT label, hitam, uban, total
          FROM retul_summary
          WHERE retul_id = ?
        `, [invoice.retul_id]);

        // Get retul rows (per size)
        const [retulRows] = await db.execute(`
          SELECT size_inch, kg_1, kg_2, kg_3, kg_4, total_hitam, lus_uban
          FROM retul_rows
          WHERE retul_id = ?
          ORDER BY id
        `, [invoice.retul_id]);

        // Get KW/ORI breakdown
        const [gradeRows] = await db.execute(`
          SELECT
            v.remy_grade,
            SUM(v.kg_received) AS kg
          FROM invoice_item_verifications v
          JOIN invoice_items ii ON ii.id = v.invoice_item_id
          WHERE v.no_invoice = ? AND ii.kategori = 'REMY'
          GROUP BY v.remy_grade
        `, [noInvoice]);

        // Build summary object
        const summary = {};
        for (const s of summaryRows) {
          summary[s.label] = { hitam: parseFloat(s.hitam), uban: parseFloat(s.uban), total: parseFloat(s.total) };
        }

        const purchaseRp = parseFloat(invoice.total) || 0;
        const awalKg = summary.timbanganAwal?.total || 0;
        const hasilKg = summary.hasil?.total || 0;
        const wasteLabels = ['kowol', 'petit', 'sisa', 'karet', 'bahanCina'];
        const wasteKg = wasteLabels.reduce((sum, label) => sum + (summary[label]?.total || 0), 0);
        const lossKg = Math.max(0, awalKg - (hasilKg + wasteKg));

        // HPP per KG Hasil
        const hppPerKgHasil = hasilKg > 0 ? purchaseRp / hasilKg : 0;

        // HPP per size
        const hppPerSize = retulRows.map(row => {
          const totalSize = parseFloat(row.total_hitam) + parseFloat(row.lus_uban);
          return {
            size_inch: row.size_inch,
            kg_hitam: parseFloat(row.total_hitam),
            kg_uban: parseFloat(row.lus_uban),
            kg_total: totalSize,
            hpp_size: totalSize * hppPerKgHasil
          };
        });

        // KW/ORI breakdown
        const kgKw = gradeRows.find(r => r.remy_grade === 'KW')?.kg || 0;
        const kgOri = gradeRows.find(r => r.remy_grade === 'ORI')?.kg || 0;

        // Weighted HPP for KW vs ORI (coefficient: ORI=1.0, KW=0.7)
        const coeffOri = 1.0, coeffKw = 0.7;
        const weightTotal = (parseFloat(kgOri) * coeffOri) + (parseFloat(kgKw) * coeffKw);
        const biayaOri = weightTotal > 0 ? purchaseRp * (parseFloat(kgOri) * coeffOri / weightTotal) : 0;
        const biayaKw = weightTotal > 0 ? purchaseRp * (parseFloat(kgKw) * coeffKw / weightTotal) : 0;
        const hppPerKgOri = parseFloat(kgOri) > 0 ? biayaOri / parseFloat(kgOri) : 0;
        const hppPerKgKw = parseFloat(kgKw) > 0 ? biayaKw / parseFloat(kgKw) : 0;

        return res.json({
          no_invoice: noInvoice,
          tanggal: invoice.tanggal,
          subcon: invoice.subcon,
          petani_name: invoice.petani_name,
          metrics: {
            purchase_rp: purchaseRp,
            awal_kg: awalKg,
            hasil_kg: hasilKg,
            waste_kg: wasteKg,
            loss_kg: lossKg,
            waste_rate_pct: awalKg > 0 ? parseFloat(((wasteKg / awalKg) * 100).toFixed(2)) : 0,
            yield_rate_pct: awalKg > 0 ? parseFloat(((hasilKg / awalKg) * 100).toFixed(2)) : 0
          },
          hpp: {
            hpp_per_kg_hasil: parseFloat(hppPerKgHasil.toFixed(2)),
            hpp_per_size: hppPerSize.map(s => ({
              ...s,
              hpp_size: parseFloat(s.hpp_size.toFixed(2))
            }))
          },
          grade_breakdown: {
            kg_ori: parseFloat(kgOri),
            kg_kw: parseFloat(kgKw),
            hpp_per_kg_ori: parseFloat(hppPerKgOri.toFixed(2)),
            hpp_per_kg_kw: parseFloat(hppPerKgKw.toFixed(2)),
            coefficient: { ori: coeffOri, kw: coeffKw }
          },
          summary
        });
      } catch (dbError) {
        console.log('DB hpp query failed:', dbError.message);
        return res.status(500).json({ error: dbError.message });
      }
    }

    // Memory fallback
    const inv = memoryInvoices.find(i => i.no_invoice === noInvoice);
    if (!inv) return res.status(404).json({ error: 'Invoice not found' });

    const purchaseRp = parseFloat(inv.total) || 0;
    const hasilKg = inv.retulCalculator?.summary?.hasil?.total || 0;
    const hppPerKgHasil = hasilKg > 0 ? purchaseRp / hasilKg : 0;

    res.json({
      no_invoice: noInvoice,
      metrics: { purchase_rp: purchaseRp, hasil_kg: hasilKg },
      hpp: { hpp_per_kg_hasil: parseFloat(hppPerKgHasil.toFixed(2)) }
    });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// GET HPP Summary (aggregate)
app.get('/api/hpp/summary', async (req, res) => {
  try {
    const { start_date, end_date, group_by } = req.query;
    const startDate = start_date || new Date(Date.now() - 30*24*60*60*1000).toISOString().split('T')[0];
    const endDate = end_date || new Date().toISOString().split('T')[0];
    const groupField = group_by === 'petani' ? 'i.petani_name' : (group_by === 'subcon' ? 'i.subcon' : 'i.wilayah');

    if (db) {
      try {
        const [rows] = await db.execute(`
          SELECT
            ${groupField} AS group_key,
            COUNT(DISTINCT i.no_invoice) AS invoice_count,
            SUM(i.total) AS total_purchase_rp,
            SUM(CASE WHEN rs.label = 'hasil' THEN rs.total ELSE 0 END) AS total_hasil_kg,
            SUM(CASE WHEN rs.label = 'timbanganAwal' THEN rs.total ELSE 0 END) AS total_awal_kg,
            SUM(CASE WHEN rs.label IN ('kowol','petit','sisa','karet','bahanCina') THEN rs.total ELSE 0 END) AS total_waste_kg
          FROM invoices i
          JOIN retul_calculators rc ON rc.no_invoice = i.no_invoice
          JOIN retul_summary rs ON rs.retul_id = rc.id
          WHERE i.tanggal BETWEEN ? AND ?
            AND i.verification_status = 'VERIFIED'
          GROUP BY ${groupField}
          ORDER BY total_purchase_rp DESC
        `, [startDate, endDate]);

        return res.json(rows.map(r => ({
          ...r,
          avg_hpp_per_kg: r.total_hasil_kg > 0 ? parseFloat((r.total_purchase_rp / r.total_hasil_kg).toFixed(2)) : 0,
          waste_rate_pct: r.total_awal_kg > 0 ? parseFloat(((r.total_waste_kg / r.total_awal_kg) * 100).toFixed(2)) : 0,
          yield_rate_pct: r.total_awal_kg > 0 ? parseFloat(((r.total_hasil_kg / r.total_awal_kg) * 100).toFixed(2)) : 0
        })));
      } catch (dbError) {
        console.log('DB hpp-summary query failed, using memory:', dbError.message);
      }
    }
    res.json([]);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// ============ PRICE INTERNAL MASTER ROUTES ============

// GET all price internal
app.get('/api/master/price-internal', async (req, res) => {
  try {
    if (db) {
      try {
        const [rows] = await db.execute('SELECT * FROM price_internal ORDER BY kategori, grade, size_inch');
        return res.json(rows);
      } catch (dbError) {
        console.log('DB price-internal query failed:', dbError.message);
      }
    }
    res.json([]);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// POST create/update price internal
app.post('/api/master/price-internal', async (req, res) => {
  try {
    const { kategori, grade, size_inch, harga_per_kg, keterangan } = req.body;

    if (db) {
      try {
        const [existing] = await db.execute(
          'SELECT id FROM price_internal WHERE kategori = ? AND grade = ? AND size_inch = ?',
          [kategori, grade || null, size_inch || null]
        );

        if (existing.length > 0) {
          await db.execute(
            'UPDATE price_internal SET harga_per_kg = ?, keterangan = ? WHERE id = ?',
            [harga_per_kg, keterangan || null, existing[0].id]
          );
          return res.json({ success: true, id: existing[0].id, action: 'updated' });
        } else {
          const [result] = await db.execute(
            'INSERT INTO price_internal (kategori, grade, size_inch, harga_per_kg, keterangan) VALUES (?, ?, ?, ?, ?)',
            [kategori, grade || null, size_inch || null, harga_per_kg, keterangan || null]
          );
          return res.json({ success: true, id: result.insertId, action: 'created' });
        }
      } catch (dbError) {
        return res.status(500).json({ error: dbError.message });
      }
    }
    res.status(500).json({ error: 'Database not available' });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// ============ MASTER PIC RETUL ROUTES (ERD v3) ============

// In-memory fallback for PIC master
let memoryPicsMaster = [
  { id: 'PICR-001', name: 'LEHAN', active: true },
  { id: 'PICR-002', name: 'MUN', active: true },
  { id: 'PICR-003', name: 'RIGEN', active: true },
  { id: 'PICR-004', name: 'PAKDE', active: true }
];

// GET all PIC Retul master
app.get('/api/master/retul-pics', async (req, res) => {
  try {
    const activeOnly = req.query.active === 'true';

    if (db) {
      try {
        let query = 'SELECT * FROM retul_pics_master';
        if (activeOnly) query += ' WHERE active = TRUE';
        query += ' ORDER BY name';
        const [rows] = await db.execute(query);
        return res.json(rows);
      } catch (dbError) {
        console.log('DB retul-pics query failed, using memory:', dbError.message);
      }
    }
    // Memory fallback
    let result = memoryPicsMaster;
    if (activeOnly) result = result.filter(p => p.active);
    res.json(result);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// GET single PIC by ID
app.get('/api/master/retul-pics/:id', async (req, res) => {
  try {
    if (db) {
      try {
        const [rows] = await db.execute(
          'SELECT * FROM retul_pics_master WHERE id = ?',
          [req.params.id]
        );
        if (rows.length === 0) {
          return res.status(404).json({ error: 'PIC not found' });
        }
        return res.json(rows[0]);
      } catch (dbError) {
        console.log('DB retul-pics query failed:', dbError.message);
      }
    }
    // Memory fallback
    const pic = memoryPicsMaster.find(p => p.id === req.params.id);
    if (!pic) return res.status(404).json({ error: 'PIC not found' });
    res.json(pic);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// POST create new PIC Retul
app.post('/api/master/retul-pics', async (req, res) => {
  try {
    const { name } = req.body;
    if (!name) return res.status(400).json({ error: 'Name is required' });

    // Generate new ID
    const newId = `PICR-${String(Date.now()).slice(-6)}`;

    if (db) {
      try {
        await db.execute(
          'INSERT INTO retul_pics_master (id, name, active) VALUES (?, ?, TRUE)',
          [newId, name]
        );
        return res.json({ success: true, id: newId, name, active: true });
      } catch (dbError) {
        if (dbError.code === 'ER_DUP_ENTRY') {
          return res.status(400).json({ error: 'PIC with this ID already exists' });
        }
        console.log('DB retul-pics insert failed:', dbError.message);
      }
    }
    // Memory fallback
    const newPic = { id: newId, name, active: true };
    memoryPicsMaster.push(newPic);
    res.json({ success: true, ...newPic, storage: 'memory' });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// PUT update PIC Retul
app.put('/api/master/retul-pics/:id', async (req, res) => {
  try {
    const { name, active } = req.body;
    const picId = req.params.id;

    if (db) {
      try {
        const updates = [];
        const params = [];
        if (name !== undefined) { updates.push('name = ?'); params.push(name); }
        if (active !== undefined) { updates.push('active = ?'); params.push(active); }

        if (updates.length === 0) {
          return res.status(400).json({ error: 'No fields to update' });
        }

        params.push(picId);
        await db.execute(
          `UPDATE retul_pics_master SET ${updates.join(', ')} WHERE id = ?`,
          params
        );
        return res.json({ success: true, id: picId });
      } catch (dbError) {
        console.log('DB retul-pics update failed:', dbError.message);
      }
    }
    // Memory fallback
    const pic = memoryPicsMaster.find(p => p.id === picId);
    if (!pic) return res.status(404).json({ error: 'PIC not found' });
    if (name !== undefined) pic.name = name;
    if (active !== undefined) pic.active = active;
    res.json({ success: true, ...pic, storage: 'memory' });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// DELETE (soft delete) PIC Retul
app.delete('/api/master/retul-pics/:id', async (req, res) => {
  try {
    const picId = req.params.id;

    if (db) {
      try {
        // Soft delete - set active = false
        await db.execute(
          'UPDATE retul_pics_master SET active = FALSE WHERE id = ?',
          [picId]
        );
        return res.json({ success: true, id: picId, action: 'deactivated' });
      } catch (dbError) {
        console.log('DB retul-pics delete failed:', dbError.message);
      }
    }
    // Memory fallback
    const pic = memoryPicsMaster.find(p => p.id === picId);
    if (!pic) return res.status(404).json({ error: 'PIC not found' });
    pic.active = false;
    res.json({ success: true, id: picId, action: 'deactivated', storage: 'memory' });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// ============ RETUL CALCULATOR ROUTES ============

// POST save retul calculator data (UPDATED for ERD v3 - PIC dinamis)
app.post('/api/invoices/:noInvoice/retul', async (req, res) => {
  try {
    const { rows, summary, verified_by, selected_pics } = req.body;
    const noInvoice = req.params.noInvoice;

    if (db) {
      try {
        // Check if retul exists
        const [existing] = await db.execute(
          'SELECT id FROM retul_calculators WHERE no_invoice = ?', [noInvoice]
        );

        let retulId;
        if (existing.length > 0) {
          retulId = existing[0].id;
          // Update existing
          await db.execute(
            'UPDATE retul_calculators SET verified_by = ?, verified_at = NOW() WHERE id = ?',
            [verified_by, retulId]
          );
          // Delete old rows, summary, and pics
          await db.execute('DELETE FROM retul_rows WHERE retul_id = ?', [retulId]);
          await db.execute('DELETE FROM retul_summary WHERE retul_id = ?', [retulId]);
          await db.execute('DELETE FROM retul_calculator_pics WHERE retul_id = ?', [retulId]);
        } else {
          // Insert new
          const [result] = await db.execute(
            'INSERT INTO retul_calculators (no_invoice, verified_by, verified_at) VALUES (?, ?, NOW())',
            [noInvoice, verified_by]
          );
          retulId = result.insertId;
        }

        // Insert selected PICs (ERD v3)
        for (const picId of selected_pics || []) {
          try {
            await db.execute(
              'INSERT INTO retul_calculator_pics (retul_id, retul_pic_id) VALUES (?, ?)',
              [retulId, picId]
            );
          } catch (picErr) {
            // Ignore duplicate errors
          }
        }

        // Insert rows with hitam_by_pic JSON (ERD v3)
        for (const row of rows || []) {
          // Calculate totalHitam from hitam_by_pic or legacy kg1-kg4
          let totalHitam = 0;
          const hitamByPic = row.hitam_by_pic || {};

          if (Object.keys(hitamByPic).length > 0) {
            // New format - sum from hitam_by_pic
            totalHitam = Object.values(hitamByPic).reduce((sum, val) => sum + (parseFloat(val) || 0), 0);
          } else {
            // Legacy format - use kg1-kg4
            totalHitam = (row.kg1 || 0) + (row.kg2 || 0) + (row.kg3 || 0) + (row.kg4 || 0);
          }

          await db.execute(
            `INSERT INTO retul_rows (retul_id, size_inch, kg_1, kg_2, kg_3, kg_4, hitam_by_pic, total_hitam, lus_uban)
             VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
            [retulId, row.size, row.kg1 || 0, row.kg2 || 0, row.kg3 || 0, row.kg4 || 0,
             JSON.stringify(hitamByPic), totalHitam, row.lusUban || 0]
          );
        }

        // Insert summary
        const summaryLabels = ['timbanganAwal', 'hasil', 'kowol', 'petit', 'sisa', 'karet', 'bahanCina'];
        for (const label of summaryLabels) {
          const data = summary[label] || { hitam: 0, uban: 0, total: 0 };
          await db.execute(
            'INSERT INTO retul_summary (retul_id, label, hitam, uban, total) VALUES (?, ?, ?, ?, ?)',
            [retulId, label, data.hitam || 0, data.uban || 0, data.total || 0]
          );
        }

        return res.json({ success: true, retulId, selected_pics: selected_pics || [] });
      } catch (dbError) {
        console.log('DB retul save failed:', dbError.message);
      }
    }

    // Memory fallback
    const inv = memoryInvoices.find(i => i.no_invoice === noInvoice);
    if (inv) {
      inv.retulCalculator = {
        rows,
        summary,
        verified_by,
        verified_at: new Date().toISOString(),
        selected_pics: selected_pics || []
      };
    }
    res.json({ success: true, storage: 'memory', selected_pics: selected_pics || [] });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// GET retul calculator data
app.get('/api/invoices/:noInvoice/retul', async (req, res) => {
  try {
    if (db) {
      const [retul] = await db.execute(
        'SELECT * FROM retul_calculators WHERE no_invoice = ?', [req.params.noInvoice]
      );
      if (retul.length === 0) {
        return res.json(null);
      }
      const [rows] = await db.execute(
        'SELECT * FROM retul_rows WHERE retul_id = ? ORDER BY id', [retul[0].id]
      );
      const [summary] = await db.execute(
        'SELECT * FROM retul_summary WHERE retul_id = ?', [retul[0].id]
      );

      // Get selected PICs for this retul (ERD v3)
      const [selectedPics] = await db.execute(
        `SELECT rp.id, rp.name FROM retul_calculator_pics rcp
         JOIN retul_pics_master rp ON rp.id = rcp.retul_pic_id
         WHERE rcp.retul_id = ? ORDER BY rp.name`,
        [retul[0].id]
      );

      // Convert summary array to object
      const summaryObj = {};
      for (const s of summary) {
        summaryObj[s.label] = { hitam: s.hitam, uban: s.uban, total: s.total };
      }

      // Parse hitam_by_pic JSON and ensure backward compatibility
      const parsedRows = rows.map(row => {
        let hitamByPic = {};
        if (row.hitam_by_pic) {
          try {
            hitamByPic = typeof row.hitam_by_pic === 'string'
              ? JSON.parse(row.hitam_by_pic)
              : row.hitam_by_pic;
          } catch (e) {
            hitamByPic = {};
          }
        }
        // Backward compatibility: if hitam_by_pic empty, use legacy kg_1-kg_4
        if (Object.keys(hitamByPic).length === 0 && (row.kg_1 || row.kg_2 || row.kg_3 || row.kg_4)) {
          hitamByPic = {
            'LEHAN': row.kg_1 || 0,
            'MUN': row.kg_2 || 0,
            'RIGEN': row.kg_3 || 0,
            'PAKDE': row.kg_4 || 0
          };
        }
        return { ...row, hitam_by_pic: hitamByPic };
      });

      return res.json({
        ...retul[0],
        rows: parsedRows,
        summary: summaryObj,
        selected_pics: selectedPics.length > 0 ? selectedPics : [
          { id: 'LEHAN', name: 'LEHAN' },
          { id: 'MUN', name: 'MUN' },
          { id: 'RIGEN', name: 'RIGEN' },
          { id: 'PAKDE', name: 'PAKDE' }
        ]
      });
    }
    const inv = memoryInvoices.find(i => i.no_invoice === req.params.noInvoice);
    res.json(inv?.retulCalculator || null);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// ============ RETUL AUDIT ROUTES (Query per PIC per Ukuran) ============

// GET Audit retul per invoice: "PIC mana isi berapa kg di ukuran berapa"
app.get('/api/audit/retul/:noInvoice/detail', async (req, res) => {
  try {
    const noInvoice = req.params.noInvoice;

    if (db) {
      try {
        // Get retul data with PIC breakdown per size
        const [rows] = await db.execute(`
          SELECT
            rc.no_invoice,
            rr.size_inch,
            rr.hitam_by_pic,
            rr.kg_1, rr.kg_2, rr.kg_3, rr.kg_4,
            rr.total_hitam,
            rr.lus_uban,
            rr.migrated
          FROM retul_calculators rc
          JOIN retul_rows rr ON rr.retul_id = rc.id
          WHERE rc.no_invoice = ?
          ORDER BY
            CASE WHEN rr.size_inch = 'UP' THEN 999
                 ELSE CAST(REPLACE(rr.size_inch, '"', '') AS UNSIGNED) END
        `, [noInvoice]);

        // Get legacy column mapping
        const [legacyMap] = await db.execute(
          'SELECT legacy_col, retul_pic_id FROM retul_legacy_col_map'
        );
        const mapObj = {};
        for (const m of legacyMap) {
          mapObj[m.legacy_col] = m.retul_pic_id;
        }

        // Get PIC master names
        const [picMaster] = await db.execute(
          'SELECT id, name FROM retul_pics_master WHERE active = TRUE'
        );
        const picNames = {};
        for (const p of picMaster) {
          picNames[p.id] = p.name;
        }

        // Transform rows to include PIC breakdown
        const result = rows.map(row => {
          let picBreakdown = {};

          // Try to parse hitam_by_pic JSON
          if (row.hitam_by_pic) {
            try {
              picBreakdown = typeof row.hitam_by_pic === 'string'
                ? JSON.parse(row.hitam_by_pic)
                : row.hitam_by_pic;
            } catch (e) {
              picBreakdown = {};
            }
          }

          // Fallback to legacy kg_1-kg_4 if hitam_by_pic is empty
          if (Object.keys(picBreakdown).length === 0) {
            if (row.kg_1) picBreakdown[mapObj['kg_1'] || 'kg_1'] = parseFloat(row.kg_1);
            if (row.kg_2) picBreakdown[mapObj['kg_2'] || 'kg_2'] = parseFloat(row.kg_2);
            if (row.kg_3) picBreakdown[mapObj['kg_3'] || 'kg_3'] = parseFloat(row.kg_3);
            if (row.kg_4) picBreakdown[mapObj['kg_4'] || 'kg_4'] = parseFloat(row.kg_4);
          }

          // Convert PIC IDs to names
          const picBreakdownNamed = {};
          for (const [picId, kg] of Object.entries(picBreakdown)) {
            const name = picNames[picId] || picId;
            picBreakdownNamed[name] = kg;
          }

          return {
            no_invoice: row.no_invoice,
            size_inch: row.size_inch,
            pic_breakdown: picBreakdownNamed,
            total_hitam: parseFloat(row.total_hitam),
            lus_uban: parseFloat(row.lus_uban),
            migrated: row.migrated === 1
          };
        });

        return res.json({
          no_invoice: noInvoice,
          rows: result,
          pic_list: Object.values(picNames)
        });
      } catch (dbError) {
        console.log('DB audit query failed:', dbError.message);
        return res.status(500).json({ error: dbError.message });
      }
    }
    res.json({ no_invoice: noInvoice, rows: [], pic_list: [] });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// GET Audit ringkas: "Total KG per PIC untuk 1 invoice"
app.get('/api/audit/retul/:noInvoice/summary', async (req, res) => {
  try {
    const noInvoice = req.params.noInvoice;

    if (db) {
      try {
        const [rows] = await db.execute(`
          SELECT rr.hitam_by_pic, rr.kg_1, rr.kg_2, rr.kg_3, rr.kg_4
          FROM retul_calculators rc
          JOIN retul_rows rr ON rr.retul_id = rc.id
          WHERE rc.no_invoice = ?
        `, [noInvoice]);

        // Get legacy mapping and PIC names
        const [legacyMap] = await db.execute('SELECT legacy_col, retul_pic_id FROM retul_legacy_col_map');
        const mapObj = {};
        for (const m of legacyMap) mapObj[m.legacy_col] = m.retul_pic_id;

        const [picMaster] = await db.execute('SELECT id, name FROM retul_pics_master WHERE active = TRUE');
        const picNames = {};
        for (const p of picMaster) picNames[p.id] = p.name;

        // Aggregate per PIC
        const totals = {};
        for (const row of rows) {
          let picData = {};
          if (row.hitam_by_pic) {
            try {
              picData = typeof row.hitam_by_pic === 'string' ? JSON.parse(row.hitam_by_pic) : row.hitam_by_pic;
            } catch (e) { picData = {}; }
          }
          if (Object.keys(picData).length === 0) {
            if (row.kg_1) picData[mapObj['kg_1'] || 'kg_1'] = parseFloat(row.kg_1);
            if (row.kg_2) picData[mapObj['kg_2'] || 'kg_2'] = parseFloat(row.kg_2);
            if (row.kg_3) picData[mapObj['kg_3'] || 'kg_3'] = parseFloat(row.kg_3);
            if (row.kg_4) picData[mapObj['kg_4'] || 'kg_4'] = parseFloat(row.kg_4);
          }
          for (const [picId, kg] of Object.entries(picData)) {
            const name = picNames[picId] || picId;
            totals[name] = (totals[name] || 0) + (parseFloat(kg) || 0);
          }
        }

        const result = Object.entries(totals)
          .map(([pic_name, total_kg]) => ({ pic_name, total_kg: parseFloat(total_kg.toFixed(3)) }))
          .sort((a, b) => b.total_kg - a.total_kg);

        return res.json({ no_invoice: noInvoice, pic_totals: result });
      } catch (dbError) {
        return res.status(500).json({ error: dbError.message });
      }
    }
    res.json({ no_invoice: noInvoice, pic_totals: [] });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// GET Audit periode: "Top PIC retul berdasarkan total KG (date range)"
app.get('/api/audit/retul/period', async (req, res) => {
  try {
    const { start_date, end_date, limit } = req.query;
    const startDate = start_date || new Date(Date.now() - 30*24*60*60*1000).toISOString().split('T')[0];
    const endDate = end_date || new Date().toISOString().split('T')[0];
    const limitNum = parseInt(limit) || 10;

    if (db) {
      try {
        const [rows] = await db.execute(`
          SELECT rr.hitam_by_pic, rr.kg_1, rr.kg_2, rr.kg_3, rr.kg_4
          FROM invoices i
          JOIN retul_calculators rc ON rc.no_invoice = i.no_invoice
          JOIN retul_rows rr ON rr.retul_id = rc.id
          WHERE i.tanggal BETWEEN ? AND ?
        `, [startDate, endDate]);

        // Get legacy mapping and PIC names
        const [legacyMap] = await db.execute('SELECT legacy_col, retul_pic_id FROM retul_legacy_col_map');
        const mapObj = {};
        for (const m of legacyMap) mapObj[m.legacy_col] = m.retul_pic_id;

        const [picMaster] = await db.execute('SELECT id, name FROM retul_pics_master WHERE active = TRUE');
        const picNames = {};
        for (const p of picMaster) picNames[p.id] = p.name;

        // Aggregate per PIC
        const totals = {};
        for (const row of rows) {
          let picData = {};
          if (row.hitam_by_pic) {
            try {
              picData = typeof row.hitam_by_pic === 'string' ? JSON.parse(row.hitam_by_pic) : row.hitam_by_pic;
            } catch (e) { picData = {}; }
          }
          if (Object.keys(picData).length === 0) {
            if (row.kg_1) picData[mapObj['kg_1'] || 'kg_1'] = parseFloat(row.kg_1);
            if (row.kg_2) picData[mapObj['kg_2'] || 'kg_2'] = parseFloat(row.kg_2);
            if (row.kg_3) picData[mapObj['kg_3'] || 'kg_3'] = parseFloat(row.kg_3);
            if (row.kg_4) picData[mapObj['kg_4'] || 'kg_4'] = parseFloat(row.kg_4);
          }
          for (const [picId, kg] of Object.entries(picData)) {
            const name = picNames[picId] || picId;
            totals[name] = (totals[name] || 0) + (parseFloat(kg) || 0);
          }
        }

        const result = Object.entries(totals)
          .map(([pic_name, total_kg]) => ({ pic_name, total_kg: parseFloat(total_kg.toFixed(3)) }))
          .sort((a, b) => b.total_kg - a.total_kg)
          .slice(0, limitNum);

        return res.json({
          period: { start_date: startDate, end_date: endDate },
          top_pics: result
        });
      } catch (dbError) {
        return res.status(500).json({ error: dbError.message });
      }
    }
    res.json({ period: { start_date: startDate, end_date: endDate }, top_pics: [] });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// ============ MIGRATION ROUTES (kg_1-kg_4 → hitam_by_pic) ============

// GET Migration status
app.get('/api/migration/retul/status', async (req, res) => {
  try {
    if (db) {
      try {
        const [total] = await db.execute('SELECT COUNT(*) as count FROM retul_rows');
        const [migrated] = await db.execute('SELECT COUNT(*) as count FROM retul_rows WHERE migrated = 1');
        const [pending] = await db.execute('SELECT COUNT(*) as count FROM retul_rows WHERE migrated = 0');

        return res.json({
          total_rows: total[0].count,
          migrated_rows: migrated[0].count,
          pending_rows: pending[0].count,
          progress_pct: total[0].count > 0
            ? parseFloat(((migrated[0].count / total[0].count) * 100).toFixed(2))
            : 100
        });
      } catch (dbError) {
        return res.status(500).json({ error: dbError.message });
      }
    }
    res.json({ total_rows: 0, migrated_rows: 0, pending_rows: 0, progress_pct: 100 });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// POST Run migration batch (kg_1-kg_4 → hitam_by_pic)
app.post('/api/migration/retul/run', async (req, res) => {
  try {
    const { batch_size } = req.body;
    const batchSize = parseInt(batch_size) || 100;

    if (db) {
      try {
        // Get legacy mapping
        const [legacyMap] = await db.execute('SELECT legacy_col, retul_pic_id FROM retul_legacy_col_map');
        const mapObj = {};
        for (const m of legacyMap) mapObj[m.legacy_col] = m.retul_pic_id;

        // Get pending rows
        const [pendingRows] = await db.execute(
          'SELECT id, kg_1, kg_2, kg_3, kg_4, total_hitam FROM retul_rows WHERE migrated = 0 LIMIT ?',
          [batchSize]
        );

        if (pendingRows.length === 0) {
          return res.json({ success: true, message: 'No pending rows to migrate', migrated_count: 0 });
        }

        let migratedCount = 0;
        for (const row of pendingRows) {
          // Build hitam_by_pic JSON from kg_1-kg_4
          const hitamByPic = {};
          if (row.kg_1 && parseFloat(row.kg_1) > 0) hitamByPic[mapObj['kg_1']] = parseFloat(row.kg_1);
          if (row.kg_2 && parseFloat(row.kg_2) > 0) hitamByPic[mapObj['kg_2']] = parseFloat(row.kg_2);
          if (row.kg_3 && parseFloat(row.kg_3) > 0) hitamByPic[mapObj['kg_3']] = parseFloat(row.kg_3);
          if (row.kg_4 && parseFloat(row.kg_4) > 0) hitamByPic[mapObj['kg_4']] = parseFloat(row.kg_4);

          // Calculate total from JSON
          const totalHitam = Object.values(hitamByPic).reduce((sum, v) => sum + v, 0);

          // Update row
          await db.execute(
            'UPDATE retul_rows SET hitam_by_pic = ?, total_hitam = ?, migrated = 1 WHERE id = ?',
            [JSON.stringify(hitamByPic), totalHitam, row.id]
          );
          migratedCount++;
        }

        // Get updated status
        const [total] = await db.execute('SELECT COUNT(*) as count FROM retul_rows');
        const [migrated] = await db.execute('SELECT COUNT(*) as count FROM retul_rows WHERE migrated = 1');

        return res.json({
          success: true,
          migrated_count: migratedCount,
          total_migrated: migrated[0].count,
          total_rows: total[0].count,
          progress_pct: parseFloat(((migrated[0].count / total[0].count) * 100).toFixed(2))
        });
      } catch (dbError) {
        return res.status(500).json({ error: dbError.message });
      }
    }
    res.json({ success: false, error: 'Database not available' });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// GET Legacy column mapping
app.get('/api/migration/retul/mapping', async (req, res) => {
  try {
    if (db) {
      const [rows] = await db.execute(`
        SELECT lcm.legacy_col, lcm.retul_pic_id, rpm.name as pic_name
        FROM retul_legacy_col_map lcm
        LEFT JOIN retul_pics_master rpm ON rpm.id = lcm.retul_pic_id
        ORDER BY lcm.legacy_col
      `);
      return res.json(rows);
    }
    res.json([]);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// PUT Update legacy column mapping
app.put('/api/migration/retul/mapping/:legacyCol', async (req, res) => {
  try {
    const { retul_pic_id } = req.body;
    const legacyCol = req.params.legacyCol;

    if (db) {
      try {
        await db.execute(
          'UPDATE retul_legacy_col_map SET retul_pic_id = ? WHERE legacy_col = ?',
          [retul_pic_id, legacyCol]
        );
        return res.json({ success: true, legacy_col: legacyCol, retul_pic_id });
      } catch (dbError) {
        return res.status(500).json({ error: dbError.message });
      }
    }
    res.status(500).json({ error: 'Database not available' });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// ============ DEPOSIT ROUTES ============

app.get('/api/deposits', async (req, res) => {
  try {
    if (!db) return res.json([]);
    const [rows] = await db.execute(
      'SELECT * FROM deposits ORDER BY created_at DESC'
    );
    res.json(rows);
  } catch (error) {
    res.json([]);
  }
});

app.get('/api/deposits/summary', async (req, res) => {
  try {
    if (!db) return res.json([]);
    const [rows] = await db.execute(`
      SELECT wilayah, pic, SUM(jumlah) as total
      FROM deposits
      WHERE status = 'AKTIF'
      GROUP BY wilayah, pic
    `);
    res.json(rows);
  } catch (error) {
    res.json([]);
  }
});

app.post('/api/deposits', async (req, res) => {
  try {
    const { no_deposit, tanggal, pic, subcon, wilayah, jumlah } = req.body;

    const [result] = await db.execute(
      'INSERT INTO deposits (no_deposit, tanggal, pic, subcon, wilayah, jumlah) VALUES (?, ?, ?, ?, ?, ?)',
      [no_deposit, tanggal, pic, subcon, wilayah, jumlah]
    );

    res.json({ success: true, id: result.insertId });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

app.delete('/api/deposits/:id', async (req, res) => {
  try {
    await db.execute('DELETE FROM deposits WHERE id = ?', [req.params.id]);
    res.json({ success: true });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// ============ SUBCON ROUTES ============

app.get('/api/subcons', async (req, res) => {
  try {
    const [rows] = await db.execute('SELECT * FROM subcons ORDER BY wilayah, nama');
    res.json(rows);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

app.post('/api/subcons', async (req, res) => {
  try {
    const { nama, wilayah, pic, status } = req.body;
    const [result] = await db.execute(
      'INSERT INTO subcons (nama, wilayah, pic, status) VALUES (?, ?, ?, ?)',
      [nama, wilayah, pic, status || 'LOCKED']
    );
    res.json({ success: true, id: result.insertId });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// ============ MASTER DATA ROUTES ============

app.get('/api/wilayah', async (req, res) => {
  try {
    const [rows] = await db.execute('SELECT * FROM wilayah');
    res.json(rows);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

app.get('/api/barang', async (req, res) => {
  try {
    const [rows] = await db.execute('SELECT * FROM barang ORDER BY kategori');
    res.json(rows);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// ============ DASHBOARD STATS ============

app.get('/api/stats', async (req, res) => {
  try {
    const currentMonth = new Date().toISOString().slice(0, 7);

    // Calculate memory stats
    const memoryStats = {
      totalPembelian: memoryInvoices
        .filter(inv => inv.tanggal && inv.tanggal.startsWith(currentMonth))
        .reduce((sum, inv) => sum + (inv.total || 0), 0),
      totalInvoice: memoryInvoices.length,
      totalDeposit: memoryDeposits
        .filter(dep => dep.status === 'AKTIF')
        .reduce((sum, dep) => sum + (dep.jumlah || 0), 0),
      subconAktif: 7 // Default subcon count
    };

    // Try database
    if (db) {
      try {
        const [totalPembelian] = await db.execute(
          `SELECT COALESCE(SUM(total), 0) as total FROM invoices WHERE DATE_FORMAT(tanggal, '%Y-%m') = ?`,
          [currentMonth]
        );

        const [totalInvoice] = await db.execute(
          'SELECT COUNT(*) as count FROM invoices'
        );

        const [totalDeposit] = await db.execute(
          `SELECT COALESCE(SUM(jumlah), 0) as total FROM deposits WHERE status = 'AKTIF'`
        );

        const [subconAktif] = await db.execute(
          'SELECT COUNT(*) as count FROM subcons'
        );

        // Combine DB + memory stats
        return res.json({
          totalPembelian: Number(totalPembelian[0].total) + memoryStats.totalPembelian,
          totalInvoice: Number(totalInvoice[0].count) + memoryStats.totalInvoice,
          totalDeposit: Number(totalDeposit[0].total) + memoryStats.totalDeposit,
          subconAktif: Number(subconAktif[0].count) || memoryStats.subconAktif
        });
      } catch (dbError) {
        console.log('DB stats failed, using memory only');
      }
    }

    // Return memory stats only
    res.json(memoryStats);
  } catch (error) {
    res.json({
      totalPembelian: 0,
      totalInvoice: 0,
      totalDeposit: 0,
      subconAktif: 7
    });
  }
});

// ============ HEALTH CHECK ============

app.get('/api/health', (req, res) => {
  res.json({
    status: 'ok',
    timestamp: new Date().toISOString(),
    db: db ? 'connected' : 'disconnected'
  });
});

// ============ START SERVER ============

async function start() {
  await initDB();

  app.listen(PORT, () => {
    console.log(`🚀 Mr. Li API running on port ${PORT}`);
    console.log(`📍 http://localhost:${PORT}`);
  });
}

start();
