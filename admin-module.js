/**
 * ENTERPRISE USER MANAGEMENT MODULE
 * Indo Hair Purchase System
 * Version 2.0 - Enterprise Grade
 */

const bcrypt = require('bcrypt');
const crypto = require('crypto');
const { v4: uuidv4 } = require('uuid');

// ============ CONSTANTS ============

const ROLES = ['OWNER', 'ADMIN', 'AUDITOR', 'STAFF_PURCHASE', 'STAFF_GUDANG', 'VIEWER'];

const USER_STATUS = {
  ACTIVE: 'active',
  INACTIVE: 'inactive',
  LOCKED: 'locked'
};

const DEFAULT_PASSWORD_POLICY = {
  min_length: 10,
  require_uppercase: true,
  require_lowercase: true,
  require_number: true,
  require_symbol: false,
  block_common: true
};

const DEFAULT_LOCKOUT_POLICY = {
  max_attempts: 5,
  lockout_minutes: 10
};

// Common weak passwords to block
const COMMON_PASSWORDS = [
  'password', '123456', '12345678', 'qwerty', 'abc123', 'monkey', 'master',
  'dragon', 'letmein', 'login', 'admin', 'welcome', 'password1', 'password123',
  'indohair', 'purchase', 'admin123', 'user123'
];

// Permission groups for UI display
const PERMISSION_GROUPS = {
  'Invoice': [
    { code: 'invoice.view', name: 'View Invoices' },
    { code: 'invoice.create', name: 'Create Invoice' },
    { code: 'invoice.edit', name: 'Edit Invoice' },
    { code: 'invoice.delete', name: 'Soft Delete Invoice' },
    { code: 'invoice.restore', name: 'Restore Deleted' },
    { code: 'invoice.hard_delete', name: 'Permanent Delete' },
    { code: 'invoice.export', name: 'Export Invoice' },
    { code: 'invoice.print', name: 'Print Invoice' }
  ],
  'Deposit': [
    { code: 'deposit.view', name: 'View Deposits' },
    { code: 'deposit.create', name: 'Create Deposit' },
    { code: 'deposit.edit', name: 'Edit Deposit' },
    { code: 'deposit.delete', name: 'Delete Deposit' }
  ],
  'Gudang': [
    { code: 'verification.view', name: 'View Verifications' },
    { code: 'verification.create', name: 'Verify Invoice' },
    { code: 'retul.view', name: 'View Retul' },
    { code: 'retul.create', name: 'Create Retul' },
    { code: 'retul.edit', name: 'Edit Retul' }
  ],
  'Master Data': [
    { code: 'master.view', name: 'View Master Data' },
    { code: 'master.edit', name: 'Edit Master Data' }
  ],
  'Reports': [
    { code: 'report.view', name: 'View Reports' },
    { code: 'report.export', name: 'Export Reports' }
  ],
  'Admin': [
    { code: 'user.view', name: 'View Users' },
    { code: 'user.create', name: 'Create User' },
    { code: 'user.edit', name: 'Edit User' },
    { code: 'user.delete', name: 'Delete User' },
    { code: 'user.manage_sessions', name: 'Manage Sessions' },
    { code: 'user.manage_permissions', name: 'Manage Permissions' },
    { code: 'audit.view', name: 'View Audit Logs' },
    { code: 'audit.export', name: 'Export Audit Logs' },
    { code: 'security.manage', name: 'Manage Security Settings' }
  ]
};

// Default role permissions
const ROLE_PERMISSIONS = {
  'OWNER': Object.values(PERMISSION_GROUPS).flat().map(p => p.code),
  'ADMIN': [
    'invoice.view', 'invoice.create', 'invoice.edit', 'invoice.delete', 'invoice.restore', 'invoice.export', 'invoice.print',
    'deposit.view', 'deposit.create', 'deposit.edit', 'deposit.delete',
    'verification.view', 'verification.create', 'retul.view', 'retul.create', 'retul.edit',
    'master.view', 'master.edit',
    'report.view', 'report.export',
    'user.view', 'user.create', 'user.edit', 'user.manage_sessions',
    'audit.view'
  ],
  'AUDITOR': [
    'invoice.view', 'invoice.export',
    'deposit.view',
    'verification.view', 'retul.view',
    'master.view',
    'report.view', 'report.export',
    'audit.view', 'audit.export'
  ],
  'STAFF_PURCHASE': [
    'invoice.view', 'invoice.create', 'invoice.edit', 'invoice.print',
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
    'deposit.view',
    'verification.view', 'retul.view',
    'master.view',
    'report.view'
  ]
};

// ============ HELPER FUNCTIONS ============

function validatePassword(password, policy = DEFAULT_PASSWORD_POLICY) {
  const errors = [];

  if (password.length < policy.min_length) {
    errors.push(`Password must be at least ${policy.min_length} characters`);
  }

  if (policy.require_uppercase && !/[A-Z]/.test(password)) {
    errors.push('Password must contain at least one uppercase letter');
  }

  if (policy.require_lowercase && !/[a-z]/.test(password)) {
    errors.push('Password must contain at least one lowercase letter');
  }

  if (policy.require_number && !/[0-9]/.test(password)) {
    errors.push('Password must contain at least one number');
  }

  if (policy.require_symbol && !/[!@#$%^&*(),.?":{}|<>]/.test(password)) {
    errors.push('Password must contain at least one symbol');
  }

  if (policy.block_common && COMMON_PASSWORDS.includes(password.toLowerCase())) {
    errors.push('Password is too common, please choose a stronger one');
  }

  return { valid: errors.length === 0, errors };
}

function generateToken() {
  return uuidv4() + '-' + uuidv4() + '-' + crypto.randomBytes(16).toString('hex');
}

async function hashToken(token) {
  return await bcrypt.hash(token, 5);
}

function parseUserAgent(ua) {
  if (!ua) return { browser: 'Unknown', os: 'Unknown', device: 'Unknown' };

  let browser = 'Unknown';
  let os = 'Unknown';
  let device = 'Desktop';

  // Browser detection
  if (ua.includes('Chrome') && !ua.includes('Edg')) browser = 'Chrome';
  else if (ua.includes('Firefox')) browser = 'Firefox';
  else if (ua.includes('Safari') && !ua.includes('Chrome')) browser = 'Safari';
  else if (ua.includes('Edg')) browser = 'Edge';
  else if (ua.includes('MSIE') || ua.includes('Trident')) browser = 'IE';

  // OS detection
  if (ua.includes('Windows')) os = 'Windows';
  else if (ua.includes('Mac OS')) os = 'macOS';
  else if (ua.includes('Linux')) os = 'Linux';
  else if (ua.includes('Android')) os = 'Android';
  else if (ua.includes('iOS') || ua.includes('iPhone') || ua.includes('iPad')) os = 'iOS';

  // Device detection
  if (ua.includes('Mobile') || ua.includes('Android') || ua.includes('iPhone')) device = 'Mobile';
  else if (ua.includes('iPad') || ua.includes('Tablet')) device = 'Tablet';

  return { browser, os, device };
}

function getClientInfo(req) {
  const ip = req.headers['x-forwarded-for']?.split(',')[0] || req.ip || req.connection?.remoteAddress || 'unknown';
  const userAgent = req.get('User-Agent') || '';
  const parsed = parseUserAgent(userAgent);

  return {
    ip: ip.replace('::ffff:', ''),
    user_agent: userAgent,
    browser: parsed.browser,
    os: parsed.os,
    device: parsed.device
  };
}

// ============ DATABASE SCHEMA FOR ENTERPRISE MODULE ============

// ALTER TABLE statements (without IF NOT EXISTS since MySQL doesn't support it)
const COLUMN_ADDITIONS = [
  // Users table columns
  { table: 'users', column: 'status', definition: "ENUM('active','inactive','locked') DEFAULT 'active'" },
  { table: 'users', column: 'failed_login_attempts', definition: 'INT DEFAULT 0' },
  { table: 'users', column: 'locked_until', definition: 'DATETIME NULL' },
  { table: 'users', column: 'last_ip', definition: 'VARCHAR(45) NULL' },
  { table: 'users', column: 'last_user_agent', definition: 'TEXT NULL' },
  { table: 'users', column: 'password_changed_at', definition: 'DATETIME NULL' },
  { table: 'users', column: 'force_password_change', definition: 'TINYINT DEFAULT 0' },
  { table: 'users', column: 'mfa_enabled', definition: 'TINYINT DEFAULT 0' },
  { table: 'users', column: 'mfa_secret', definition: 'VARCHAR(255) NULL' },
  { table: 'users', column: 'created_by', definition: 'BIGINT NULL' },
  // Sessions table columns
  { table: 'sessions', column: 'last_seen_at', definition: 'DATETIME NULL' },
  { table: 'sessions', column: 'device_info', definition: 'VARCHAR(255) NULL' },
  // Audit logs table columns
  { table: 'audit_logs', column: 'request_id', definition: 'VARCHAR(100) NULL' },
  { table: 'audit_logs', column: 'device_info', definition: 'VARCHAR(255) NULL' }
];

const ENTERPRISE_TABLES = [
  // Update role enum to include AUDITOR
  `ALTER TABLE users MODIFY COLUMN role ENUM('OWNER','ADMIN','AUDITOR','STAFF_PURCHASE','STAFF_GUDANG','VIEWER') DEFAULT 'VIEWER'`,
  `ALTER TABLE role_permissions MODIFY COLUMN role ENUM('OWNER','ADMIN','AUDITOR','STAFF_PURCHASE','STAFF_GUDANG','VIEWER') NOT NULL`,

  // User permission overrides table
  `CREATE TABLE IF NOT EXISTS user_permission_overrides (
    id BIGINT AUTO_INCREMENT PRIMARY KEY,
    user_id BIGINT NOT NULL,
    permission_code VARCHAR(50) NOT NULL,
    allowed TINYINT DEFAULT 1,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    created_by BIGINT NULL,
    UNIQUE KEY unique_user_perm (user_id, permission_code),
    INDEX idx_user_id (user_id)
  )`,

  // Login history table (without foreign key to avoid issues)
  `CREATE TABLE IF NOT EXISTS login_history (
    id BIGINT AUTO_INCREMENT PRIMARY KEY,
    user_id BIGINT NULL,
    username VARCHAR(50) NOT NULL,
    success TINYINT DEFAULT 0,
    ip_address VARCHAR(45),
    user_agent TEXT,
    device_info VARCHAR(255),
    failure_reason VARCHAR(100) NULL,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    INDEX idx_user_id (user_id),
    INDEX idx_created_at (created_at),
    INDEX idx_success (success)
  )`,

  // Security settings table
  `CREATE TABLE IF NOT EXISTS security_settings (
    id INT AUTO_INCREMENT PRIMARY KEY,
    setting_key VARCHAR(50) UNIQUE NOT NULL,
    setting_value JSON,
    updated_at DATETIME DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    updated_by BIGINT NULL
  )`
];

// Default security settings
const DEFAULT_SECURITY_SETTINGS = [
  { key: 'password_policy', value: DEFAULT_PASSWORD_POLICY },
  { key: 'lockout_policy', value: DEFAULT_LOCKOUT_POLICY },
  { key: 'session_expiry_hours', value: 168 }, // 7 days
  { key: 'ip_allowlist_enabled', value: false },
  { key: 'ip_allowlist', value: [] },
  { key: 'mfa_required_roles', value: [] }
];

// ============ ENTERPRISE PERMISSION SEEDS ============

const ENTERPRISE_PERMISSIONS = [
  // Invoice permissions
  { code: 'invoice.view', name: 'View Invoices', module: 'invoice' },
  { code: 'invoice.create', name: 'Create Invoice', module: 'invoice' },
  { code: 'invoice.edit', name: 'Edit Invoice', module: 'invoice' },
  { code: 'invoice.delete', name: 'Delete Invoice (Soft)', module: 'invoice' },
  { code: 'invoice.restore', name: 'Restore Deleted Invoice', module: 'invoice' },
  { code: 'invoice.hard_delete', name: 'Permanently Delete Invoice', module: 'invoice' },
  { code: 'invoice.export', name: 'Export Invoice', module: 'invoice' },
  { code: 'invoice.print', name: 'Print Invoice', module: 'invoice' },
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
  { code: 'deposit.edit', name: 'Edit Deposit', module: 'deposit' },
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
  { code: 'user.manage_sessions', name: 'Manage User Sessions', module: 'user' },
  { code: 'user.manage_permissions', name: 'Manage User Permissions', module: 'user' },
  // Audit log permissions
  { code: 'audit.view', name: 'View Audit Logs', module: 'audit' },
  { code: 'audit.export', name: 'Export Audit Logs', module: 'audit' },
  // Security permissions
  { code: 'security.manage', name: 'Manage Security Settings', module: 'security' }
];

// ============ SETUP FUNCTION ============

async function setupEnterpriseTables(db) {
  console.log('Setting up enterprise tables...');

  // Add columns to existing tables (check if exists first)
  for (const col of COLUMN_ADDITIONS) {
    try {
      // Check if column exists
      const [rows] = await db.execute(
        `SELECT COLUMN_NAME FROM INFORMATION_SCHEMA.COLUMNS
         WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = ? AND COLUMN_NAME = ?`,
        [col.table, col.column]
      );

      if (rows.length === 0) {
        // Column doesn't exist, add it
        await db.execute(`ALTER TABLE ${col.table} ADD COLUMN ${col.column} ${col.definition}`);
        console.log(`Added column: ${col.table}.${col.column}`);
      }
    } catch (err) {
      // Silently ignore errors
    }
  }

  // Run CREATE TABLE and MODIFY statements
  for (const query of ENTERPRISE_TABLES) {
    try {
      await db.execute(query);
    } catch (err) {
      // Silently ignore errors (table already exists, etc)
      if (!err.message.includes('Duplicate') && !err.message.includes('already exists')) {
        // Only log non-duplicate errors for debugging
      }
    }
  }

  // Seed permissions
  for (const perm of ENTERPRISE_PERMISSIONS) {
    try {
      await db.execute(
        'INSERT IGNORE INTO permissions (code, name, description, module) VALUES (?, ?, ?, ?)',
        [perm.code, perm.name, perm.description || null, perm.module]
      );
    } catch (err) {
      // Ignore duplicates
    }
  }

  // Seed role permissions
  for (const [role, perms] of Object.entries(ROLE_PERMISSIONS)) {
    for (const permCode of perms) {
      try {
        await db.execute(
          'INSERT IGNORE INTO role_permissions (role, permission_code) VALUES (?, ?)',
          [role, permCode]
        );
      } catch (err) {
        // Ignore duplicates
      }
    }
  }

  // Seed security settings
  for (const setting of DEFAULT_SECURITY_SETTINGS) {
    try {
      await db.execute(
        'INSERT IGNORE INTO security_settings (setting_key, setting_value) VALUES (?, ?)',
        [setting.key, JSON.stringify(setting.value)]
      );
    } catch (err) {
      // Ignore duplicates
    }
  }

  console.log('✅ Enterprise tables ready');
}

// ============ EXPORTS ============

module.exports = {
  ROLES,
  USER_STATUS,
  PERMISSION_GROUPS,
  ROLE_PERMISSIONS,
  DEFAULT_PASSWORD_POLICY,
  DEFAULT_LOCKOUT_POLICY,
  validatePassword,
  generateToken,
  hashToken,
  parseUserAgent,
  getClientInfo,
  setupEnterpriseTables,
  ENTERPRISE_PERMISSIONS
};
