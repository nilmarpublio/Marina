-- Marina Management System Database Schema

-- Users table (Admin, Associates, Employees)
CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL,
    email TEXT UNIQUE NOT NULL,
    password TEXT NOT NULL,
    role TEXT NOT NULL CHECK (role IN ('admin', 'associate', 'employee')),
    cpf TEXT,
    phone TEXT,
    address TEXT,
    plan TEXT,
    status TEXT DEFAULT 'active' CHECK (status IN ('active', 'inactive', 'suspended')),
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
);

-- Boats table
CREATE TABLE IF NOT EXISTS boats (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL,
    type TEXT,
    length REAL,
    width REAL,
    owner_id INTEGER,
    status TEXT DEFAULT 'active',
    registration_number TEXT,
    engine_type TEXT,
    engine_power TEXT,
    boat_image TEXT,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (owner_id) REFERENCES users (id)
);

-- Berths/Spaces table
CREATE TABLE IF NOT EXISTS berths (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    number TEXT UNIQUE NOT NULL,
    type TEXT NOT NULL CHECK (type IN ('dry', 'wet')),
    length REAL,
    width REAL,
    status TEXT DEFAULT 'available' CHECK (status IN ('available', 'occupied', 'maintenance', 'reserved')),
    boat_id INTEGER,
    assigned_date DATETIME,
    monthly_rate REAL,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (boat_id) REFERENCES boats (id)
);

-- Appointments and Services table
CREATE TABLE IF NOT EXISTS appointments (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL,
    boat_id INTEGER,
    service_type TEXT NOT NULL, -- crane, fuel, cleaning, maintenance, entry, exit
    description TEXT,
    scheduled_date DATETIME NOT NULL,
    status TEXT DEFAULT 'pending' CHECK (status IN ('pending', 'confirmed', 'completed', 'cancelled')),
    assigned_employee_id INTEGER,
    estimated_duration INTEGER, -- in minutes
    actual_duration INTEGER,
    cost REAL,
    notes TEXT,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users (id),
    FOREIGN KEY (boat_id) REFERENCES boats (id),
    FOREIGN KEY (assigned_employee_id) REFERENCES users (id)
);

-- Financial Records table
CREATE TABLE IF NOT EXISTS financial_records (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL,
    type TEXT NOT NULL CHECK (type IN ('income', 'expense')),
    category TEXT, -- monthly_fee, service, maintenance, etc.
    description TEXT,
    amount REAL NOT NULL,
    due_date DATE,
    payment_date DATE,
    status TEXT DEFAULT 'pending' CHECK (status IN ('pending', 'paid', 'overdue', 'cancelled')),
    payment_method TEXT, -- cash, card, transfer, boleto
    invoice_number TEXT,
    notes TEXT,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users (id)
);

-- Documents table
CREATE TABLE IF NOT EXISTS documents (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL,
    boat_id INTEGER,
    document_type TEXT NOT NULL, -- boat_registration, nautical_license, contract, etc.
    file_name TEXT NOT NULL,
    file_path TEXT NOT NULL,
    expiry_date DATE,
    status TEXT DEFAULT 'valid' CHECK (status IN ('valid', 'expired', 'pending_review')),
    uploaded_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users (id),
    FOREIGN KEY (boat_id) REFERENCES boats (id)
);

-- Messages table
CREATE TABLE IF NOT EXISTS messages (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    sender_id INTEGER NOT NULL,
    recipient_id INTEGER,
    subject TEXT NOT NULL,
    content TEXT NOT NULL,
    status TEXT DEFAULT 'unread',
    sent_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (sender_id) REFERENCES users (id),
    FOREIGN KEY (recipient_id) REFERENCES users (id)
);

-- User Activity Logs table
CREATE TABLE IF NOT EXISTS user_logs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL,
    action TEXT NOT NULL, -- login, logout, create, update, delete
    table_affected TEXT,
    record_id INTEGER,
    details TEXT,
    ip_address TEXT,
    timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users (id)
);

-- Boat Movement Logs table
CREATE TABLE IF NOT EXISTS boat_movements (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    boat_id INTEGER NOT NULL,
    movement_type TEXT NOT NULL CHECK (movement_type IN ('entry', 'exit')),
    timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
    user_id INTEGER,
    notes TEXT,
    FOREIGN KEY (boat_id) REFERENCES boats (id),
    FOREIGN KEY (user_id) REFERENCES users (id)
);

-- Service Orders table
CREATE TABLE IF NOT EXISTS service_orders (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    appointment_id INTEGER NOT NULL,
    assigned_employee_id INTEGER,
    priority TEXT DEFAULT 'normal' CHECK (priority IN ('low', 'normal', 'high', 'urgent')),
    estimated_time INTEGER, -- in minutes
    actual_time INTEGER,
    materials_used TEXT,
    cost REAL,
    customer_rating INTEGER CHECK (customer_rating BETWEEN 1 AND 5),
    customer_feedback TEXT,
    status TEXT DEFAULT 'pending' CHECK (status IN ('pending', 'in_progress', 'completed', 'cancelled')),
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    completed_at DATETIME,
    FOREIGN KEY (appointment_id) REFERENCES appointments (id),
    FOREIGN KEY (assigned_employee_id) REFERENCES users (id)
);

-- Incidents table (Security and Environment)
CREATE TABLE IF NOT EXISTS incidents (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    incident_type TEXT NOT NULL, -- damage, spill, fire, theft, etc.
    description TEXT NOT NULL,
    location TEXT,
    severity TEXT DEFAULT 'low' CHECK (severity IN ('low', 'medium', 'high', 'critical')),
    reported_by INTEGER NOT NULL,
    boat_id INTEGER,
    status TEXT DEFAULT 'open' CHECK (status IN ('open', 'investigating', 'resolved', 'closed')),
    actions_taken TEXT,
    resolution_notes TEXT,
    reported_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    resolved_at DATETIME,
    FOREIGN KEY (reported_by) REFERENCES users (id),
    FOREIGN KEY (boat_id) REFERENCES boats (id)
);

-- Inspections table
CREATE TABLE IF NOT EXISTS inspections (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    inspection_type TEXT NOT NULL, -- fire_extinguisher, pump, waste, general
    inspector_id INTEGER NOT NULL,
    inspection_date DATE NOT NULL,
    location TEXT,
    status TEXT NOT NULL CHECK (status IN ('passed', 'failed', 'needs_attention')),
    findings TEXT,
    recommendations TEXT,
    next_inspection_date DATE,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (inspector_id) REFERENCES users (id)
);

-- Create indexes for better performance
CREATE INDEX IF NOT EXISTS idx_users_email ON users(email);
CREATE INDEX IF NOT EXISTS idx_users_role ON users(role);
CREATE INDEX IF NOT EXISTS idx_boats_owner ON boats(owner_id);
CREATE INDEX IF NOT EXISTS idx_berths_status ON berths(status);
CREATE INDEX IF NOT EXISTS idx_appointments_user ON appointments(user_id);
CREATE INDEX IF NOT EXISTS idx_appointments_date ON appointments(scheduled_date);
CREATE INDEX IF NOT EXISTS idx_financial_user ON financial_records(user_id);
CREATE INDEX IF NOT EXISTS idx_financial_status ON financial_records(status);
CREATE INDEX IF NOT EXISTS idx_messages_recipient ON messages(recipient_id);
CREATE INDEX IF NOT EXISTS idx_logs_user ON user_logs(user_id);
