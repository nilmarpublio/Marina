from flask import Flask, render_template, request, redirect, url_for, session, flash, jsonify
import sqlite3
import hashlib
import datetime
import os
from functools import wraps

app = Flask(__name__)
app.secret_key = 'marina_secret_key_2024'

# Database initialization
def init_db():
    """Initialize the database with all required tables"""
    conn = sqlite3.connect('marina.db')
    cursor = conn.cursor()
    
    # Read and execute schema
    with open('schema.sql', 'r', encoding='utf-8') as f:
        cursor.executescript(f.read())
    
    # Create default admin user if not exists
    cursor.execute("SELECT * FROM users WHERE email = 'admin@marina.com'")
    if not cursor.fetchone():
        admin_password = hashlib.sha256('admin123'.encode()).hexdigest()
        cursor.execute("""
            INSERT INTO users (name, email, password, role, cpf, phone, address, status)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        """, ('Administrador', 'admin@marina.com', admin_password, 'admin', '00000000000', '(11) 99999-9999', 'Marina Central', 'active'))
    
    # Create sample associate if not exists
    cursor.execute("SELECT * FROM users WHERE email = 'joao@email.com'")
    if not cursor.fetchone():
        user_password = hashlib.sha256('123456'.encode()).hexdigest()
        cursor.execute("""
            INSERT INTO users (name, email, password, role, cpf, phone, address, status, plan)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, ('João Silva', 'joao@email.com', user_password, 'associate', '12345678901', '(11) 98765-4321', 'Rua das Flores, 123', 'active', 'vaga_molhada_mensal'))
    
    # Get the associate ID for boats
    associate = cursor.execute("SELECT id FROM users WHERE email = 'joao@email.com'").fetchone()
    if associate:
        associate_id = associate[0]
        
        # Create sample boats if not exist
        cursor.execute("SELECT COUNT(*) as count FROM boats")
        boat_count = cursor.fetchone()[0]
        
        if boat_count == 0:
            sample_boats = [
                ('Vento Sul', 'veleiro', 12.5, 4.0, associate_id, 'active', 'BR001', 'Yamaha 150HP', '150CV'),
                ('Brisa do Mar', 'lancha', 8.0, 3.0, associate_id, 'active', 'BR002', 'Mercury 200HP', '200CV'),
                ('Aventura', 'iate', 15.0, 5.0, associate_id, 'active', 'BR003', 'Caterpillar 300HP', '300CV'),
                ('Liberdade', 'jetski', 3.5, 1.2, associate_id, 'active', 'BR004', 'Sea-Doo 130HP', '130CV'),
                ('Serenidade', 'catamarã', 10.0, 6.0, associate_id, 'active', 'BR005', 'Volvo 250HP', '250CV')
            ]
            
            for boat in sample_boats:
                cursor.execute("""
                    INSERT INTO boats (name, type, length, width, owner_id, status, registration_number, engine_type, engine_power, created_at)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """, (*boat, datetime.datetime.now()))
    
    conn.commit()
    conn.close()

def check_and_fix_schema():
    """Verificar e corrigir schema do banco de dados"""
    conn = sqlite3.connect('marina.db')
    cursor = conn.cursor()
    
    try:
        # Verificar se as colunas existem na tabela boats
        cursor.execute("PRAGMA table_info(boats)")
        columns = [column[1] for column in cursor.fetchall()]
        
        # Adicionar colunas faltantes na tabela boats
        if 'registration_number' not in columns:
            cursor.execute("ALTER TABLE boats ADD COLUMN registration_number TEXT")
            print("Coluna 'registration_number' adicionada à tabela boats")
        
        if 'engine_type' not in columns:
            cursor.execute("ALTER TABLE boats ADD COLUMN engine_type TEXT")
            print("Coluna 'engine_type' adicionada à tabela boats")
        
        if 'engine_power' not in columns:
            cursor.execute("ALTER TABLE boats ADD COLUMN engine_power TEXT")
            print("Coluna 'engine_power' adicionada à tabela boats")
        
        if 'boat_image' not in columns:
            cursor.execute("ALTER TABLE boats ADD COLUMN boat_image TEXT")
            print("Coluna 'boat_image' adicionada à tabela boats")
        
        conn.commit()
        print("Schema verificado e corrigido com sucesso!")
        
    except Exception as e:
        print(f"Erro ao verificar/corrigir schema: {e}")
    finally:
        conn.close()

# Authentication decorator - OBRIGATÓRIO para TODAS as rotas
def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            flash('Você precisa fazer login para acessar esta página.', 'warning')
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function

# Role-based access control
def role_required(roles):
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            if 'user_role' not in session or session['user_role'] not in roles:
                flash('Acesso negado! Você não tem permissão para acessar esta funcionalidade.', 'error')
                return redirect(url_for('dashboard'))
            return f(*args, **kwargs)
        return decorated_function
    return decorator

# Database helper functions
def get_db_connection():
    conn = sqlite3.connect('marina.db')
    conn.row_factory = sqlite3.Row
    return conn

def hash_password(password):
    return hashlib.sha256(password.encode()).hexdigest()

# Public Routes (sem login required)
@app.route('/')
def index():
    """Rota inicial - sempre redireciona para login se não autenticado"""
    if 'user_id' in session:
        return redirect(url_for('dashboard'))
    return redirect(url_for('login'))

@app.route('/login', methods=['GET', 'POST'])
def login():
    """Única rota pública - página de login"""
    # Se já está logado, redireciona para dashboard
    if 'user_id' in session:
        return redirect(url_for('dashboard'))
        
    if request.method == 'POST':
        email = request.form.get('email', '').strip()
        password = request.form.get('password', '')
        
        if not email or not password:
            flash('Email e senha são obrigatórios!', 'error')
            return render_template('auth/login.html')
        
        password_hash = hash_password(password)
        
        conn = get_db_connection()
        user = conn.execute(
            'SELECT * FROM users WHERE email = ? AND password = ? AND status = "active"',
            (email, password_hash)
        ).fetchone()
        conn.close()
        
        if user:
            # Criar sessão segura
            session['user_id'] = user['id']
            session['user_name'] = user['name']
            session['user_role'] = user['role']
            session['user_email'] = user['email']
            session['login_time'] = datetime.datetime.now().isoformat()
            
            # Log da atividade de login
            log_user_activity(user['id'], 'login', 'users', user['id'], f'Login realizado - IP: {request.remote_addr}')
            
            flash(f'Bem-vindo, {user["name"]}!', 'success')
            return redirect(url_for('dashboard'))
        else:
            flash('Email ou senha incorretos, ou conta inativa!', 'error')
    
    return render_template('auth/login.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    """Registro público apenas para associados"""
    # Se já está logado, redireciona para dashboard
    if 'user_id' in session:
        return redirect(url_for('dashboard'))
        
    if request.method == 'POST':
        name = request.form.get('name', '').strip()
        email = request.form.get('email', '').strip()
        password = request.form.get('password', '')
        cpf = request.form.get('cpf', '').strip()
        phone = request.form.get('phone', '').strip()
        address = request.form.get('address', '').strip()
        
        # Validações básicas
        if not all([name, email, password, cpf, phone, address]):
            flash('Todos os campos são obrigatórios!', 'error')
            return render_template('auth/register.html')
        
        if len(password) < 6:
            flash('A senha deve ter pelo menos 6 caracteres!', 'error')
            return render_template('auth/register.html')
        
        conn = get_db_connection()
        
        # Check if email already exists
        existing_user = conn.execute('SELECT * FROM users WHERE email = ?', (email,)).fetchone()
        if existing_user:
            flash('Email já cadastrado!', 'error')
            conn.close()
            return render_template('auth/register.html')
        
        # Insert new user as associate (apenas associados podem se registrar)
        try:
            password_hash = hash_password(password)
            conn.execute("""
                INSERT INTO users (name, email, password, role, cpf, phone, address, status, created_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (name, email, password_hash, 'associate', cpf, phone, address, 'active', datetime.datetime.now()))
            
            conn.commit()
            flash('Cadastro realizado com sucesso! Faça login para continuar.', 'success')
            return redirect(url_for('login'))
        except Exception as e:
            flash(f'Erro ao realizar cadastro: {str(e)}', 'error')
        finally:
            conn.close()
    
    return render_template('auth/register.html')

# Helper function for logging user activities
def log_user_activity(user_id, action, table_affected=None, record_id=None, details=None):
    """Log user activities for security and audit"""
    try:
        conn = get_db_connection()
        conn.execute("""
            INSERT INTO user_logs (user_id, action, table_affected, record_id, details, ip_address, timestamp)
            VALUES (?, ?, ?, ?, ?, ?, ?)
        """, (user_id, action, table_affected, record_id, details, request.remote_addr, datetime.datetime.now()))
        conn.commit()
        conn.close()
    except:
        pass  # Não falhar se o log não funcionar

# Protected Routes (todas requerem login)
@app.route('/logout')
@login_required
def logout():
    """Logout seguro com limpeza de sessão"""
    user_id = session.get('user_id')
    user_name = session.get('user_name')
    
    # Log da atividade de logout
    if user_id:
        log_user_activity(user_id, 'logout', 'users', user_id, f'Logout realizado - IP: {request.remote_addr}')
    
    # Limpar completamente a sessão
    session.clear()
    
    flash(f'Logout realizado com sucesso! Até logo, {user_name}!', 'success')
    return redirect(url_for('login'))

@app.route('/dashboard')
@login_required
def dashboard():
    """Dashboard principal - acesso baseado em role"""
    role = session['user_role']
    
    # Log de acesso ao dashboard
    log_user_activity(session['user_id'], 'access_dashboard', 'dashboard', None, f'Acesso ao dashboard {role}')
    
    if role == 'admin':
        return render_template('dashboard/admin_dashboard.html')
    elif role == 'associate':
        return render_template('dashboard/associate_dashboard.html')
    elif role == 'employee':
        return render_template('dashboard/employee_dashboard.html')
    else:
        flash('Tipo de usuário inválido!', 'error')
        return redirect(url_for('logout'))

# Debug route to check boats
@app.route('/debug/boats')
@login_required
@role_required(['admin'])
def debug_boats():
    """Rota de debug para verificar embarcações"""
    conn = get_db_connection()
    
    # Verificar todas as embarcações
    all_boats = conn.execute("SELECT * FROM boats").fetchall()
    active_boats = conn.execute("SELECT * FROM boats WHERE status = 'active'").fetchall()
    
    # Verificar associados
    associates = conn.execute("SELECT * FROM users WHERE role = 'associate'").fetchall()
    
    conn.close()
    
    debug_info = {
        'total_boats': len(all_boats),
        'active_boats': len(active_boats),
        'total_associates': len(associates),
        'boats': [dict(boat) for boat in all_boats],
        'associates': [dict(assoc) for assoc in associates]
    }
    
    return jsonify(debug_info)

# Admin Routes - TODAS protegidas
@app.route('/admin/associates')
@login_required
@role_required(['admin'])
def admin_associates():
    log_user_activity(session['user_id'], 'view_associates', 'users', None, 'Visualização da lista de associados')
    
    conn = get_db_connection()
    associates = conn.execute(
        'SELECT * FROM users WHERE role = "associate" ORDER BY name'
    ).fetchall()
    conn.close()
    return render_template('admin/associates.html', associates=associates)

@app.route('/admin/associates/create', methods=['POST'])
@login_required
@role_required(['admin'])
def admin_associates_create():
    name = request.form.get('name', '').strip()
    email = request.form.get('email', '').strip()
    password = request.form.get('password', '')
    cpf = request.form.get('cpf', '').strip()
    phone = request.form.get('phone', '').strip()
    address = request.form.get('address', '').strip()
    plan = request.form.get('plan', '')
    status = request.form.get('status', 'active')
    
    # Validações
    if not all([name, email, password, cpf, phone, address]):
        flash('Todos os campos obrigatórios devem ser preenchidos!', 'error')
        return redirect(url_for('admin_associates'))
    
    conn = get_db_connection()
    
    # Check if email already exists
    existing_user = conn.execute('SELECT * FROM users WHERE email = ?', (email,)).fetchone()
    if existing_user:
        flash('Email já cadastrado!', 'error')
        conn.close()
        return redirect(url_for('admin_associates'))
    
    # Insert new associate
    try:
        password_hash = hash_password(password)
        cursor = conn.execute("""
            INSERT INTO users (name, email, password, role, cpf, phone, address, plan, status, created_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (name, email, password_hash, 'associate', cpf, phone, address, plan, status, datetime.datetime.now()))
        
        new_user_id = cursor.lastrowid
        conn.commit()
        
        # Log da atividade
        log_user_activity(session['user_id'], 'create_associate', 'users', new_user_id, f'Criado associado: {name}')
        
        flash(f'Associado {name} cadastrado com sucesso!', 'success')
    except Exception as e:
        flash(f'Erro ao cadastrar associado: {str(e)}', 'error')
    finally:
        conn.close()
    
    return redirect(url_for('admin_associates'))

@app.route('/admin/boats')
@login_required
@role_required(['admin'])
def admin_boats():
    log_user_activity(session['user_id'], 'view_boats', 'boats', None, 'Visualização da lista de embarcações')
    
    conn = get_db_connection()
    boats = conn.execute("""
        SELECT b.*, u.name as owner_name 
        FROM boats b 
        LEFT JOIN users u ON b.owner_id = u.id 
        ORDER BY b.name
    """).fetchall()
    
    # Get associates for the dropdown
    associates = conn.execute(
        'SELECT id, name FROM users WHERE role = "associate" ORDER BY name'
    ).fetchall()
    
    conn.close()
    return render_template('admin/boats.html', boats=boats, associates=associates)

@app.route('/admin/boats/create', methods=['POST'])
@login_required
@role_required(['admin'])
def admin_boats_create():
    name = request.form.get('name', '').strip()
    boat_type = request.form.get('type', '')
    length = request.form.get('length', '')
    width = request.form.get('width', '')
    owner_id = request.form.get('owner_id', '')
    status = request.form.get('status', 'active')
    registration_number = request.form.get('registration_number', '').strip()
    engine_type = request.form.get('engine_type', '').strip()
    engine_power = request.form.get('engine_power', '').strip()
    
    # Validações
    if not all([name, boat_type, length, width, owner_id]):
        flash('Campos obrigatórios: Nome, Tipo, Dimensões e Proprietário!', 'error')
        return redirect(url_for('admin_boats'))
    
    # Handle file upload if present
    boat_image = None
    if 'boat_image' in request.files and request.files['boat_image'].filename:
        file = request.files['boat_image']
        # Create uploads directory if it doesn't exist
        if not os.path.exists('static/uploads'):
            os.makedirs('static/uploads')
        
        # Save the file
        filename = f"{datetime.datetime.now().strftime('%Y%m%d%H%M%S')}_{file.filename}"
        file_path = os.path.join('static/uploads', filename)
        file.save(file_path)
        boat_image = f"/uploads/{filename}"
    
    conn = get_db_connection()
    
    # Insert new boat
    try:
        cursor = conn.execute("""
            INSERT INTO boats (name, type, length, width, owner_id, status, registration_number, engine_type, engine_power, created_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (name, boat_type, length, width, owner_id, status, registration_number, engine_type, engine_power, datetime.datetime.now()))
        
        new_boat_id = cursor.lastrowid
        conn.commit()
        
        # Log da atividade
        log_user_activity(session['user_id'], 'create_boat', 'boats', new_boat_id, f'Criada embarcação: {name}')
        
        flash(f'Embarcação {name} cadastrada com sucesso!', 'success')
    except Exception as e:
        flash(f'Erro ao cadastrar embarcação: {str(e)}', 'error')
    finally:
        conn.close()
    
    return redirect(url_for('admin_boats'))

@app.route('/admin/berths')
@login_required
@role_required(['admin'])
def admin_berths():
    log_user_activity(session['user_id'], 'view_berths', 'berths', None, 'Visualização da lista de vagas')
    
    conn = get_db_connection()
    
    # Debug: verificar se há embarcações
    boat_count = conn.execute("SELECT COUNT(*) as count FROM boats").fetchone()['count']
    print(f"DEBUG: Total de embarcações no banco: {boat_count}")
    
    berths = conn.execute("""
        SELECT b.*, bt.name as boat_name, u.name as owner_name
        FROM berths b
        LEFT JOIN boats bt ON b.boat_id = bt.id
        LEFT JOIN users u ON bt.owner_id = u.id
        ORDER BY b.number
    """).fetchall()
    
    # Get boats for the dropdown - CORRIGIDO com debug
    boats = conn.execute("""
        SELECT b.id, b.name, b.type, u.name as owner_name
        FROM boats b
        LEFT JOIN users u ON b.owner_id = u.id
        ORDER BY b.name
    """).fetchall()
    
    print(f"DEBUG: Embarcações encontradas para dropdown: {len(boats)}")
    for boat in boats:
        print(f"DEBUG: Embarcação - ID: {boat['id']}, Nome: {boat['name']}, Tipo: {boat['type']}, Proprietário: {boat['owner_name']}")
    
    conn.close()
    return render_template('admin/berths.html', berths=berths, boats=boats)

@app.route('/admin/berths/create', methods=['POST'])
@login_required
@role_required(['admin'])
def admin_berths_create():
    number = request.form.get('number', '').strip()
    berth_type = request.form.get('type', '')
    length = request.form.get('length', '')
    width = request.form.get('width', '')
    monthly_rate = request.form.get('monthly_rate', 0)
    status = request.form.get('status', 'available')
    boat_id = request.form.get('boat_id') or None
    
    # Validações
    if not all([number, berth_type, length, width]):
        flash('Campos obrigatórios: Número, Tipo e Dimensões!', 'error')
        return redirect(url_for('admin_berths'))
    
    conn = get_db_connection()
    
    # Check if berth number already exists
    existing_berth = conn.execute('SELECT * FROM berths WHERE number = ?', (number,)).fetchone()
    if existing_berth:
        flash('Número de vaga já existe!', 'error')
        conn.close()
        return redirect(url_for('admin_berths'))
    
    # Insert new berth
    try:
        cursor = conn.execute("""
            INSERT INTO berths (number, type, length, width, status, boat_id, monthly_rate, created_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        """, (number, berth_type, length, width, status, boat_id, monthly_rate, datetime.datetime.now()))
        
        new_berth_id = cursor.lastrowid
        conn.commit()
        
        # Log da atividade
        log_user_activity(session['user_id'], 'create_berth', 'berths', new_berth_id, f'Criada vaga: {number}')
        
        flash(f'Vaga {number} cadastrada com sucesso!', 'success')
    except Exception as e:
        flash(f'Erro ao cadastrar vaga: {str(e)}', 'error')
    finally:
        conn.close()
    
    return redirect(url_for('admin_berths'))

@app.route('/admin/appointments')
@login_required
@role_required(['admin'])
def admin_appointments():
    log_user_activity(session['user_id'], 'view_appointments', 'appointments', None, 'Visualização da lista de agendamentos')
    
    conn = get_db_connection()
    appointments = conn.execute("""
        SELECT a.*, u.name as user_name, b.name as boat_name, e.name as employee_name
        FROM appointments a
        LEFT JOIN users u ON a.user_id = u.id
        LEFT JOIN boats b ON a.boat_id = b.id
        LEFT JOIN users e ON a.assigned_employee_id = e.id
        ORDER BY a.scheduled_date DESC
    """).fetchall()
    
    # Get data for dropdowns - CORRIGIDO
    associates = conn.execute('SELECT id, name FROM users WHERE role = "associate" ORDER BY name').fetchall()
    boats = conn.execute("""
        SELECT b.id, b.name, b.type, u.name as owner_name 
        FROM boats b 
        LEFT JOIN users u ON b.owner_id = u.id 
        ORDER BY b.name
    """).fetchall()
    employees = conn.execute('SELECT id, name FROM users WHERE role = "employee" ORDER BY name').fetchall()
    
    conn.close()
    return render_template('admin/appointments.html', appointments=appointments, associates=associates, boats=boats, employees=employees)

@app.route('/admin/appointments/create', methods=['POST'])
@login_required
@role_required(['admin'])
def admin_appointments_create():
    user_id = request.form.get('user_id', '')
    boat_id = request.form.get('boat_id') or None
    scheduled_date = request.form.get('scheduled_date', '')
    service_type = request.form.get('service_type', '')
    assigned_employee_id = request.form.get('assigned_employee_id') or None
    estimated_duration = request.form.get('estimated_duration') or None
    description = request.form.get('description', '')
    cost = request.form.get('cost') or None
    
    # Validações
    if not all([user_id, scheduled_date, service_type]):
        flash('Campos obrigatórios: Associado, Data/Hora e Tipo de Serviço!', 'error')
        return redirect(url_for('admin_appointments'))
    
    conn = get_db_connection()
    
    # Insert new appointment
    try:
        cursor = conn.execute("""
            INSERT INTO appointments (user_id, boat_id, service_type, description, scheduled_date, 
                                    assigned_employee_id, estimated_duration, cost, status, created_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (user_id, boat_id, service_type, description, scheduled_date, 
              assigned_employee_id, estimated_duration, cost, 'pending', datetime.datetime.now()))
        
        new_appointment_id = cursor.lastrowid
        conn.commit()
        
        # Log da atividade
        log_user_activity(session['user_id'], 'create_appointment', 'appointments', new_appointment_id, f'Criado agendamento: {service_type}')
        
        flash('Agendamento criado com sucesso!', 'success')
    except Exception as e:
        flash(f'Erro ao criar agendamento: {str(e)}', 'error')
    finally:
        conn.close()
    
    return redirect(url_for('admin_appointments'))

@app.route('/admin/financial')
@login_required
@role_required(['admin'])
def admin_financial():
    log_user_activity(session['user_id'], 'view_financial', 'financial_records', None, 'Visualização dos registros financeiros')
    
    conn = get_db_connection()
    financial_records = conn.execute("""
        SELECT f.*, u.name as user_name
        FROM financial_records f
        LEFT JOIN users u ON f.user_id = u.id
        ORDER BY f.created_at DESC
    """).fetchall()
    
    # Get associates for dropdown
    associates = conn.execute('SELECT id, name FROM users WHERE role = "associate" ORDER BY name').fetchall()
    
    conn.close()
    return render_template('admin/financial.html', financial_records=financial_records, associates=associates)

@app.route('/admin/financial/create', methods=['POST'])
@login_required
@role_required(['admin'])
def admin_financial_create():
    user_id = request.form.get('user_id', '')
    record_type = request.form.get('type', '')
    category = request.form.get('category', '')
    description = request.form.get('description', '').strip()
    amount = request.form.get('amount', '')
    due_date = request.form.get('due_date') or None
    payment_date = request.form.get('payment_date') or None
    status = request.form.get('status', 'pending')
    payment_method = request.form.get('payment_method', '')
    invoice_number = request.form.get('invoice_number', '').strip()
    notes = request.form.get('notes', '').strip()
    
    # Validações
    if not all([user_id, record_type, category, description, amount]):
        flash('Campos obrigatórios: Associado, Tipo, Categoria, Descrição e Valor!', 'error')
        return redirect(url_for('admin_financial'))
    
    conn = get_db_connection()
    
# Insert new financial record
    try:
        cursor = conn.execute("""
            INSERT INTO financial_records (user_id, type, category, description, amount, due_date, 
                                     payment_date, status, payment_method, invoice_number, notes, created_at)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    """, (user_id, record_type, category, description, amount, due_date, 
          payment_date, status, payment_method, invoice_number, notes, datetime.datetime.now()))
    
        new_record_id = cursor.lastrowid
        conn.commit()
    
        # Log da atividade
        log_user_activity(session['user_id'], 'create_financial_record', 'financial_records', new_record_id, f'Criado lançamento: {description}')
    
        flash('Lançamento financeiro criado com sucesso!', 'success')
    except Exception as e:
        flash(f'Erro ao criar lançamento: {str(e)}', 'error')
    finally:
        conn.close()
    
    return redirect(url_for('admin_financial'))

@app.route('/admin/employees')
@login_required
@role_required(['admin'])
def admin_employees():
    log_user_activity(session['user_id'], 'view_employees', 'users', None, 'Visualização da lista de funcionários')
    
    conn = get_db_connection()
    employees = conn.execute(
        'SELECT * FROM users WHERE role = "employee" ORDER BY name'
    ).fetchall()
    conn.close()
    return render_template('admin/employees.html', employees=employees)

@app.route('/admin/employees/create', methods=['POST'])
@login_required
@role_required(['admin'])
def admin_employees_create():
    name = request.form.get('name', '').strip()
    email = request.form.get('email', '').strip()
    password = request.form.get('password', '')
    cpf = request.form.get('cpf', '').strip()
    phone = request.form.get('phone', '').strip()
    address = request.form.get('address', '').strip()
    position = request.form.get('position', '')
    status = request.form.get('status', 'active')
    hire_date = request.form.get('hire_date') or None
    salary = request.form.get('salary') or None
    
    # Validações
    if not all([name, email, password, cpf, phone, address]):
        flash('Todos os campos obrigatórios devem ser preenchidos!', 'error')
        return redirect(url_for('admin_employees'))
    
    conn = get_db_connection()
    
    # Check if email already exists
    existing_user = conn.execute('SELECT * FROM users WHERE email = ?', (email,)).fetchone()
    if existing_user:
        flash('Email já cadastrado!', 'error')
        conn.close()
        return redirect(url_for('admin_employees'))
    
    # Insert new employee
    try:
        password_hash = hash_password(password)
        cursor = conn.execute("""
            INSERT INTO users (name, email, password, role, cpf, phone, address, status, created_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (name, email, password_hash, 'employee', cpf, phone, address, status, datetime.datetime.now()))
        
        new_employee_id = cursor.lastrowid
        conn.commit()
        
        # Log da atividade
        log_user_activity(session['user_id'], 'create_employee', 'users', new_employee_id, f'Criado funcionário: {name}')
        
        flash(f'Funcionário {name} cadastrado com sucesso!', 'success')
    except Exception as e:
        flash(f'Erro ao cadastrar funcionário: {str(e)}', 'error')
    finally:
        conn.close()
    
    return redirect(url_for('admin_employees'))

@app.route('/admin/reports')
@login_required
@role_required(['admin'])
def admin_reports():
    log_user_activity(session['user_id'], 'view_reports', 'reports', None, 'Visualização dos relatórios')
    
    conn = get_db_connection()
    
    # Get statistics for reports
    stats = {}
    stats['total_associates'] = conn.execute('SELECT COUNT(*) as count FROM users WHERE role = "associate"').fetchone()['count']
    stats['total_boats'] = conn.execute('SELECT COUNT(*) as count FROM boats').fetchone()['count']
    stats['occupied_berths'] = conn.execute('SELECT COUNT(*) as count FROM berths WHERE status = "occupied"').fetchone()['count']
    stats['total_berths'] = conn.execute('SELECT COUNT(*) as count FROM berths').fetchone()['count']
    stats['pending_appointments'] = conn.execute('SELECT COUNT(*) as count FROM appointments WHERE status = "pending"').fetchone()['count']
    
    conn.close()
    return render_template('admin/reports.html', stats=stats)

# Associate Routes - TODAS protegidas
@app.route('/associate/profile')
@login_required
@role_required(['associate'])
def associate_profile():
    log_user_activity(session['user_id'], 'view_profile', 'users', session['user_id'], 'Visualização do perfil')
    
    conn = get_db_connection()
    user = conn.execute('SELECT * FROM users WHERE id = ?', (session['user_id'],)).fetchone()
    boats = conn.execute('SELECT * FROM boats WHERE owner_id = ?', (session['user_id'],)).fetchall()
    conn.close()
    return render_template('associate/profile.html', user=user, boats=boats)

@app.route('/associate/appointments')
@login_required
@role_required(['associate'])
def associate_appointments():
    log_user_activity(session['user_id'], 'view_my_appointments', 'appointments', None, 'Visualização dos meus agendamentos')
    
    conn = get_db_connection()
    appointments = conn.execute("""
        SELECT a.*, b.name as boat_name, e.name as employee_name
        FROM appointments a
        LEFT JOIN boats b ON a.boat_id = b.id
        LEFT JOIN users e ON a.assigned_employee_id = e.id
        WHERE a.user_id = ?
        ORDER BY a.scheduled_date DESC
    """, (session['user_id'],)).fetchall()
    
    # Get user's boats for new appointment form
    boats = conn.execute("""
        SELECT id, name, type 
        FROM boats 
        WHERE owner_id = ? AND status = 'active'
        ORDER BY name
    """, (session['user_id'],)).fetchall()
    
    conn.close()
    return render_template('associate/appointments.html', appointments=appointments, boats=boats)

@app.route('/associate/appointments/create', methods=['POST'])
@login_required
@role_required(['associate'])
def associate_appointments_create():
    boat_id = request.form.get('boat_id') or None
    scheduled_date = request.form.get('scheduled_date', '')
    service_type = request.form.get('service_type', '')
    description = request.form.get('description', '').strip()
    estimated_duration = request.form.get('estimated_duration') or None
    priority = request.form.get('priority', 'normal')
    
    # Validações
    if not all([scheduled_date, service_type, description]):
        flash('Campos obrigatórios: Data/Hora, Tipo de Serviço e Descrição!', 'error')
        return redirect(url_for('associate_appointments'))
    
    # Verificar se a data é pelo menos 24h no futuro
    try:
        appointment_date = datetime.datetime.fromisoformat(scheduled_date)
        now = datetime.datetime.now()
        if appointment_date <= now + datetime.timedelta(hours=24):
            flash('Agendamentos devem ser feitos com pelo menos 24h de antecedência!', 'error')
            return redirect(url_for('associate_appointments'))
    except ValueError:
        flash('Data e hora inválidas!', 'error')
        return redirect(url_for('associate_appointments'))
    
    # Verificar se a embarcação pertence ao usuário (se especificada)
    if boat_id:
        conn = get_db_connection()
        boat = conn.execute(
            'SELECT * FROM boats WHERE id = ? AND owner_id = ?', 
            (boat_id, session['user_id'])
        ).fetchone()
        conn.close()
        
        if not boat:
            flash('Embarcação não encontrada ou não pertence a você!', 'error')
            return redirect(url_for('associate_appointments'))
    
    conn = get_db_connection()
    
    # Insert new appointment
    try:
        cursor = conn.execute("""
            INSERT INTO appointments (user_id, boat_id, service_type, description, scheduled_date, 
                                    estimated_duration, status, created_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        """, (session['user_id'], boat_id, service_type, description, scheduled_date, 
              estimated_duration, 'pending', datetime.datetime.now()))
        
        new_appointment_id = cursor.lastrowid
        conn.commit()
        
        # Log da atividade
        log_user_activity(session['user_id'], 'create_appointment', 'appointments', new_appointment_id, f'Criado agendamento: {service_type}')
        
        flash('Agendamento solicitado com sucesso! Aguarde a confirmação da marina.', 'success')
    except Exception as e:
        flash(f'Erro ao criar agendamento: {str(e)}', 'error')
    finally:
        conn.close()
    
    return redirect(url_for('associate_appointments'))

@app.route('/associate/financial')
@login_required
@role_required(['associate'])
def associate_financial():
    log_user_activity(session['user_id'], 'view_my_financial', 'financial_records', None, 'Visualização dos meus registros financeiros')
    
    conn = get_db_connection()
    
    # Obter registros financeiros do usuário
    financial_records = conn.execute("""
        SELECT * FROM financial_records 
        WHERE user_id = ?
        ORDER BY created_at DESC
    """, (session['user_id'],)).fetchall()
    
    # Obter informações do usuário
    user = conn.execute('SELECT * FROM users WHERE id = ?', (session['user_id'],)).fetchone()
    
    # Calcular totais
    pending_total = 0
    paid_total = 0
    overdue_total = 0
    
    # Data atual para verificar vencimentos
    current_date = datetime.datetime.now().date()
    
    # Calcular próximo vencimento
    next_due_date = None
    
    # Histórico de pagamentos (últimos 5)
    payment_history = conn.execute("""
        SELECT description, amount, payment_date as date
        FROM financial_records
        WHERE user_id = ? AND status = 'paid'
        ORDER BY payment_date DESC
        LIMIT 5
    """, (session['user_id'],)).fetchall()
    
    # Calcular totais e verificar vencimentos
    for record in financial_records:
        if record['status'] == 'pending':
            pending_total += record['amount']
            
            # Verificar se está vencido
            if record['due_date']:
                due_date = datetime.datetime.strptime(record['due_date'], '%Y-%m-%d').date()
                
                if due_date < current_date:
                    # Atualizar status para vencido
                    conn.execute("""
                        UPDATE financial_records
                        SET status = 'overdue'
                        WHERE id = ?
                    """, (record['id'],))
                    
                    overdue_total += record['amount']
                    pending_total -= record['amount']
                
                # Verificar próximo vencimento
                if not next_due_date or due_date < next_due_date:
                    next_due_date = due_date
        
        elif record['status'] == 'overdue':
            overdue_total += record['amount']
        
        elif record['status'] == 'paid':
            # Verificar se foi pago no último mês
            if record['payment_date']:
                payment_date = datetime.datetime.strptime(record['payment_date'], '%Y-%m-%d').date()
                one_month_ago = current_date - datetime.timedelta(days=30)
                
                if payment_date >= one_month_ago:
                    paid_total += record['amount']
    
    # Commit para salvar atualizações de status
    conn.commit()
    
    # Determinar status da conta
    account_status = 'regular'
    if overdue_total > 0:
        account_status = 'irregular'
    elif pending_total > 0:
        account_status = 'pending'
    
    # Valor mensal baseado no plano
    monthly_fee = 0
    if user:
        if user['plan'] == 'vaga_seca_mensal':
            monthly_fee = 800.00
        elif user['plan'] == 'vaga_molhada_mensal':
            monthly_fee = 1500.00
        elif user['plan'] == 'mensalista':
            monthly_fee = 300.00
    else:
        # Se o usuário não for encontrado, use valores padrão
        user = {
            'name': session.get('user_name', 'Usuário'),
            'plan': 'Não definido',
            'id': session.get('user_id')
        }
        flash('Não foi possível carregar os dados do usuário. Por favor, contate o administrador.', 'warning')
    
    # Formatar próximo vencimento
    if next_due_date:
        next_due_date = next_due_date.strftime('%d/%m/%Y')
    
    conn.close()
    
    return render_template(
        'associate/financial.html', 
        financial_records=financial_records,
        user=user,
        pending_total=pending_total,
        paid_total=paid_total,
        overdue_total=overdue_total,
        next_due_date=next_due_date,
        account_status=account_status,
        monthly_fee=monthly_fee,
        payment_history=payment_history
    )

@app.route('/associate/financial/pay', methods=['POST'])
@login_required
@role_required(['associate'])
def associate_financial_pay():
    record_id = request.form.get('record_id')
    payment_method = request.form.get('payment_method')
    
    if not record_id or not payment_method:
        flash('Informações de pagamento incompletas!', 'error')
        return redirect(url_for('associate_financial'))
    
    conn = get_db_connection()
    
    # Verificar se o registro existe e pertence ao usuário
    record = conn.execute(
        'SELECT * FROM financial_records WHERE id = ? AND user_id = ?', 
        (record_id, session['user_id'])
    ).fetchone()
    
    if not record:
        flash('Registro financeiro não encontrado ou não pertence a você!', 'error')
        conn.close()
        return redirect(url_for('associate_financial'))
    
    # Verificar se o registro já está pago
    if record['status'] == 'paid':
        flash('Este registro já está pago!', 'warning')
        conn.close()
        return redirect(url_for('associate_financial'))
    
    # Atualizar o registro para pago
    try:
        conn.execute("""
            UPDATE financial_records 
            SET status = 'paid', 
                payment_date = ?, 
                payment_method = ?
            WHERE id = ?
        """, (datetime.datetime.now().strftime('%Y-%m-%d'), payment_method, record_id))
        
        conn.commit()
        
        # Log da atividade
        log_user_activity(
            session['user_id'], 
            'payment', 
            'financial_records', 
            record_id, 
            f'Pagamento realizado: {record["description"]} - Método: {payment_method}'
        )
        
        flash('Pagamento registrado com sucesso! Nossa equipe irá confirmar em breve.', 'success')
    except Exception as e:
        flash(f'Erro ao processar pagamento: {str(e)}', 'error')
    finally:
        conn.close()
    
    return redirect(url_for('associate_financial'))

@app.route('/associate/documents')
@login_required
@role_required(['associate'])
def associate_documents():
    log_user_activity(session['user_id'], 'view_my_documents', 'documents', None, 'Visualização dos meus documentos')
    
    conn = get_db_connection()
    documents = conn.execute("""
        SELECT d.*, b.name as boat_name
        FROM documents d
        LEFT JOIN boats b ON d.boat_id = b.id
        WHERE d.user_id = ?
        ORDER BY d.uploaded_at DESC
    """, (session['user_id'],)).fetchall()
    
    # Get user's boats for document upload
    boats = conn.execute("""
        SELECT id, name, type 
        FROM boats 
        WHERE owner_id = ? AND status = 'active'
        ORDER BY name
    """, (session['user_id'],)).fetchall()
    
    conn.close()
    return render_template('associate/documents.html', documents=documents, boats=boats)

# Employee Routes - TODAS protegidas
@app.route('/employee/messages')
@login_required
@role_required(['employee'])
def employee_messages():
    log_user_activity(session['user_id'], 'view_my_messages', 'messages', None, 'Visualização das minhas mensagens')
    
    conn = get_db_connection()
    messages = conn.execute("""
        SELECT m.*, s.name as sender_name
        FROM messages m
        LEFT JOIN users s ON m.sender_id = s.id
        WHERE m.recipient_id = ? OR m.recipient_id IS NULL
        ORDER BY m.sent_at DESC
    """, (session['user_id'],)).fetchall()
    conn.close()
    return render_template('employee/messages.html', messages=messages)

# Messages Routes - TODAS protegidas
@app.route('/messages')
@login_required
def messages():
    log_user_activity(session['user_id'], 'view_messages', 'messages', None, 'Visualização das mensagens')
    
    conn = get_db_connection()
    
    if session['user_role'] == 'admin':
        messages = conn.execute("""
            SELECT m.*, 
                   s.name as sender_name, 
                   r.name as recipient_name
            FROM messages m
            LEFT JOIN users s ON m.sender_id = s.id
            LEFT JOIN users r ON m.recipient_id = r.id
            ORDER BY m.sent_at DESC
        """).fetchall()
    else:
        messages = conn.execute("""
            SELECT m.*, 
                   s.name as sender_name, 
                   r.name as recipient_name
            FROM messages m
            LEFT JOIN users s ON m.sender_id = s.id
            LEFT JOIN users r ON m.recipient_id = r.id
            WHERE m.sender_id = ? OR m.recipient_id = ? OR (m.recipient_id IS NULL AND ? = 'admin')
        """, (session['user_id'], session['user_id'], session['user_role'])).fetchall()
    
    # Obter usuários para o dropdown (para todos os tipos de usuário)
    users = conn.execute('SELECT id, name, role FROM users WHERE id != ? ORDER BY name', (session['user_id'],)).fetchall()
    
    conn.close()
    return render_template('messages/list.html', messages=messages, users=users)

@app.route('/messages/create', methods=['POST'])
@login_required
def messages_create():
    recipient_type = request.form.get('recipient_type', '')
    recipient_id = request.form.get('recipient_id') or None
    subject = request.form.get('subject', '').strip()
    content = request.form.get('content', '').strip()
    urgent = 'urgent' in request.form
    
    # Validações
    if not all([recipient_type, subject, content]):
        flash('Campos obrigatórios: Destinatário, Assunto e Mensagem!', 'error')
        return redirect(url_for('messages'))
    
    if recipient_type == 'specific' and not recipient_id:
        flash('Selecione um usuário específico!', 'error')
        return redirect(url_for('messages'))
    
    conn = get_db_connection()
    
    try:
        if recipient_type == 'specific' and recipient_id:
            # Send to specific user
            cursor = conn.execute("""
                INSERT INTO messages (sender_id, recipient_id, subject, content, status, sent_at)
                VALUES (?, ?, ?, ?, ?, ?)
            """, (session['user_id'], recipient_id, subject, content, 'unread', datetime.datetime.now()))
            
            message_id = cursor.lastrowid
            log_user_activity(session['user_id'], 'send_message', 'messages', message_id, f'Mensagem enviada para usuário específico: {subject}')
            
        elif recipient_type in ['all', 'associates', 'employees']:
            # Send to multiple users based on type
            if recipient_type == 'all':
                recipients = conn.execute('SELECT id FROM users WHERE id != ?', (session['user_id'],)).fetchall()
            elif recipient_type == 'associates':
                recipients = conn.execute('SELECT id FROM users WHERE role = "associate"').fetchall()
            elif recipient_type == 'employees':
                recipients = conn.execute('SELECT id FROM users WHERE role = "employee"').fetchall()
            
            message_count = 0
            for recipient in recipients:
                conn.execute("""
                    INSERT INTO messages (sender_id, recipient_id, subject, content, status, sent_at)
                    VALUES (?, ?, ?, ?, ?, ?)
                """, (session['user_id'], recipient['id'], subject, content, 'unread', datetime.datetime.now()))
                message_count += 1
            
            log_user_activity(session['user_id'], 'send_bulk_message', 'messages', None, f'Mensagem enviada para {message_count} usuários ({recipient_type}): {subject}')
        
        conn.commit()
        flash('Mensagem enviada com sucesso!', 'success')
    except Exception as e:
        flash(f'Erro ao enviar mensagem: {str(e)}', 'error')
    finally:
        conn.close()
    
    return redirect(url_for('messages'))

@app.route('/messages/<int:message_id>/mark-read', methods=['POST'])
@login_required
def mark_message_read(message_id):
    """Marcar mensagem como lida"""
    conn = get_db_connection()
    
    try:
        # Verificar se o usuário tem permissão para marcar esta mensagem como lida
        message = conn.execute("""
            SELECT * FROM messages 
            WHERE id = ? AND (recipient_id = ? OR sender_id = ? OR ? = 'admin')
        """, (message_id, session['user_id'], session['user_id'], session['user_role'])).fetchone()
        
        if not message:
            return jsonify({'success': False, 'error': 'Mensagem não encontrada ou sem permissão'})
        
        # Marcar como lida
        conn.execute("""
            UPDATE messages 
            SET status = 'read' 
            WHERE id = ? AND recipient_id = ?
        """, (message_id, session['user_id']))
        
        conn.commit()
        
        # Log da atividade
        log_user_activity(session['user_id'], 'mark_message_read', 'messages', message_id, f'Mensagem marcada como lida')
        
        return jsonify({'success': True})
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)})
    finally:
        conn.close()

# Error handlers
@app.errorhandler(404)
def not_found(error):
    """Página não encontrada - redireciona para login se não autenticado"""
    if 'user_id' not in session:
        flash('Página não encontrada. Faça login para continuar.', 'warning')
        return redirect(url_for('login'))
    else:
        flash('Página não encontrada.', 'error')
        return redirect(url_for('dashboard'))

@app.errorhandler(403)
def forbidden(error):
    """Acesso negado"""
    flash('Acesso negado! Você não tem permissão para acessar esta página.', 'error')
    return redirect(url_for('dashboard'))

@app.errorhandler(500)
def internal_error(error):
    """Erro interno do servidor"""
    flash('Erro interno do servidor. Tente novamente.', 'error')
    return redirect(url_for('dashboard'))

if __name__ == '__main__':
    if not os.path.exists('marina.db'):
        init_db()
    
    # Verificar e corrigir schema sempre que o app iniciar
    check_and_fix_schema()
    
    app.run(debug=True, host='0.0.0.0', port=5000)
