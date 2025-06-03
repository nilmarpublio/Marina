from app import app, init_db
import os

if __name__ == '__main__':
    # Initialize database if it doesn't exist
    if not os.path.exists('marina.db'):
        init_db()
        print("Database initialized successfully!")
    
    print("Starting Marina Management System...")
    print("Access the system at: http://localhost:5000")
    print("Default admin login:")
    print("Email: admin@marina.com")
    print("Password: admin123")
    
    app.run(debug=True, host='0.0.0.0', port=5000)
