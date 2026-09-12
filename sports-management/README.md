# S.D. Public School — SPORTS DEPARTMENT

GitHub/Render-ready Flask + SQLite school sports management system.

## Features
- Owner, Sports Teacher, House Teacher, Student roles
- Secure login + hashed passwords
- Student-only personal report card access
- House Teacher restricted to assigned house
- Student add/edit/remove
- Teacher creation/disable
- Change password + Forgot Password request + Owner reset
- No SMS/OTP
- School logo and 4 house logo uploads
- School/house names and final settings (Owner only)
- Events: Group A/B/C/D, Game/Sports, House VS House
- House-based results and championship scoreboard
- Student participation records
- Physical assessment: fitness, running, strength, flexibility, endurance, discipline, participation, remarks
- Annual function/sports records
- Certificates with print/save-PDF
- Student report card with photo, physical profile, assessment, participation and certificates
- Search and CSV export
- SQLite backup
- Owner audit log
- CSRF tokens on forms
- Production WSGI using Waitress
- Render deployment configuration

## Local run
python -m venv venv
Windows: venv\Scripts\activate
pip install -r requirements.txt
set SECRET_KEY=put-a-long-random-secret-here
python app.py

Open http://127.0.0.1:5000

Default Owner:
User ID: owner
Password: ChangeMe123!

Change this password immediately.

## GitHub + Render
1. Create a GitHub repository.
2. Upload all files/folders from this project.
3. On Render choose New Web Service and connect the repository.
4. Build command: pip install -r requirements.txt
5. Start command: waitress-serve --host=0.0.0.0 --port=$PORT app:app
6. Add SECRET_KEY environment variable with a long random value.
7. Deploy.

### Database note
SQLite is suitable for a small school deployment. On ephemeral hosting, persistent storage is required if you need the database/uploads to survive redeploys. For larger multi-user production use, migrate the database to PostgreSQL and use persistent object storage for photos/logos.

## Security note
The app includes role checks, password hashing, CSRF protection, secure session flags and upload validation. Production HTTPS, persistent storage, regular backups and strong SECRET_KEY are still required.
