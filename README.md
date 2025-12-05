# Ella Rises — INTEX Project

## Overview
**Ella Rises** is a full-stack web application built to support the mission of empowering young women through education and leadership programs.  
The system manages participants, events, donations, surveys, and milestones through a secure, role-based portal.

This project was developed as part of the **BYU Information Systems INTEX** capstone.

---

## Features

### Authentication
- Secure login and registration using **bcrypt** for password hashing.
- Session-based authentication with `express-session` and `connect-pg-simple` for persistent logins.
- Role-based access control (Admin / User).

### Participant Management
- Admins can view, add, edit, and delete participants.
- Users can view and update their own profile information.
- All data is stored in a normalized PostgreSQL database.

### Event Management
- Events are stored in two linked tables: `master_events` and `event_instances`.
- Event listings include name, type, description, date/time, and capacity.
- Supports filtering and pagination.

### Donation Tracking
- Tracks donor contributions linked to user accounts.
- Supports both **registered users** and **guest donors**.
- Admins can add, edit, and delete donations.
- Each donation displays donor name, ID, amount, and date.

### Milestones
- Admins can assign and track participant milestones (e.g., program completions).
- Lists all completed milestones per user with dates and titles.

### Surveys
- Event-based surveys tied to user registrations.
- Tracks satisfaction and feedback data.
- Admin and user-specific views.

### Dashboard
- Displays high-level statistics including:
  - Total participants
  - Number of admins
  - Total donations
  - Regular user count
- Provides quick links to manage system areas.

---

## Tech Stack

| Layer | Technologies |
|-------|---------------|
| **Frontend** | HTML, CSS, EJS Templates |
| **Backend** | Node.js, Express |
| **Database** | PostgreSQL |
| **Authentication** | `bcrypt`, `express-session`, `connect-pg-simple` |
| **Hosting / Deployment** | Localhost (dev) or AWS RDS (optional) |

---

## ⚙️ Environment Setup

### 1. Install Dependencies
```bash
npm install

DB_HOST=localhost
DB_PORT=5433
DB_USER=postgres
DB_PASSWORD=admin
DB_NAME=pokemon_db
SESSION_SECRET=pokemon
PORT=3000


