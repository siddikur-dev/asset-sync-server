# Asset Sync Server

AssetSync is a smart digital system designed to help companies manage all their physical assets—such as laptops, keyboards, monitors, chairs, and more—while keeping track of which employee is using which item.
It eliminates the confusion, manual paperwork, and asset-loss issues often faced by growing organizations.

---

## 🌟 Features

- **RESTful API** for all platform resources (users, sessions, materials, bookings, etc.)
- **Role-Based Access Control** for admin, tutor, and student
- **Authentication & Authorization** (JWT, Firebase, or custom)
- **Session & Booking Management**
- **Material Upload & Download**
- **Statistics & Analytics Endpoints**
- **Payment Integration (Stripe)**
- **Announcements & Notifications**
- **Secure Middleware** for validation and error handling

---

## 🛠️ Main Packages Used

| Package         | Purpose/Description                        |
| -------------- | ------------------------------------------ |
| **express**    | Web server framework for Node.js           |
| **cors**       | Enable Cross-Origin Resource Sharing        |
| **dotenv**     | Environment variable management            |
| **jsonwebtoken** | JWT authentication and authorization     |
| **firebase-admin** | Firebase admin SDK for server-side ops |
| **stripe**     | Stripe payment integration                 |
| **multer**     | File upload handling                       |
| **mongoose**   | MongoDB object modeling (if using MongoDB) |
| **nodemailer** | Sending emails (notifications, etc.)       |
| **bcryptjs**   | Password hashing and security              |

---

## 🚀 Getting Started

### 1. Clone the Repository

```bash
git clone https://github.com/your-username/edu-sync-server.git
cd edu-sync-server
```

### 2. Install Dependencies

```bash
npm install
```

### 3. Environment Variables

Create a `.env` file in the root directory and add your environment-specific variables (e.g., database URI, JWT secret, Stripe keys, Firebase credentials).

### 4. Start the Server

```bash
npm start
```

The server will run on the port specified in your `.env` file (default: 5000).

---

## 📁 Project Structure

```
edu-sync-server/
  ├── middleware/        # Custom middleware (auth, error handling, etc.)
  ├── routes/            # API route handlers
  ├── controllers/       # Business logic for each resource
  ├── models/            # Database models/schemas
  ├── utils/             # Utility functions
  ├── index.js           # Server entry point
  └── ...
```

---

## 👨‍💻 Developer & Contact

- **Portfolio:** [siddikur-dev.web.app](https://siddikur-dev.web.app/)
- **LinkedIn:** [linkedin.com/in/siddikur-dev](https://www.linkedin.com/in/siddikur-dev/)

---

## 📄 License

This project is licensed under the MIT License.

---

> **Asset
Sync Server** – Powering the Edu Sync platform backend.
