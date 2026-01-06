This is a comprehensive implementation of the Project Management System backend. It follows the standard MVC (Model-View-Controller) pattern with Express, Mongoose, and JWT.

### Folder Structure
```text
pms-backend/
├── config/
│   └── db.js
├── controllers/
│   ├── authController.js
│   ├── userController.js
│   ├── teamController.js
│   └── reportController.js
├── middlewares/
│   ├── authMiddleware.js
│   └── roleMiddleware.js
├── models/
│   ├── User.js
│   ├── Team.js
│   ├── Report.js
│   └── Project.js
├── routes/
│   ├── authRoutes.js
│   ├── userRoutes.js
│   ├── teamRoutes.js
│   └── reportRoutes.js
├── .env
├── app.js
└── server.js
```

### 1. Database Configuration (`config/db.js`)
```javascript
const mongoose = require('mongoose');

const connectDB = async () => {
    try {
        await mongoose.connect(process.env.MONGO_URI);
        console.log('MongoDB Connected...');
    } catch (err) {
        console.error(err.message);
        process.exit(1);
    }
};

module.exports = connectDB;
```

### 2. Models

#### User Model (`models/User.js`)
```javascript
const mongoose = require('mongoose');
const bcrypt = require('bcryptjs');

const UserSchema = new mongoose.Schema({
    name: { type: String, required: true },
    email: { type: String, required: true, unique: true },
    password: { type: String, required: true },
    role: { 
        type: String, 
        enum: ['admin', 'manager', 'team leader', 'dev', 'jrDev'], 
        default: 'jrDev' 
    },
    isActive: { type: Boolean, default: true },
    teamId: { type: mongoose.Schema.Types.ObjectId, ref: 'Team' }
}, { timestamps: true });

UserSchema.pre('save', async function(next) {
    if (!this.isModified('password')) next();
    this.password = await bcrypt.hash(this.password, 10);
});

module.exports = mongoose.model('User', UserSchema);
```

#### Report Model (`models/Report.js`)
```javascript
const mongoose = require('mongoose');

const ReportSchema = new mongoose.Schema({
    title: { type: String, required: true },
    content: { type: String, required: true },
    status: { 
        type: String, 
        enum: ['Pending', 'Approved', 'Rework'], 
        default: 'Pending' 
    },
    createdBy: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
    teamId: { type: mongoose.Schema.Types.ObjectId, ref: 'Team', required: true },
    feedback: { type: String }
}, { timestamps: true });

module.exports = mongoose.model('Report', ReportSchema);
```

### 3. Middlewares

#### Auth Middleware (`middlewares/authMiddleware.js`)
```javascript
const jwt = require('jsonwebtoken');
const User = require('../models/User');

const protect = async (req, res, next) => {
    let token;
    if (req.headers.authorization && req.headers.authorization.startsWith('Bearer')) {
        try {
            token = req.headers.authorization.split(' ')[1];
            const decoded = jwt.verify(token, process.env.JWT_SECRET);
            req.user = await User.findById(decoded.id).select('-password');
            
            if (!req.user.isActive) {
                return res.status(401).json({ message: 'User account is deactivated' });
            }
            next();
        } catch (error) {
            res.status(401).json({ message: 'Not authorized, token failed' });
        }
    }
    if (!token) res.status(401).json({ message: 'No token, authorization denied' });
};

module.exports = { protect };
```

#### Role Middleware (`middlewares/roleMiddleware.js`)
```javascript
const authorize = (...roles) => {
    return (req, res, next) => {
        if (!roles.includes(req.user.role)) {
            return res.status(403).json({ 
                message: `Role ${req.user.role} is not authorized to access this route` 
            });
        }
        next();
    };
};

module.exports = { authorize };
```

### 4. Controllers (Key Logic)

#### Report Controller (`controllers/reportController.js`)
This controller contains the logic for the specific access rules you mentioned.
```javascript
const Report = require('../models/Report');

// Create Report (Dev and JrDev)
exports.createReport = async (req, res) => {
    try {
        const { title, content } = req.body;
        const report = await Report.create({
            title,
            content,
            createdBy: req.user._id,
            teamId: req.user.teamId
        });
        res.status(201).json(report);
    } catch (error) {
        res.status(500).json({ message: error.message });
    }
};

// Get Reports based on Role logic
exports.getReports = async (req, res) => {
    try {
        let query = {};

        if (req.user.role === 'admin' || req.user.role === 'manager') {
            // Admin & Manager see everything
            query = {};
        } else if (req.user.role === 'team leader' || req.user.role === 'dev') {
            // See reports of their own team
            query = { teamId: req.user.teamId };
        } else {
            // JrDev sees only their own
            query = { createdBy: req.user._id };
        }

        const reports = await Report.find(query).populate('createdBy', 'name role');
        res.json(reports);
    } catch (error) {
        res.status(500).json({ message: error.message });
    }
};

// Review Report (TL can ask for rework, Dev can review JrDev)
exports.updateReportStatus = async (req, res) => {
    const { status, feedback } = req.body;
    try {
        const report = await Report.findById(req.params.id).populate('createdBy');
        
        // Logic: Dev can only review JrDev
        if (req.user.role === 'dev' && report.createdBy.role !== 'jrDev') {
            return res.status(403).json({ message: 'Devs can only review JrDev reports' });
        }

        report.status = status || report.status;
        report.feedback = feedback || report.feedback;
        await report.save();
        
        res.json(report);
    } catch (error) {
        res.status(500).json({ message: error.message });
    }
};
```

### 5. Routes

#### Report Routes (`routes/reportRoutes.js`)
```javascript
const express = require('express');
const router = express.Router();
const { createReport, getReports, updateReportStatus } = require('../controllers/reportController');
const { protect } = require('../middlewares/authMiddleware');
const { authorize } = require('../middlewares/roleMiddleware');

router.route('/')
    .post(protect, authorize('dev', 'jrDev'), createReport)
    .get(protect, getReports);

router.route('/:id')
    .put(protect, authorize('admin', 'team leader', 'dev'), updateReportStatus);

module.exports = router;
```

#### User Routes (`routes/userRoutes.js`)
```javascript
const express = require('express');
const router = express.Router();
const User = require('../models/User');
const { protect } = require('../middlewares/authMiddleware');
const { authorize } = require('../middlewares/roleMiddleware');

// Admin only: Deactivate/Activate user
router.put('/:id/status', protect, authorize('admin'), async (req, res) => {
    const user = await User.findById(req.params.id);
    user.isActive = req.body.isActive;
    await user.save();
    res.json({ message: `User status updated to ${user.isActive}` });
});

// Admin: Reset Password
router.put('/:id/reset-password', protect, authorize('admin'), async (req, res) => {
    const user = await User.findById(req.params.id);
    user.password = req.body.newPassword; // Will be hashed by pre-save hook
    await user.save();
    res.json({ message: 'Password reset successfully' });
});

module.exports = router;
```

### 6. App Entry Point (`app.js`)
```javascript
require('dotenv').config();
const express = require('express');
const connectDB = require('./config/db');

connectDB();

const app = express();
app.use(express.json());

// Routes
app.use('/api/auth', require('./routes/authRoutes'));
app.use('/api/users', require('./routes/userRoutes'));
app.use('/api/reports', require('./routes/reportRoutes'));
app.use('/api/teams', require('./routes/teamRoutes'));

const PORT = process.env.PORT || 5000;
app.listen(PORT, () => console.log(`Server running on port ${PORT}`));
```

### 7. Environment Variables (`.env`)
```text
PORT=5000
MONGO_URI=mongodb://localhost:27017/pms_db
JWT_SECRET=your_super_secret_key_123
```

### Key Logic Implementation Summary:
1.  **Admin Access:** Can access `userRoutes` to activate/deactivate and reset passwords. In `reportController`, the `getReports` query is empty `{}` to show all.
2.  **Manager Access:** In `teamRoutes` (not fully coded above but implied), the Manager would have access to assign `teamId` to Users.
3.  **Team Leader (TL):** The `getReports` function filters by `teamId`. The `authorize` middleware allows TL to update report status (Rework).
4.  **Dev:** Can create reports. In `updateReportStatus`, a check is added to ensure they can only review reports where the creator is a `jrDev`.
5.  **JrDev:** Restricted via `authorize` middleware to only create/view. `getReports` filters by `createdBy: req.user._id`.
6.  **Auth:** `protect` middleware ensures the user is logged in and their `isActive` flag is true.
