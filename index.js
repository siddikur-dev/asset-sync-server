const express = require("express");
const { MongoClient, ServerApiVersion, ObjectId } = require("mongodb");
const cors = require("cors");
require("dotenv").config();
const app = express();
const port = process.env.PORT || 3000;
const admin = require("firebase-admin");

// Initialize Stripe
const stripe = require("stripe")(process.env.PAYMENT_GATEWAY_KEY);

// Middleware
app.use(cors());
app.use(express.json());

// Firebase Admin Setup
const decodedKey = Buffer.from(process.env.FB_SERVICE_KEY, 'base64').toString('utf8');
const serviceAccount = JSON.parse(decodedKey);

admin.initializeApp({
  credential: admin.credential.cert(serviceAccount)
});

// MongoDB Setup
const client = new MongoClient(process.env.MONGODB_URI, {
  serverApi: {
    version: ServerApiVersion.v1,
    strict: true,
    deprecationErrors: true,
  },
});

async function run() {
  try {
    // Database Collections
    const db = client.db("AssetSyncDB");
    const usersCollection = db.collection("users");
    const assetsCollection = db.collection("assets");
    const requestsCollection = db.collection("requests");
    const employeeAffiliationsCollection = db.collection("employeeAffiliations");
    const packagesCollection = db.collection("packages");
    const paymentsCollection = db.collection("payments");

    // --- Custom Middlewares ---

    // 1. Verify Firebase Token
    const verifyToken = async (req, res, next) => {
      const authHeader = req.headers.authorization;
      if (!authHeader) {
        return res.status(401).send({ message: 'unauthorized access' });
      }
      const token = authHeader.split(' ')[1];
      if (!token) {
        return res.status(401).send({ message: 'unauthorized access' });
      }
      try {
        const decoded = await admin.auth().verifyIdToken(token);
        req.decoded = decoded;
        next();
      } catch (error) {
        return res.status(403).send({ message: 'forbidden access' });
      }
    };

    // 2. Verify HR Middleware (requires verifyToken first)
    const verifyHR = async (req, res, next) => {
      const email = req.decoded.email;
      const user = await usersCollection.findOne({ email });
      if (!user || user.role !== 'hr') {
        return res.status(403).send({ message: 'forbidden access' });
      }
      next();
    };

    // --- Routes ---

    // 1. Authentication & Users

    // POST /register
    app.post('/register', async (req, res) => {
      try {
        const { name, email, password, role, dateOfBirth, companyName, companyLogo } = req.body;

        if (!email || !role) {
          return res.status(400).json({ success: false, message: 'Email and role are required' });
        }

        const existingUser = await usersCollection.findOne({ email });
        if (existingUser) {
          return res.status(400).json({ success: false, message: 'User already exists' });
        }

        const newUser = {
          name,
          email,
          role, // 'hr' or 'employee'
          dateOfBirth,
          profileImage: '', // default
          createdAt: new Date(),
          updatedAt: new Date()
        };

        if (role === 'hr') {
          if (!companyName) {
            return res.status(400).json({ success: false, message: 'Company name is required for HR' });
          }
          newUser.companyName = companyName;
          newUser.companyLogo = companyLogo || '';
          newUser.packageLimit = 5; // Default package
          newUser.currentEmployees = 0;
          newUser.subscription = 'basic';
        } else if (role === 'employee') {
          // Employee starts unaffiliated. 
          // Note: "No companyName field - will be affiliated via requests"
        } else {
          return res.status(400).json({ success: false, message: 'Invalid role' });
        }

        const result = await usersCollection.insertOne(newUser);
        res.status(201).json({
          success: true,
          message: 'User registered successfully',
          user: { _id: result.insertedId, ...newUser }
        });
      } catch (error) {
        console.error('Registration error:', error);
        res.status(500).json({ success: false, message: 'Server error' });
      }
    });

    // GET /users/me -> Get current user info (using token)
    app.get('/users/me', verifyToken, async (req, res) => {
      try {
        const email = req.decoded.email;
        const user = await usersCollection.findOne({ email });
        if (!user) {
          return res.status(404).send({ message: 'User not found' });
        }
        res.send(user);
      } catch (error) {
        res.status(500).send({ message: 'Failed to fetch user' });
      }
    });

    // GET /users/:email -> Get user role/info
    app.get('/users/:email', async (req, res) => {
      try {
        const { email } = req.params;
        const user = await usersCollection.findOne({ email });
        if (!user) {
          return res.status(404).send({ message: 'User not found' });
        }
        res.send(user);
      } catch (error) {
        res.status(500).send({ message: 'Failed to fetch user' });
      }
    });

    // PUT /users/:id -> Update Profile
    app.put('/users/:id', verifyToken, async (req, res) => {
      const { id } = req.params;
      const { name, profileImage } = req.body;
      const result = await usersCollection.updateOne(
        { _id: new ObjectId(id) },
        { $set: { name, profileImage } }
      );
      res.send({ success: true, result });
    });


    // 2. Assets (HR Only)

    // GET /assets
    app.get('/assets', verifyToken, async (req, res) => {
      const { email, search, type } = req.query;

      let query = {};

      const requester = await usersCollection.findOne({ email: req.decoded.email });
      if (!requester) return res.status(404).send({ message: 'User not found' });

      if (requester.role === 'hr') {
        // HR sees their own assets
        query.hrEmail = req.decoded.email;
      } else {
        // Employee sees "Available" assets (quantity > 0)
        query.productQuantity = { $gt: 0 };
      }

      if (search) {
        query.productName = { $regex: search, $options: 'i' };
      }
      if (type) {
        query.productType = type;
      }

      const assets = await assetsCollection.find(query).toArray();
      res.send(assets);
    });

    // GET /assets/:id
    app.get('/assets/:id', async (req, res) => {
      const { id } = req.params;
      const asset = await assetsCollection.findOne({ _id: new ObjectId(id) });
      res.send(asset);
    });

    // POST /assets (HR Only)
    app.post('/assets', verifyToken, verifyHR, async (req, res) => {
      const asset = req.body;
      const user = await usersCollection.findOne({ email: req.decoded.email });

      const newAsset = {
        ...asset,
        productQuantity: parseInt(asset.productQuantity),
        dateAdded: new Date(),
        hrEmail: user.email,
        companyName: user.companyName
      };

      const result = await assetsCollection.insertOne(newAsset);
      res.send({ success: true, insertedId: result.insertedId });
    });

    // DELETE /assets/:id (HR Only)
    app.delete('/assets/:id', verifyToken, verifyHR, async (req, res) => {
      const { id } = req.params;
      const result = await assetsCollection.deleteOne({ _id: new ObjectId(id) });
      res.send(result);
    });

    // UPDATE ASSET (Step 1 A Actions: Edit)
    app.put('/assets/:id', verifyToken, verifyHR, async (req, res) => {
      const { id } = req.params;
      const updateData = req.body;
      delete updateData._id; // prevent id update
      const result = await assetsCollection.updateOne(
        { _id: new ObjectId(id) },
        { $set: updateData }
      );
      res.send(result);
    });


    // 3. Requests

    // POST /requests (Employee)
    app.post('/requests', verifyToken, async (req, res) => {
      const { assetId, note } = req.body;
      const requesterEmail = req.decoded.email;
      const requester = await usersCollection.findOne({ email: requesterEmail });

      const asset = await assetsCollection.findOne({ _id: new ObjectId(assetId) });
      if (!asset) return res.status(404).send({ message: 'Asset not found' });

      const newRequest = {
        assetId: new ObjectId(assetId),
        assetName: asset.productName,
        assetType: asset.productType,
        assetImage: asset.productImage,
        requesterName: requester.name,
        requesterEmail: requesterEmail,
        hrEmail: asset.hrEmail,
        companyName: asset.companyName,
        requestDate: new Date(),
        requestStatus: 'pending',
        note,
      };

      const result = await requestsCollection.insertOne(newRequest);
      res.send({ success: true, insertedId: result.insertedId });
    });

    // GET /requests (HR: all requests for their assets, Employee: their own requests)
    app.get('/requests', verifyToken, async (req, res) => {
      const { email } = req.query; // Filter query param
      const user = await usersCollection.findOne({ email: req.decoded.email });

      // Ensure user can only see their own relevant data
      let query = {};
      if (user.role === 'hr') {
        query.hrEmail = user.email;
      } else {
        query.requesterEmail = user.email;
      }

      const requests = await requestsCollection.find(query).toArray();
      res.send(requests);
    });

    // GET /my-assets (Employee)
    app.get('/my-assets', verifyToken, async (req, res) => {
      const email = req.decoded.email;
      const result = await requestsCollection.find({
        requesterEmail: email,
        requestStatus: { $in: ['approved', 'returned'] }
      }).toArray();
      res.send(result);
    });

    // PATCH /requests/:id (Modified to handle permissions inside)
    app.patch('/requests/:id', verifyToken, async (req, res) => {
      const { id } = req.params;
      const { status } = req.body; // 'approved', 'rejected', or 'returned'

      const request = await requestsCollection.findOne({ _id: new ObjectId(id) });
      if (!request) return res.status(404).send({ message: 'Request not found' });

      const user = await usersCollection.findOne({ email: req.decoded.email });

      // Permission Check:
      // If Status is 'returned', Requester OR HR can do it.
      // If Status is 'approved' or 'rejected', ONLY HR can do it.

      if (status === 'returned') {
        if (user.role !== 'hr' && request.requesterEmail !== user.email) {
          return res.status(403).send({ message: 'Forbidden access' });
        }
        // Logic for returning asset
        await requestsCollection.updateOne(
          { _id: new ObjectId(id) },
          { $set: { requestStatus: 'returned' } }
        );
        // Increment stock back
        await assetsCollection.updateOne(
          { _id: request.assetId },
          { $inc: { productQuantity: 1 } }
        );
        return res.send({ success: true });
      }

      // Allow ONLY HR for Approve/Reject
      if (user.role !== 'hr') {
        return res.status(403).send({ message: 'Forbidden access' });
      }

      if (status === 'approved') {
        // Check Package Limit for HR
        const hrUser = await usersCollection.findOne({ email: request.hrEmail });

        // Check affiliation status
        const isAffiliated = await employeeAffiliationsCollection.findOne({
          employeeEmail: request.requesterEmail,
          hrEmail: request.hrEmail
        });

        if (hrUser.currentEmployees >= hrUser.packageLimit && !isAffiliated) {
          return res.status(400).send({ message: 'Package limit reached. Please upgrade.' });
        }

        // Update Asset Quantity
        const asset = await assetsCollection.findOne({ _id: request.assetId });

        // If already approved, don't double count? 
        if (request.requestStatus === 'approved') {
          return res.status(400).send({ message: 'Already approved' });
        }

        // Check stock
        if (!asset || asset.productQuantity <= 0) {
          return res.status(400).send({ message: 'Out of stock' });
        }

        await assetsCollection.updateOne(
          { _id: request.assetId },
          { $inc: { productQuantity: -1 } }
        );

        // Create Affiliation if not exists
        if (!isAffiliated) {
          await employeeAffiliationsCollection.insertOne({
            employeeEmail: request.requesterEmail,
            employeeName: request.requesterName,
            hrEmail: request.hrEmail,
            companyName: request.companyName,
            companyLogo: hrUser.companyLogo,
            affiliationDate: new Date(),
            status: 'active'
          });

          // Increment HR employee count
          await usersCollection.updateOne(
            { email: request.hrEmail },
            { $inc: { currentEmployees: 1 } }
          );
        }

        // Update Request Status
        await requestsCollection.updateOne(
          { _id: new ObjectId(id) },
          {
            $set: {
              requestStatus: 'approved',
              approvalDate: new Date()
            }
          }
        );

      } else if (status === 'rejected') {
        await requestsCollection.updateOne(
          { _id: new ObjectId(id) },
          { $set: { requestStatus: 'rejected' } }
        );
      }

      res.send({ success: true });
    });


    // 4. Employee Affiliations 

    // GET /my-team (Employee) -> List users with same affiliation
    app.get('/my-team', verifyToken, async (req, res) => {
      const requesterEmail = req.decoded.email;
      // Find companies this employee is affiliated with
      const affiliations = await employeeAffiliationsCollection.find({ employeeEmail: requesterEmail }).toArray();
      if (affiliations.length === 0) {
        return res.send([]);
      }
      // For each company, get other employees
      const hrEmails = affiliations.map(a => a.hrEmail);

      // Find all affiliations for these HRs (i.e. colleagues)
      // We only want employees OF these HRs.
      const teamAffiliations = await employeeAffiliationsCollection.find({ hrEmail: { $in: hrEmails } }).toArray();

      // Enrich with user data (photo, name, birthday)
      const teamEmails = teamAffiliations.map(t => t.employeeEmail);
      const teamUsers = await usersCollection.find(
        { email: { $in: teamEmails } },
        { projection: { name: 1, email: 1, profileImage: 1, dateOfBirth: 1 } }
      ).toArray();

      res.send(teamUsers);
    });

    // GET /my-employees (HR) - UPDATED with metadata
    app.get('/my-employees', verifyToken, verifyHR, async (req, res) => {
      const hrEmail = req.decoded.email;
      const hrUser = await usersCollection.findOne({ email: hrEmail });

      const affiliations = await employeeAffiliationsCollection.find({ hrEmail }).toArray();
      const employeeEmails = affiliations.map(a => a.employeeEmail);

      const employees = await usersCollection.find(
        { email: { $in: employeeEmails } },
        { projection: { name: 1, email: 1, profileImage: 1, dateOfBirth: 1 } }
      ).toArray();

      // Merge data
      const result = employees.map(emp => {
        const aff = affiliations.find(a => a.employeeEmail === emp.email);
        return {
          _id: emp._id,
          employeeName: emp.name,
          employeeEmail: emp.email,
          employeeDetails: emp,
          affiliationDate: aff ? aff.affiliationDate : null,
          assetCount: 0 // TODO: query assigned assets count if needed
        };
      });

      res.send({
        employees: result,
        totalEmployees: result.length,
        packageLimit: hrUser.packageLimit || 5
      });
    });

    // DELETE /my-employees/:id (HR remove from team)
    app.delete('/my-employees/:id', verifyToken, verifyHR, async (req, res) => {
      const { id } = req.params; // this is the employee's USER ID
      const hrEmail = req.decoded.email;

      // 1. Find employee email
      const employeeUser = await usersCollection.findOne({ _id: new ObjectId(id) });
      if (!employeeUser) return res.status(404).send({ message: 'User not found' });

      // 2. Remove affiliation
      const deleteResult = await employeeAffiliationsCollection.deleteOne({
        employeeEmail: employeeUser.email,
        hrEmail: hrEmail
      });

      if (deleteResult.deletedCount > 0) {
        // 3. Decrement count
        await usersCollection.updateOne(
          { email: hrEmail },
          { $inc: { currentEmployees: -1 } }
        );
      }

      res.send({ success: true });
    });


    // 5. Packages
    // GET /packages 
    app.get('/packages', async (req, res) => {
      res.send([
        { name: "Basic", employeeLimit: 5, price: 5 },
        { name: "Standard", employeeLimit: 10, price: 8 },
        { name: "Premium", employeeLimit: 20, price: 15 }
      ]);
    });

    // POST /create-checkout-session (Stripe Hosted Checkout)
    app.post('/create-checkout-session', verifyToken, verifyHR, async (req, res) => {
      const { packageName, successUrl, cancelUrl } = req.body;

      // Define package details
      const packages = {
        'Basic': { price: 500, limit: 5 }, // amount in cents
        'Standard': { price: 800, limit: 10 },
        'Premium': { price: 1500, limit: 20 }
      };

      const pkg = packages[packageName];
      if (!pkg) return res.status(400).send({ message: 'Invalid package' });

      const session = await stripe.checkout.sessions.create({
        payment_method_types: ['card'],
        line_items: [
          {
            price_data: {
              currency: 'usd',
              product_data: {
                name: `${packageName} Package`,
                description: `Up to ${pkg.limit} employees`,
              },
              unit_amount: pkg.price,
            },
            quantity: 1,
          },
        ],
        mode: 'payment',
        success_url: successUrl.includes('{CHECKOUT_SESSION_ID}') ? successUrl : `${successUrl}&session_id={CHECKOUT_SESSION_ID}`,
        cancel_url: cancelUrl,
        metadata: {
          hrEmail: req.decoded.email,
          packageName: packageName,
          employeeLimit: pkg.limit
        }
      });

      res.send({ url: session.url });
    });

    // GET /payments/session/:sessionId (Verify Status)
    app.get('/payments/session/:sessionId', async (req, res) => {
      const { sessionId } = req.params;

      // Validate session ID format
      if (!sessionId || sessionId === '{CHECKOUT_SESSION_ID}') {
        return res.status(400).send({ message: 'Invalid session ID' });
      }

      try {
        const session = await stripe.checkout.sessions.retrieve(sessionId);

        if (session.payment_status === 'paid') {
          // Check if we already processed this
          const existingPayment = await paymentsCollection.findOne({ transactionId: sessionId });

          if (!existingPayment) {
            const hrEmail = session.metadata.hrEmail;
            const packageName = session.metadata.packageName;
            const employeeLimit = parseInt(session.metadata.employeeLimit);
            const amount = session.amount_total / 100;

            // Record Payment
            await paymentsCollection.insertOne({
              hrEmail,
              transactionId: sessionId,
              amount: amount,
              date: new Date(),
              packageName: packageName
            });

            // Update User Limit
            await usersCollection.updateOne(
              { email: hrEmail },
              { $set: { packageLimit: employeeLimit, subscription: packageName } }
            );
          }
          res.send({ status: 'completed', message: 'Payment successful' });
        } else {
          res.send({ status: session.payment_status, message: 'Payment not completed' });
        }

      } catch (error) {
        console.error('Session retrieval error:', error);
        res.status(500).send({ message: 'Failed to retrieve session' });
      }
    });

    // 6. Analytics (HR Only)
    app.get('/analytics', verifyToken, verifyHR, async (req, res) => {
      const hrEmail = req.decoded.email;

      // 1. Total Assets (HR's assets)
      const totalAssets = await assetsCollection.countDocuments({ hrEmail });

      // 2. Asset Distribution
      const returnable = await assetsCollection.countDocuments({ hrEmail, productType: 'Returnable' });
      const nonReturnable = await assetsCollection.countDocuments({ hrEmail, productType: 'Non-returnable' });

      // 3. Total Requests & Pending
      const totalRequests = await requestsCollection.countDocuments({ hrEmail });
      const pendingRequests = await requestsCollection.countDocuments({ hrEmail, requestStatus: 'pending' });

      // 4. Assigned Assets (Approved requests)
      // Note: Assigned means currently out with employees
      const totalAssigned = await requestsCollection.countDocuments({
        hrEmail,
        requestStatus: 'approved'
      });

      // 5. Top Requested Items
      const topRequested = await requestsCollection.aggregate([
        { $match: { hrEmail } },
        { $group: { _id: "$assetName", count: { $sum: 1 } } },
        { $sort: { count: -1 } },
        { $limit: 5 }
      ]).toArray();

      res.send({
        totalAssets,
        assetDistribution: { returnable, nonReturnable },
        requests: { total: totalRequests, pending: pendingRequests },
        totalAssigned,
        topRequestedAssets: topRequested
      });
    });

    // Ping
    app.get('/', (req, res) => {
      res.send('AssetVerse Server is running');
    });

  } catch (error) {
    console.error(error);
  }
}

run().catch(console.dir);


app.listen(port, () => {
  console.log(`AssetVerse is running on port ${port}`);
});
