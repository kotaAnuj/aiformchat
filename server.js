// server.js

/**
 * Upgraded Express server with Google Forms/Sheets integration,
 * Firebase authentication/token verification, logging, Swagger documentation,
 * and a new chat endpoint to dynamically generate resources based on user input.
 * 
 * Required packages:
 * express, cors, googleapis, @google/generative-ai, firebase-admin, path, dotenv,
 * express-rate-limit, express-validator, winston, morgan, swagger-jsdoc, swagger-ui-express.
 */

const express = require('express');
const cors = require('cors');
const { google } = require('googleapis');
const { GoogleGenerativeAI } = require("@google/generative-ai");
const admin = require('firebase-admin');
const path = require('path');
const rateLimit = require('express-rate-limit');
const { body, validationResult } = require('express-validator');
const winston = require('winston');
const morgan = require('morgan');
const swaggerJsdoc = require('swagger-jsdoc');
const swaggerUi = require('swagger-ui-express');
require('dotenv').config();

// =============================================
// Logger Setup using Winston
// =============================================
const logger = winston.createLogger({
  level: 'info',
  format: winston.format.combine(
    winston.format.timestamp(),
    winston.format.json()
  ),
  transports: [new winston.transports.Console()]
});

// =============================================
// Firebase Admin Initialization using serviceAccountKey.json
// =============================================
const serviceAccount = require('./nothing-d3af4-firebase-adminsdk-gu32b-c5f1c1120e.json');
admin.initializeApp({
  credential: admin.credential.cert(serviceAccount),
  // Use Firestore – no databaseURL needed for Firestore logging.
  // If you still need the realtime database for other parts, include it here.
  databaseURL: process.env.FIREBASE_DATABASE_URL
});

// =============================================
// Express App Configuration
// =============================================
const app = express();
app.use(cors());
app.use(express.json());
app.use(express.static('public'));

// =============================================
// Request Logging using Morgan integrated with Winston
// =============================================
app.use(morgan('combined', { stream: { write: message => logger.info(message.trim()) } }));

// =============================================
// Rate Limiting Middleware
// =============================================
const limiter = rateLimit({
  windowMs: 60 * 1000, // 1 minute
  max: 100 // Limit each IP to 100 requests per minute
});
app.use(limiter);

// =============================================
// Swagger API Documentation Setup
// =============================================
const PORT = process.env.PORT || 3000;
const swaggerOptions = {
  swaggerDefinition: {
    openapi: '3.0.0',
    info: {
      title: 'Google Form & Sheet Generator API',
      version: '1.0.0',
      description: 'API documentation for the form and sheet generation service'
    },
    servers: [
      {
        url: `http://localhost:${PORT}`,
        description: 'Local server'
      }
    ],
    components: {
      securitySchemes: {
        bearerAuth: {
          type: 'http',
          scheme: 'bearer',
          bearerFormat: 'JWT'
        }
      }
    },
    security: [{
      bearerAuth: []
    }]
  },
  apis: ['./server.js']
};

const swaggerSpec = swaggerJsdoc(swaggerOptions);
app.use('/api-docs', swaggerUi.serve, swaggerUi.setup(swaggerSpec));

// =============================================
// Gemini AI Initialization
// =============================================
const genAI = new GoogleGenerativeAI(process.env.GEMINI_API_KEY);
const model = genAI.getGenerativeModel({ model: "gemini-pro" });

// =============================================
// Google Auth Configuration
// =============================================
const googleCredentials = {
  type: "service_account",
  project_id: process.env.GOOGLE_PROJECT_ID,
  private_key_id: process.env.GOOGLE_PRIVATE_KEY_ID,
  // Convert literal "\n" sequences into newlines if needed.
  private_key: process.env.GOOGLE_PRIVATE_KEY.replace(/\\n/g, '\n'),
  client_email: process.env.GOOGLE_CLIENT_EMAIL,
  client_id: process.env.GOOGLE_CLIENT_ID,
  auth_uri: process.env.GOOGLE_AUTH_URI,
  token_uri: process.env.GOOGLE_TOKEN_URI,
  auth_provider_x509_cert_url: process.env.GOOGLE_AUTH_PROVIDER_X509_CERT_URL,
  client_x509_cert_url: process.env.GOOGLE_CLIENT_X509_CERT_URL
};

const auth = new google.auth.GoogleAuth({
  credentials: googleCredentials,
  scopes: [
    'https://www.googleapis.com/auth/forms',
    'https://www.googleapis.com/auth/drive',
    'https://www.googleapis.com/auth/drive.file',
    'https://www.googleapis.com/auth/spreadsheets'
  ]
});

const sheets = google.sheets({ version: 'v4', auth });

// =============================================
// Helper Functions
// =============================================

/**
 * Generates a Google Form structure based on a description using Gemini AI.
 */
async function generateFormStructure(description) {
  try {
    const prompt = `Generate a Google Form structure based on this description: "${description}".
Return a JSON object (and nothing else) with exactly this structure:
{
    "title": "appropriate form title",
    "description": "brief form description",
    "questions": [
        {
            "title": "question text",
            "type": "TEXT or MULTIPLE_CHOICE",
            "required": true or false,
            "options": ["option1", "option2"] (include only for MULTIPLE_CHOICE)
        }
    ]
}`;
    const result = await model.generateContent(prompt);
    const response = await result.response;
    const text = response.text();
    const cleanedText = text.replace(/```json\n?/g, '').replace(/```\n?/g, '');
    const jsonMatch = cleanedText.match(/\{[\s\S]*\}/);
    if (!jsonMatch) {
      throw new Error('Invalid AI response format');
    }
    const formStructure = JSON.parse(jsonMatch[0]);
    logger.info('Form structure generated successfully');
    return formStructure;
  } catch (error) {
    logger.error('Gemini API Error:', error);
    throw new Error(`Failed to generate form structure: ${error.message}`);
  }
}

/**
 * Creates a Google Form based on the provided form data.
 * Optionally grants write permission to a given user email.
 */
async function createGoogleForm(formData, userEmail) {
  try {
    const forms = google.forms({ version: 'v1', auth });
    const drive = google.drive({ version: 'v3', auth });
    logger.info('Creating form with title:', formData.title);
    const form = await forms.forms.create({
      requestBody: { info: { title: formData.title } }
    });
    const formId = form.data.formId;
    const batchUpdateRequest = { requests: [] };
    if (formData.description) {
      batchUpdateRequest.requests.push({
        updateFormInfo: {
          info: { description: formData.description },
          updateMask: 'description'
        }
      });
    }
    formData.questions.forEach((question, index) => {
      batchUpdateRequest.requests.push({
        createItem: {
          item: {
            title: question.title,
            questionItem: {
              question: {
                required: question.required ?? false,
                textQuestion: question.type === 'TEXT' ? {} : undefined,
                choiceQuestion: question.type === 'MULTIPLE_CHOICE' ? {
                  options: question.options.map(opt => ({ value: opt })),
                  type: 'RADIO'
                } : undefined
              }
            }
          },
          location: { index }
        }
      });
    });
    await forms.forms.batchUpdate({ formId, requestBody: batchUpdateRequest });
    if (userEmail) {
      await drive.permissions.create({
        fileId: formId,
        requestBody: {
          role: 'writer',
          type: 'user',
          emailAddress: userEmail
        },
        sendNotificationEmail: false
      });
    }
    logger.info(`Form created successfully: ${formId}`);
    return `https://docs.google.com/forms/d/${formId}/viewform`;
  } catch (error) {
    logger.error('Form creation error:', error.response?.data || error);
    throw new Error(`Failed to create Google Form: ${error.message}`);
  }
}

/**
 * Creates a Google Sheet and returns its URL.
 */
async function createGoogleSheet(sheetTitle) {
  try {
    const resource = {
      properties: { title: sheetTitle }
    };
    const response = await sheets.spreadsheets.create({ requestBody: resource });
    const sheetId = response.data.spreadsheetId;
    logger.info(`Sheet created successfully: ${sheetId}`);
    return `https://docs.google.com/spreadsheets/d/${sheetId}/edit`;
  } catch (error) {
    logger.error('Sheet creation error:', error.response?.data || error);
    throw new Error(`Failed to create Google Sheet: ${error.message}`);
  }
}

/**
 * Links the Google Form to the Google Sheet (for form responses).
 * (This is a placeholder – linking is often managed via the Forms UI or triggers.)
 */
async function linkFormToSheet(formId, sheetId) {
  try {
    logger.info(`Linking Form ${formId} to Sheet ${sheetId}`);
    // Implement the actual linking logic as needed.
    return true;
  } catch (error) {
    logger.error('Error linking form to sheet:', error);
    throw new Error(`Failed to link Form and Sheet: ${error.message}`);
  }
}

/**
 * Logs form creation details into Firestore.
 */
async function logFormCreation(userUid, logData) {
  try {
    const db = admin.firestore();
    await db.collection('forms').add({
      userUid,
      title: logData.title,
      formUrl: logData.formUrl,
      sheetUrl: logData.sheetUrl || null,
      createdAt: admin.firestore.FieldValue.serverTimestamp()
    });
    logger.info(`Logged form creation for user ${userUid}`);
  } catch (error) {
    logger.error('Error logging form creation:', error);
  }
}

// =============================================
// Firebase Token Verification Middleware
// =============================================
const verifyFirebaseToken = async (req, res, next) => {
  const authHeader = req.headers.authorization;
  if (!authHeader || !authHeader.startsWith('Bearer ')) {
    return res.status(401).json({ success: false, error: 'No token provided' });
  }
  const token = authHeader.split('Bearer ')[1];
  try {
    const decodedToken = await admin.auth().verifyIdToken(token);
    req.user = decodedToken;
    next();
  } catch (error) {
    logger.error('Token verification error:', error);
    res.status(401).json({ success: false, error: 'Invalid token' });
  }
};

// =============================================
// API Endpoints
// =============================================

/**
 * @swagger
 * /health:
 *   get:
 *     summary: Health check endpoint.
 *     responses:
 *       200:
 *         description: Server is running.
 */
app.get('/health', (req, res) => {
  res.json({ status: 'ok', time: new Date().toISOString() });
});

/**
 * @swagger
 * /api/generate-form:
 *   post:
 *     summary: Generate a Google Form using Gemini AI.
 *     security:
 *       - bearerAuth: []
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             properties:
 *               description:
 *                 type: string
 *               userEmail:
 *                 type: string
 *     responses:
 *       200:
 *         description: Form created successfully.
 *       400:
 *         description: Invalid request.
 *       500:
 *         description: Server error.
 */
app.post(
  '/api/generate-form',
  verifyFirebaseToken,
  body('description').notEmpty().withMessage('Description is required'),
  async (req, res, next) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json({ success: false, errors: errors.array() });
    }
    try {
      const { description, userEmail } = req.body;
      const formStructure = await generateFormStructure(description);
      const formUrl = await createGoogleForm(formStructure, userEmail);
      await logFormCreation(req.user.uid, { title: formStructure.title, formUrl });
      res.json({ success: true, url: formUrl, title: formStructure.title });
    } catch (error) {
      next(error);
    }
  }
);

/**
 * @swagger
 * /api/generate-form-sheet:
 *   post:
 *     summary: Generate a Google Form and create a linked Google Sheet.
 *     security:
 *       - bearerAuth: []
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             properties:
 *               description:
 *                 type: string
 *               userEmail:
 *                 type: string
 *     responses:
 *       200:
 *         description: Form and Sheet created successfully.
 *       400:
 *         description: Invalid request.
 *       500:
 *         description: Server error.
 */
app.post(
  '/api/generate-form-sheet',
  verifyFirebaseToken,
  body('description').notEmpty().withMessage('Description is required'),
  async (req, res, next) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json({ success: false, errors: errors.array() });
    }
    try {
      const { description, userEmail } = req.body;
      const formStructure = await generateFormStructure(description);
      const formUrl = await createGoogleForm(formStructure, userEmail);
      const sheetTitle = `${formStructure.title} Responses`;
      const sheetUrl = await createGoogleSheet(sheetTitle);
      await linkFormToSheet(formUrl.split('/d/')[1], sheetUrl.split('/d/')[1]);
      await logFormCreation(req.user.uid, { title: formStructure.title, formUrl, sheetUrl });
      res.json({
        success: true,
        formUrl,
        sheetUrl,
        title: formStructure.title
      });
    } catch (error) {
      next(error);
    }
  }
);

/**
 * @swagger
 * /api/forms:
 *   get:
 *     summary: Retrieve all forms created by the authenticated user.
 *     security:
 *       - bearerAuth: []
 *     responses:
 *       200:
 *         description: A list of forms.
 *       401:
 *         description: Unauthorized.
 *       500:
 *         description: Server error.
 */
app.get('/api/forms', verifyFirebaseToken, async (req, res, next) => {
  try {
    const db = admin.firestore();
    const formsSnapshot = await db.collection('forms').where('userUid', '==', req.user.uid).get();
    const forms = {};
    formsSnapshot.forEach(doc => {
      forms[doc.id] = doc.data();
    });
    res.json({ success: true, forms });
  } catch (error) {
    next(error);
  }
});

/**
 * @swagger
 * /api/chat:
 *   post:
 *     summary: Chat with the AI to generate dynamic Google Form/Sheet based on your requirements.
 *     security:
 *       - bearerAuth: []
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             properties:
 *               message:
 *                 type: string
 *               userEmail:
 *                 type: string
 *     responses:
 *       200:
 *         description: Chat response with generated link.
 *       400:
 *         description: Invalid request.
 *       500:
 *         description: Server error.
 */
app.post(
  '/api/chat',
  verifyFirebaseToken,
  body('message').notEmpty().withMessage('Message is required'),
  async (req, res, next) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json({ success: false, errors: errors.array() });
    }
    try {
      const { message, userEmail } = req.body;
      const prompt = `You are an intelligent assistant. Based on the following user request:
"${message}"
Determine if the user wants to generate a Google Form, a Google Sheet, or both. 
Return a JSON object with exactly these keys:
{
  "command": "generateForm", "generateFormSheet", or "generateSheet",
  "description": "A refined description for the task."
}
Only output the JSON object and nothing else.`;
      
      const result = await model.generateContent(prompt);
      const response = await result.response;
      const text = response.text();
      const cleanedText = text.replace(/```json\n?/g, '').replace(/```\n?/g, '');
      const jsonMatch = cleanedText.match(/\{[\s\S]*\}/);
      if (!jsonMatch) {
        throw new Error('Invalid AI chat response format');
      }
      const chatCommand = JSON.parse(jsonMatch[0]);
      
      let resultData = {};
      if (chatCommand.command === "generateForm") {
        const formStructure = await generateFormStructure(chatCommand.description);
        const formUrl = await createGoogleForm(formStructure, userEmail);
        await logFormCreation(req.user.uid, { title: formStructure.title, formUrl });
        resultData = { success: true, type: "form", url: formUrl, title: formStructure.title };
      } else if (chatCommand.command === "generateFormSheet") {
        const formStructure = await generateFormStructure(chatCommand.description);
        const formUrl = await createGoogleForm(formStructure, userEmail);
        const sheetTitle = `${formStructure.title} Responses`;
        const sheetUrl = await createGoogleSheet(sheetTitle);
        await linkFormToSheet(formUrl.split('/d/')[1], sheetUrl.split('/d/')[1]);
        await logFormCreation(req.user.uid, { title: formStructure.title, formUrl, sheetUrl });
        resultData = { success: true, type: "formSheet", formUrl, sheetUrl, title: formStructure.title };
      } else if (chatCommand.command === "generateSheet") {
        const sheetUrl = await createGoogleSheet(chatCommand.description);
        await logFormCreation(req.user.uid, { title: chatCommand.description, formUrl: null, sheetUrl });
        resultData = { success: true, type: "sheet", url: sheetUrl, title: chatCommand.description };
      } else {
        return res.status(400).json({ success: false, error: 'Unrecognized command from chat AI' });
      }
      
      res.json(resultData);
    } catch (error) {
      next(error);
    }
  }
);

// =============================================
// Centralized Error Handling Middleware
// =============================================
app.use((err, req, res, next) => {
  logger.error('Unhandled error:', err);
  res.status(500).json({ success: false, error: err.message });
});

// =============================================
// Server Startup
// =============================================
app.listen(PORT, () => logger.info(`Server running at http://localhost:${PORT}`));
