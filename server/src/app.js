import express from 'express';
import cors from 'cors';
import helmet from 'helmet';
import rateLimit from 'express-rate-limit';
import { env } from './config/env.js';
import healthRoutes from './routes/health.routes.js';
import analyzeRoutes from './routes/analyze.routes.js';
import urlRoutes from './routes/url.routes.js';
import imageRoutes from './routes/image.routes.js';
import { getRootStatus } from './controllers/health.controller.js';
import { notFoundHandler } from './middleware/not-found.middleware.js';
import { errorHandler } from './middleware/error.middleware.js';

export function createApp() {
  const app = express();

  // 1. Security Headers via Helmet
  app.use(helmet());

  // 2. Controlled CORS configuration
  const allowedOrigins = [env.CLIENT_URL, 'http://localhost:5173', 'http://127.0.0.1:5173'];
  app.use(
    cors({
      origin: (origin, callback) => {
        // Allow requests with no origin (e.g. mobile apps, curl, server-to-server) or allowed origins
        let isLocalDevelopmentOrigin = false;
        if (origin && env.NODE_ENV !== 'production') {
          try {
            const { hostname, protocol } = new URL(origin);
            isLocalDevelopmentOrigin =
              protocol === 'http:' &&
              ['localhost', '127.0.0.1', '[::1]'].includes(hostname);
          } catch {
            isLocalDevelopmentOrigin = false;
          }
        }

        if (!origin || allowedOrigins.includes(origin) || isLocalDevelopmentOrigin) {
          callback(null, true);
        } else {
          callback(new Error(`CORS blocked request from origin: ${origin}`));
        }
      },
      credentials: true,
      methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
      allowedHeaders: ['Content-Type', 'Authorization'],
    })
  );

  // 3. JSON body parser with safety limit
  app.use(express.json({ limit: '100kb' }));
  app.use(express.urlencoded({ extended: true, limit: '100kb' }));

  // 4. Rate Limiting for API routes
  const apiLimiter = rateLimit({
    windowMs: env.RATE_LIMIT_WINDOW_MS,
    max: env.RATE_LIMIT_MAX_REQUESTS,
    standardHeaders: true, // Return rate limit info in `RateLimit-*` headers
    legacyHeaders: false, // Disable `X-RateLimit-*` headers
    message: {
      success: false,
      message: 'Too many requests from this IP, please try again later.',
      timestamp: new Date().toISOString(),
    },
  });

  // Apply rate limiter to /api routes
  app.use('/api', apiLimiter);

  // 5. Root endpoint
  app.get('/', getRootStatus);

  // 6. Mount API routes
  app.use('/api', healthRoutes);
  app.use('/api', analyzeRoutes);
  app.use('/api', urlRoutes);
  app.use('/api', imageRoutes);

  // 7. 404 Handler for undefined routes
  app.use(notFoundHandler);

  // 8. Centralized error handling
  app.use(errorHandler);

  return app;
}

export default createApp();
