/**
 * Centralized Error-Handling Middleware
 * Catches unhandled errors across the Express application and returns consistent JSON.
 */
export function errorHandler(err, _req, res, _next) {
  const statusCode = err.status || err.statusCode || 500;
  const isDev = process.env.NODE_ENV === 'development';

  console.error(`[Error] ${err.name || 'ServerError'}: ${err.message}`);
  if (err.stack && isDev) {
    console.error(err.stack);
  }

  res.status(statusCode).json({
    success: false,
    message: err.message || 'Internal Server Error',
    timestamp: new Date().toISOString(),
    ...(isDev && { stack: err.stack }),
  });
}
