/**
 * 404 Not Found Middleware
 * Handles all requests targeting routes that are not defined.
 */
export function notFoundHandler(req, res, _next) {
  res.status(404).json({
    success: false,
    message: `Cannot ${req.method} ${req.originalUrl} - Route not found`,
    timestamp: new Date().toISOString(),
  });
}
