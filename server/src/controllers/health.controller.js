/**
 * Health Controller
 * Provides system status checks and root endpoints.
 */

export function getHealthStatus(_req, res) {
  res.status(200).json({
    success: true,
    message: 'ScamSathi AI backend is running',
    timestamp: new Date().toISOString(),
  });
}

export function getRootStatus(_req, res) {
  res.status(200).json({
    success: true,
    message: 'ScamSathi AI API Service',
    version: '1.0.0',
    documentation: '/api/health',
    timestamp: new Date().toISOString(),
  });
}
