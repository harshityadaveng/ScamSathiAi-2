import { env } from './config/env.js';
import app from './app.js';

const server = app.listen(env.PORT, () => {
  console.log('==================================================');
  console.log(`🛡️  ScamSathi AI Backend Service Started`);
  console.log(`📡 Environment: ${env.NODE_ENV}`);
  console.log(`🚀 Port:        ${env.PORT}`);
  console.log(`🔗 Local URL:   http://localhost:${env.PORT}`);
  console.log(`🩺 Health API:  http://localhost:${env.PORT}/api/health`);
  console.log(`🌐 Allowed Web: ${env.CLIENT_URL}`);
  console.log('==================================================');
});

// Graceful shutdown handling
function gracefulShutdown(signal) {
  console.log(`\n🛑 Received ${signal}. Shutting down ScamSathi AI server gracefully...`);
  server.close(() => {
    console.log('✅ HTTP server closed. Process terminating cleanly.');
    process.exit(0);
  });

  // Force close if taking too long
  setTimeout(() => {
    console.error('⚠️  Forcefully shutting down server after timeout.');
    process.exit(1);
  }, 10000);
}

process.on('SIGINT', () => gracefulShutdown('SIGINT'));
process.on('SIGTERM', () => gracefulShutdown('SIGTERM'));
