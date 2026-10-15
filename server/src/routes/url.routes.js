import { Router } from 'express';
import { checkUrl } from '../controllers/url.controller.js';
import { checkUrlRequestSchema } from '../validators/url.schema.js';
import { validateBody } from '../validators/analyze.schema.js';

const router = Router();

// POST /api/check-url
router.post('/check-url', validateBody(checkUrlRequestSchema), checkUrl);

export default router;
