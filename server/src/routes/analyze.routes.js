import { Router } from 'express';
import { analyzeContent } from '../controllers/analyze.controller.js';
import { analyzeRequestSchema, validateBody } from '../validators/analyze.schema.js';

const router = Router();

// POST /api/analyze
router.post('/analyze', validateBody(analyzeRequestSchema), analyzeContent);

export default router;
