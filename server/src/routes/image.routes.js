import { Router } from 'express';
import multer from 'multer';
import { scanImage } from '../controllers/image.controller.js';

const router = Router();

const upload = multer({
  storage: multer.memoryStorage(),
  limits: {
    fileSize: 5 * 1024 * 1024, // 5MB
  },
  fileFilter: (_req, file, cb) => {
    const allowed = ['image/png', 'image/jpeg', 'image/jpg', 'image/webp'];
    if (allowed.includes((file.mimetype || '').toLowerCase())) {
      cb(null, true);
    } else {
      cb(new Error(`INVALID_MIME_TYPE: Unsupported image format "${file.mimetype}". Allowed: PNG, JPEG, WebP.`));
    }
  },
});

router.post('/scan-image', upload.single('image'), scanImage);

export default router;
