# ScamSathi AI 🛡️

> **AI-Powered Scam Detection & Threat Intelligence Platform**  
> Protect users against online frauds, phishing links, fake payment QR codes, and malicious messages with real-time heuristic scanning and Gemini AI multimodal intelligence.

---

## 🌟 Overview

**ScamSathi AI** is a cyber-safety and anti-fraud web application designed to safeguard users—particularly across the Indian digital payments and messaging ecosystem. Whether it is an unexpected WhatsApp job offer, an urgent UPI payment request, an SMS containing an APK download link, or a suspicious QR code screenshot, ScamSathi AI breaks down the threat indicators in seconds and delivers actionable safety guidance.

---

## ✨ Key Features

### 1. 🔍 Multimodal Threat Analysis
- **Text & Message Scanner**: Analyzes suspicious SMS, WhatsApp forwards, emails, lottery traps, electricity bill disconnection threats, and fake courier delivery notices.
- **Image & QR Code Decoder**: Extracts embedded URLs and payment payloads from QR codes and screenshots using `jsQR` and Gemini Vision.
- **Deep URL & Domain Inspector**: Analyzes domain age (RDAP/WHOIS), DNS records, TLS/SSL certificate validity, and tracks HTTP redirect chains to uncover disguised landing pages.

### 2. 🧠 Hybrid AI & Heuristic Intelligence
- **Gemini 3.8 Flash Integration**: Context-aware natural language processing that identifies psychological manipulation tactics (urgency, fear, greed, authority impersonation).
- **Rule-Based Pre-filter & Risk Scoring Engine**: Calculates normalized risk scores (0–100) with clear threat levels (`SAFE`, `SUSPICIOUS`, `HIGH_RISK`).
- **Threat Intelligence Providers**: Extensible support for Google Web Risk, Google Safe Browsing, and VirusTotal APIs.

### 3. 🔒 Privacy & Defense-in-Depth Security
- **PII Scrubbing**: Automatically redacts sensitive personal identifiable information (Aadhaar, PAN, phone numbers, credit cards, bank accounts) before processing.
- **SSRF & Anti-Loop Safeguards**: Strict IP validation prevents Server-Side Request Forgery against private, local, and loopback IP addresses.
- **Resilient Fallback**: Operates reliably even when external API quotas are depleted through robust internal heuristic engines.

### 4. 🇮🇳 Localized Emergency Assistance
- **One-click Cyber Helpline Access**: Direct connection to India's National Cyber Crime Helpline (`1930`) and reporting portal (`cybercrime.gov.in`).
- **Multilingual Support**: Supports English and Hindi language modes.
- **Interactive Sample Library**: Includes real-world simulated scam examples to educate and test against common fraud patterns.

---

## 🛠️ Architecture & Tech Stack

### Frontend
- **Framework**: React 18 with Vite
- **Icons**: Lucide React
- **Styling**: Modern responsive design with glassmorphism, responsive CSS variables, and fluid animations
- **Accessibility**: Native `prefers-reduced-motion` compliance, accessible modals, and semantic HTML

### Backend
- **Runtime**: Node.js (ES Modules)
- **Framework**: Express.js
- **Security**: Helmet, CORS, Express Rate Limit, SSRF IP Validation
- **AI Engine**: `@google/genai` (Google Gemini SDK)
- **Image & QR Processing**: `multer`, `jsqr`, `pngjs`, `jpeg-js`
- **Validation**: Zod schema validation
- **Testing**: Node Native Test Runner (`node --test`) & Supertest

---

## 📂 Project Structure

```text
ScamSathiAi-2/
├── index.html                   # Frontend HTML entry point
├── package.json                 # Frontend dependencies and root scripts
├── vite.config.js               # Vite bundler configuration
├── src/
│   ├── App.jsx                  # Main application container
│   ├── main.jsx                 # React root renderer
│   ├── index.css                # Global styles and design system tokens
│   ├── components/              # UI components
│   │   ├── Navbar.jsx           # Header navigation & language switcher
│   │   ├── Hero.jsx             # Hero section with headline & CTA
│   │   ├── HeroSearch.jsx       # Query & file upload interface
│   │   ├── AnalysisModal.jsx    # Detailed breakdown report modal
│   │   ├── AnalysisLoadingScreen.jsx # Animated scanning stages
│   │   ├── DeepSafetySection.jsx # Deep scan capabilities showcase
│   │   ├── HelplineSection.jsx  # 1930 Helpline & reporting guide
│   │   ├── SampleMessagesModal.jsx # Curated test scams
│   │   └── BrandLogo.jsx        # Shield brand SVG icon
│   └── services/
│       └── api.js               # Frontend API client
└── server/
    ├── package.json             # Backend dependencies and scripts
    ├── scripts/
    │   └── smokeTestProvider.js # Provider verification utility
    ├── src/
    │   ├── server.js            # Express server entry point
    │   ├── app.js               # Express application middleware setup
    │   ├── config/              # Environment & service configuration
    │   ├── controllers/         # Request handlers (analyze, url, image, health)
    │   ├── middleware/          # Rate limiting, error handling, 404 handler
    │   ├── routes/              # Express API route declarations
    │   ├── services/            # Intel pipelines, Gemini AI, DNS, RDAP, SSRF
    │   ├── utils/               # Threat scoring, engine combiners
    │   └── validators/          # Zod validation schemas
    └── tests/                   # Automated unit & integration test suites
```

---

## 🚀 Getting Started

### Prerequisites
- [Node.js](https://nodejs.org/) (v18.0.0 or higher recommended)
- `npm` or `yarn` / `pnpm`
- *(Optional)* [Google Gemini API Key](https://aistudio.google.com/) for AI analysis

---

### Installation

1. **Clone the repository:**
   ```bash
   git clone https://github.com/harshityadaveng/ScamSathiAi-2.git
   cd ScamSathiAi-2
   ```

2. **Install Root & Frontend Dependencies:**
   ```bash
   npm install
   ```

3. **Install Backend Dependencies:**
   ```bash
   cd server
   npm install
   cd ..
   ```

---

### Environment Setup

#### 1. Backend Environment (`server/.env`)
Copy the sample file and fill in your keys:
```bash
cp server/.env.example server/.env
```

Edit `server/.env`:
```env
PORT=5000
NODE_ENV=development
CLIENT_URL=http://localhost:5173

# Rate Limiting
RATE_LIMIT_WINDOW_MS=60000
RATE_LIMIT_MAX_REQUESTS=30

# Gemini AI (Optional - heuristic fallback works without it)
GEMINI_API_KEY=your_gemini_api_key_here
GEMINI_MODEL=gemini-3.8-flash
AI_ENABLED=true

# Threat Intelligence (Optional)
URL_REPUTATION_PROVIDER=none # options: none | google_web_risk | google_safe_browsing | virustotal
```

#### 2. Frontend Environment (`.env`)
```bash
cp .env.example .env
```
Ensure `VITE_API_BASE_URL` points to your backend:
```env
VITE_API_BASE_URL=http://localhost:5000
```

---

### Running the Application

You can start both frontend and backend concurrently or in separate terminal tabs:

**Terminal 1 (Backend API):**
```bash
npm run server
# Server will run on http://localhost:5000
```

**Terminal 2 (Frontend Client):**
```bash
npm run dev
# Frontend will run on http://localhost:5173
```

---

## 🧪 Running Tests

The backend includes a comprehensive suite of unit, integration, and security regression tests:

```bash
# Run all backend tests
npm run test:server

# Or directly from the server folder:
cd server
npm test
```

---

## 📡 API Endpoints

| Method | Endpoint | Description |
|---|---|---|
| `GET` | `/api/health` | Service health status and configured providers |
| `POST` | `/api/analyze` | Unified text, message, or URL threat assessment |
| `POST` | `/api/url/scan` | Deep URL pipeline (DNS, RDAP, TLS, Redirect Chains) |
| `POST` | `/api/image/scan` | Upload image/screenshot for QR decoding and OCR analysis |

---

## 🚨 Emergency Helplines (India)

If you or someone you know has been a victim of financial cyber fraud:
- **National Cyber Crime Helpline**: Dial `1930` immediately (Golden Hour).
- **Official Portal**: [https://cybercrime.gov.in](https://cybercrime.gov.in)
- **Chakshu Fraud Reporting**: Report suspicious calls & SMS via [Sanchar Saathi Chakshu](https://sancharsaathi.gov.in/sfc/).

---

## 📄 License

This project is open-source and available under the [MIT License](LICENSE).
