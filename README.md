# MS_PhishGuard - AI-Powered Phishing Detection

![MS_PhishGuard](https://github.com/user-attachments/assets/04db25fe-c470-42e8-bdf6-9b50f4d92c05)

An advanced, visually striking cyber-themed phishing detection web application featuring AI-powered URL analysis, real-time threat detection, and comprehensive security education.

## 🚀 Features

### 🤖 AI-Powered Detection
- **Hybrid Classification System**: Simulated Random Forest and LSTM algorithms working together
- **Instant Verdicts**: Client-side analysis provides immediate results
- **Three-Level Classification**: URLs are classified as Safe, Suspicious, or Phishing
- **Confidence Scoring**: Each analysis includes confidence percentage and risk score
- **Feature Extraction**: Analyzes 15+ URL characteristics including length, special characters, security indicators, and phishing patterns

### 📊 Threat Dashboard
- **Real-Time Statistics**: Track total scans, safe URLs, suspicious URLs, and phishing detections
- **Interactive Charts**: Visual risk distribution and scan timeline (when Chart.js is available)
- **Scan History**: Detailed table showing all previous scans with timestamps, URLs, verdicts, confidence levels, and risk scores
- **Persistent Storage**: History saved locally in browser using localStorage

### 🔒 Security Practices
- **Responsible Disclosure Policy**: Clear guidelines for reporting security vulnerabilities
- **Privacy Guidelines**: Transparent privacy-first approach with no data collection
- **Best Practices**: Educational content on staying safe online
- **Community Reporting**: Submit suspicious URLs to help protect others

## 🎨 Design

- **Cyber-Themed Interface**: Dark color scheme with neon accents (green, blue, orange, red)
- **Animated Elements**: Glitch effects, pulsing animations, and smooth transitions
- **Matrix-Inspired Background**: Subtle grid animation for that cyberpunk aesthetic
- **Responsive Design**: Works seamlessly on desktop and mobile devices
- **Accessible**: Clear visual hierarchy and readable typography

## 🛠️ Technical Details

### AI Detection Algorithms

#### Random Forest Classifier (7 Decision Trees)
1. **URL Length Check**: Flags abnormally long URLs
2. **Security Features**: Checks for HTTPS, IP addresses, non-standard ports
3. **Suspicious Patterns**: Detects @ symbols, double slashes, excessive hyphens
4. **Character Analysis**: Analyzes special character ratio
5. **Domain Analysis**: Evaluates domain length and subdomain structure
6. **Phishing Indicators**: Identifies common phishing keywords
7. **Invalid URL Detection**: Catches malformed URLs

#### LSTM Pattern Classifier (7 Pattern Checks)
1. **Repetitive Characters**: Detects unusual character repetition
2. **Random Strings**: Identifies randomly generated URLs
3. **Homograph Attacks**: Catches lookalike character substitutions
4. **Suspicious TLDs**: Flags commonly abused top-level domains
5. **URL Shorteners**: Identifies potential redirect services
6. **Obfuscation**: Detects URL encoding and obfuscation techniques
7. **Sequential Patterns**: Identifies suspicious character sequences

### Technology Stack
- **Frontend**: Pure HTML5, CSS3, JavaScript (ES6+)
- **Charts**: Chart.js for data visualization
- **Storage**: Browser localStorage API
- **No Backend**: Completely client-side application
- **No Dependencies**: Works offline after initial load

## 🚦 Getting Started

### Quick Start
1. Clone the repository
2. Open `index.html` in any modern web browser
3. Start scanning URLs!

### Local Development
```bash
# Clone the repository
git clone https://github.com/AND-SHAL-0813/MS_PhishGuard-Web.git

# Navigate to the directory
cd MS_PhishGuard-Web

# Start a local server (optional)
python3 -m http.server 8080

# Open in browser
# Navigate to http://localhost:8080
```

## 📖 Usage

### Scanning URLs
1. Enter a URL in the scan input field
2. Click "Analyze URL" button
3. Wait for the AI analysis (1.5 seconds)
4. View the verdict, confidence score, and analysis details

### Understanding Results
- **✅ SAFE**: URL appears legitimate (risk score < 40)
- **⚠️ SUSPICIOUS**: URL has concerning characteristics (risk score 40-69)
- **🚨 PHISHING**: High probability of phishing attack (risk score ≥ 70)

### Reporting Threats
1. Navigate to the "Report" section
2. Enter the suspicious URL
3. Select the threat type
4. Add optional details
5. Submit the report

## 🔐 Privacy & Security

### Privacy-First Approach
- ✅ **Client-Side Only**: All analysis happens in your browser
- ✅ **No Data Collection**: We don't store or transmit your scanned URLs
- ✅ **Local Storage**: Scan history stays on your device
- ✅ **No Tracking**: No cookies or analytics scripts
- ✅ **No External Calls**: URLs are never sent to any server

### Security Considerations
- This is an educational and demonstration tool
- While the heuristics are based on real phishing indicators, they are simplified simulations
- For production use, consider integrating with professional threat intelligence APIs
- Always verify suspicious URLs through multiple sources
- Report actual phishing attempts to proper authorities

## 🤝 Contributing

Contributions are welcome! Whether it's:
- Improving detection algorithms
- Enhancing the UI/UX
- Adding new features
- Fixing bugs
- Improving documentation

Please follow responsible disclosure practices for any security issues.

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## 🙏 Acknowledgments

- Inspired by modern cybersecurity tools and practices
- Built with education and awareness in mind
- Designed to promote online safety

## 📧 Contact

For security vulnerabilities, please email: security@msphishguard.com

---

**⚡ Powered by AI | 🔒 Privacy-First | 🛡️ Client-Side Detection**

© 2024 MS_PhishGuard. Open Source Security Project.
