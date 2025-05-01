# AI-Driven Network Intrusion Detection System

A Python-based network intrusion detection application that leverages advanced AI techniques to analyze and detect network security threats with intelligent monitoring capabilities.

## Key Features

- Hybrid machine learning detection approach combining autoencoders and Decision Tree classifiers
- Web and terminal interfaces for comprehensive threat analysis
- Automated data processing and real-time threat detection
- Detailed performance metrics and attack type reporting
- PostgreSQL database integration for storing detection history
- Support for various network traffic data formats (CSV)

## Installation

1. Clone the repository:
git clone https://github.com/yourusername/network-intrusion-detection.git
cd network-intrusion-detection

2. Install dependencies:
pip install -r requirements.txt

3. Set up the PostgreSQL database and configure the environment variable:
export DATABASE_URL=postgresql://username:password@localhost:5432/intrusion_detection

## Usage
### Web Interface
Run the web application:
python web_app_simple.py

Access the web interface in your browser at: http://localhost:5000
### Terminal Interface
Run the terminal application:
python terminal_app.py

### Demo
Run the automated demo:
python run_demo.py

## Attack Types Detected
The system can detect and classify the following types of network attacks:
- **DoS (Denial of Service)** - Attempts to make a resource unavailable
- **Probe** - Surveillance and port scanning activities
- **R2L (Remote to Local)** - Unauthorized access from a remote machine
- **U2R (User to Root)** - Unauthorized access to local superuser privileges
## Project Structure
- `web_app_simple.py` - Web interface using Flask
- `terminal_app.py` - Terminal interface
- `run_demo.py` - Automated demo script
- `models.py` - Database models for PostgreSQL
- `model_handler.py` - ML model handling and detection logic
- `data_processor.py` - Data loading and preprocessing
## License
This project is licensed under the MIT License - see the LICENSE file for details.
