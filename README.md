
# Cybersecurity Monitoring & Analytics Platform
## Overview
This platform delivers comprehensive endpoint security monitoring, log analysis, risk assessment, and real-time visualization. It is designed to automate threat detection, enhance security visibility, and support incident response workflows.

## Architecture
The solution is organized into three main components:

- **Agent**: Modular Python scripts for monitoring, analysis, and detection.
- **Server**: Backend API and database for log storage, model management, and data access.
- **Dashboard**: Web interface for real-time analytics, alert visualization, and user interaction.

### Agent Modules
- **agent.py**: Entry point for agent operations and orchestration.
- **agent_ntfs.py**: Monitors NTFS file system events for suspicious activity.
- **ai_analyzer.py**: Applies AI-driven analytics to detect anomalies and threats.
- **deception.py**: Identifies deception techniques and tampering attempts.
- **etw_monitor.py**: Captures and analyzes ETW (Event Tracing for Windows) events.
- **logfile_checker.py**: Performs log file integrity checks and anomaly detection.
- **monitor.py**: General system monitoring and event collection.
- **ntfs_analyzer.py**: Deep analysis of NTFS logs for forensic insights.
- **policy_monitor.py**: Monitors policy changes and compliance violations.
- **process_verifier.py**: Verifies process legitimacy and detects suspicious processes.
- **risk_engine.py**: Calculates risk scores based on observed events and behaviors.
- **trigger_tamper.py**: Detects and responds to tampering triggers.

### Server Modules
- **main.py**: API server entry point, manages request routing.
- **database.py**: Handles database connections and log storage.
- **models.py**: Defines data models for logs, alerts, and user data.
- **routes.py**: Implements API endpoints for agent and dashboard communication.

### Dashboard
- **reh.html**: Main dashboard interface for visualization.
- **reh.js**: Client-side logic for dynamic updates and interaction.
- **reh.css**: Styles for dashboard layout and appearance.

## Features
- Real-time monitoring of NTFS and ETW events
- Log file integrity checks and anomaly detection
- Deception and tampering detection
- Policy monitoring and compliance verification
- Process legitimacy verification
- Automated risk scoring and threat prioritization
- AI-driven analytics for advanced threat detection
- RESTful API for agent and dashboard integration
- Interactive dashboard for alert visualization and analytics
- Modular design for easy extension and customization

## License
MIT License

## Contact
For inquiries or support, please contact the repository owner.
## Setup Instructions
