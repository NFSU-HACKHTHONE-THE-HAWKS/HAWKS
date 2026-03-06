import google.generativeai as genai
import os

class AIAnalyzer:
    def __init__(self, api_key):
        # Configure Gemini API
        genai.configure(api_key=api_key)
        self.model = genai.GenerativeModel('gemini-1.5-flash')
        
        # This "System Prompt" forces the AI to act like a Forensics Expert
        self.system_context = (
            "You are a Senior Digital Forensics Expert. Your task is to analyze "
            "suspicious system events and explain if they represent an anti-forensics "
            "attack. Be concise and technical. Focus on the 'Intent' of the command."
        )

    def analyze_event(self, event_data):
        """
        Sends the suspicious command or file action to the AI for a final verdict.
        """
        prompt = f"""
        {self.system_context}
        
        ANALYSIS REQUEST:
        - Event Type: {event_data.get('event_type')}
        - Description: {event_data.get('description')}
        - Command Executed: {event_data.get('command_line', 'N/A')}
        - Process Name: {event_data.get('process_name', 'Unknown')}
        - Risk Score: {event_data.get('risk_score')}
        
        Please provide:
        1. VERDICT: (Malicious / Suspicious / False Positive)
        2. HACKER INTENT: (What were they trying to hide or delete?)
        3. RECOMMENDED ACTION: (How should the investigator respond?)
        """
        
        try:
            response = self.model.generate_content(prompt)
            return response.text
        except Exception as e:
            return f"AI Analysis failed: {str(e)}"

# --- DEMO USAGE ---
# if __name__ == "__main__":
    analyzer = AIAnalyzer(api_key=AIzaSyBINzhjwrBifQ2klh9Ip9qVXNnF0qPuLEU)
#    sample_event = {
#        "event_type": "kernel_log_tampering",
#        "command_line": "wevtutil cl Security",
#        "process_name": "cmd.exe",
#        "risk_score": 100
#    }
#    print(analyzer.analyze_event(sample_event))