document.addEventListener("DOMContentLoaded", function () {
    const circle = document.querySelector('.progress-ring-fill');
    const text = document.querySelector('.risk-text');
    const eventText = document.querySelector('.risk-event');
    const liveAlertMessage = document.getElementById("liveAlertMessage");
    const alertCard = document.getElementById("liveAlertCard");
    const alertSound = document.getElementById("alertSound");
    const timelineList = document.querySelector(".timeline-card ol");

    const radius = 90;
    const circumference = 2 * Math.PI * radius;
    circle.style.strokeDasharray = circumference;

    async function updateDashboard() {
        try {
            // NOTE: Demo ke waqt IP Mac ke real IP se replace karna
            const response = await fetch('http://10.116.33.19:8000/dashboard-stats');
            const data = await response.json();

            // 1. Update Stats
            document.querySelector(".hero-left .mini-card:nth-child(1) p").textContent = data.active_agents;
            document.querySelector(".hero-left .mini-card:nth-child(2) p").textContent = data.critical_threats;
            document.querySelector(".status-stable").textContent = data.system_status;

            // Agent Status UI Update
            const statusElement = document.getElementById('agent-status');
            if (data.active_agents > 0) {
                statusElement.innerText = 'Online';
                statusElement.style.color = '#00ffcc'; 
            } else {
                statusElement.innerText = 'Offline';
                statusElement.style.color = '#ff4d4d';
            }

            // 2. Update Risk Circle & Live Alert
            if (data.latest_alerts.length > 0) {
                const latest = data.latest_alerts[0];
                const risk = latest.risk_score;
                
                text.textContent = risk + "%";
                eventText.textContent = latest.file_path ? "NTFS TAMPER" : latest.event_type;
                liveAlertMessage.textContent = `Alert: ${latest.description}`;

                circle.style.strokeDashoffset = circumference - (risk / 100) * circumference;
                
                if (risk < 40) circle.style.stroke = "#00ffff";
                else if (risk < 70) circle.style.stroke = "#facc15";
                else {
                    circle.style.stroke = "#ef4444";
                    triggerAlert();
                }

                // 3. Update Timeline
                timelineList.innerHTML = ""; 
                data.latest_alerts.forEach(alert => {
                    const li = document.createElement("li");
                    li.style.marginBottom = "12px";
                    li.style.paddingLeft = "10px";

                    if (alert.file_path) { 
                        li.style.borderLeft = "4px solid #ef4444"; 
                        li.innerHTML = `
                            <strong style="color: #ef4444;">[NTFS LIVE TAMPERING]</strong><br>
                            <span style="font-size: 0.85em; color: #00ffff;">PATH: ${alert.file_path}</span><br>
                            // reh.js mein Line 65 ke theek pehle ye dalo:
                            <small style="color: #ff9f43;">[Mismatch]: $SI vs USN Journal detected!</small><br>
                            <small style="color: #ffffff;">${alert.description}</small>
                        `;
                    } else {
                        li.style.borderLeft = "4px solid #facc15";
                        li.innerHTML = `
                            <strong style="color: #facc15;">[${alert.event_type}]</strong><br>
                            <small>${alert.description}</small>
                        `;
                    }
                    timelineList.appendChild(li);
                });
            }
        } catch (error) {
            console.log("Waiting for Server...", error);
            const statusElement = document.getElementById('agent-status');
            if (statusElement) {
                statusElement.innerText = "Offline";
                statusElement.style.color = "#ff4d4d"; 
            }
        }
    }

    function triggerAlert() {
        alertCard.classList.add("alert-active");
        if (alertSound) {
            alertSound.play().catch(() => console.log("Sound blocked by browser"));
        }
        setTimeout(() => alertCard.classList.remove("alert-active"), 3000);
    }

    setInterval(updateDashboard, 3000);
    updateDashboard();
});

async function downloadReport() {
    const response = await fetch('http://10.116.33.19:8000/dashboard-stats');
    const data = await response.json();
    
    // CSV Header
    let csvContent = "data:text/csv;charset=utf-8,ID,Agent,Event,Risk,Description,Timestamp\n";
    
    // Alert data loop
    data.latest_alerts.forEach(alert => {
        csvContent += `${alert.id},${alert.agent_id},${alert.event_type},${alert.risk_score},"${alert.description}",${alert.timestamp}\n`;
    });

    const encodedUri = encodeURI(csvContent);
    const link = document.createElement("a");
    link.setAttribute("href", encodedUri);
    link.setAttribute("download", "The_Hawks_Forensic_Report.csv");
    document.body.appendChild(link);
    link.click();
}