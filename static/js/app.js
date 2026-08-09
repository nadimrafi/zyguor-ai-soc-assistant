const form = document.getElementById("alert-form");
const result = document.getElementById("result");

form.addEventListener("submit", async (event) => {
    event.preventDefault();

    const alertType = document.getElementById("alert-type").value;
    const rawAlert = document.getElementById("raw-alert").value;

    result.innerHTML = "<p>Analyzing alert...</p>";

    try {
        const response = await fetch("/analyze", {
            method: "POST",
            headers: {
                "Content-Type": "application/json",
            },
            body: JSON.stringify({
                alert_type: alertType,
                raw_alert: rawAlert,
            }),
        });

        const data = await response.json();

        if (!response.ok) {
            result.innerHTML = `<p>${data}</p>`;
            return;
        }

        result.innerHTML = `
            <h2>Analysis Result</h2>
            <p><strong>Alert Type:</strong> ${data.alert_type}</p>
            <p><strong>Summary:</strong> ${data.summary}</p>
            <p><strong>Severity:</strong> ${data.severity}</p>
            <p><strong>Confidence:</strong> ${data.confidence}</p>
        `;
    } catch (error) {
        result.innerHTML = "<p>Unable to analyze the alert.</p>";
    }
});