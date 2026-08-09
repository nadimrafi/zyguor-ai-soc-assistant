const form = document.getElementById("alert-form");

form.addEventListener("submit", async (event) => {
    event.preventDefault();

    const alertType =
        document.getElementById("alert-type").value;

    const rawAlert =
        document.getElementById("raw-alert").value;

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

    displayResult(data);
});

function displayResult(data) {

    document.getElementById("result").hidden = false;

    document.getElementById("summary-section").innerHTML =
        `<h3>Summary</h3>
         <p>${data.summary}</p>`;

    document.getElementById("severity-section").innerHTML =
        `<h3>Severity</h3>
         <p>${data.report.severity}</p>`;

    document.getElementById("confidence-section").innerHTML =
        `<h3>Confidence</h3>
         <p>${data.report.confidence.level}
         (${data.report.confidence.score}%)</p>`;
}