const form = document.getElementById("alert-form");

const submitButton = form.querySelector(
    'button[type="submit"]'
);

const copyButton =
    document.getElementById("copy-report");

const exportButton =
    document.getElementById("export-json");

let latestAnalysis = null;

form.addEventListener("submit", async (event) => {
    event.preventDefault();

    const alertType =
        document.getElementById("alert-type").value;

    const rawAlert =
        document.getElementById("raw-alert").value;

    submitButton.disabled = true;
    submitButton.textContent = "Analyzing...";

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

        if (!response.ok) {
            const message = await response.text();

            throw new Error(
                message || "Analysis request failed."
            );
        }

        const data = await response.json();

        latestAnalysis = data;

        displayResult(data);
    } catch (error) {
        const result =
            document.getElementById("result");

        result.hidden = false;
        const reportHeader =
    document.getElementById("report-header");

clearSection(reportHeader);

addHeading(
    reportHeader,
    "Investigation Metadata"
);

const generated =
    new Date(
        data.report.generated_at * 1000
    ).toLocaleString();

addParagraph(
    reportHeader,
    `Report ID: ${data.report.report_id}`
);

addParagraph(
    reportHeader,
    `Generated: ${generated}`
);

addParagraph(
    reportHeader,
    `Case Status: ${data.report.case_status}`
);
        result.replaceChildren();

        const heading =
            document.createElement("h2");

        heading.textContent =
            "Unable to Analyze Alert";

        const message =
            document.createElement("p");

        message.textContent =
            error instanceof Error
                ? error.message
                : "An unexpected error occurred.";

        result.appendChild(heading);
        result.appendChild(message);
    } finally {
        submitButton.disabled = false;
        submitButton.textContent = "Analyze Alert";
    }
});

function clearSection(section) {
    section.replaceChildren();
}

function addHeading(section, text) {
    const heading = document.createElement("h3");
    heading.textContent = text;
    section.appendChild(heading);
}

function addParagraph(section, text) {
    const paragraph = document.createElement("p");
    paragraph.textContent = text;
    section.appendChild(paragraph);
}

function displayResult(data) {
    const result = document.getElementById("result");
    result.hidden = false;

    // Summary
    const summarySection =
        document.getElementById("summary-section");

    clearSection(summarySection);
    addHeading(summarySection, "Summary");
    addParagraph(summarySection, data.summary);

    // Severity
    const severitySection =
        document.getElementById("severity-section");

    clearSection(severitySection);
    addHeading(severitySection, "Severity");

    const severityBadge = document.createElement("span");
    severityBadge.className =
        `severity-badge severity-${data.report.severity.toLowerCase()}`;
    severityBadge.textContent = data.report.severity;

    severitySection.appendChild(severityBadge);

    // Confidence
    const confidenceSection =
    document.getElementById("confidence-section");

clearSection(confidenceSection);
addHeading(confidenceSection, "Confidence");

const confidenceLabel = document.createElement("p");
confidenceLabel.textContent =
    `${data.report.confidence.level} (${data.report.confidence.score}%)`;

const confidenceTrack = document.createElement("div");
confidenceTrack.className = "confidence-track";

const confidenceBar = document.createElement("div");
confidenceBar.className = "confidence-bar";
confidenceBar.style.width =
    `${data.report.confidence.score}%`;

confidenceTrack.appendChild(confidenceBar);

confidenceSection.appendChild(confidenceLabel);
confidenceSection.appendChild(confidenceTrack);

    // MITRE ATT&CK
    const mitreSection =
    document.getElementById("mitre-section");

clearSection(mitreSection);
addHeading(mitreSection, "MITRE ATT&CK");

if (data.report.mitre.length === 0) {
    addParagraph(
        mitreSection,
        "No MITRE ATT&CK technique mapped."
    );
} else {
    const mitreGrid = document.createElement("div");
    mitreGrid.className = "mitre-grid";

    data.report.mitre.forEach((technique) => {
        const card = document.createElement("div");
        card.className = "mitre-card";

        const id = document.createElement("strong");
        id.textContent = technique.technique_id;

        const name = document.createElement("p");
        name.textContent = technique.technique_name;

        card.appendChild(id);
        card.appendChild(name);
        mitreGrid.appendChild(card);
    });

    mitreSection.appendChild(mitreGrid);
}

    // Knowledge
    const knowledgeSection =
        document.getElementById("knowledge-section");

    clearSection(knowledgeSection);
    addHeading(knowledgeSection, "Security Findings");

    data.report.knowledge.forEach((fact) => {
        const block = document.createElement("div");
        block.className = "finding";

        const title = document.createElement("strong");
        title.textContent = fact.title;

        const description = document.createElement("p");
        description.textContent = fact.description;

        block.appendChild(title);
        block.appendChild(description);

        knowledgeSection.appendChild(block);
    });

    // Recommendations
    const recommendationsSection =
        document.getElementById("recommendations-section");

    clearSection(recommendationsSection);
    addHeading(
        recommendationsSection,
        "Recommended Analyst Actions"
    );

    const recommendationList =
        document.createElement("ol");

    data.report.recommendations.forEach((recommendation) => {
        const item = document.createElement("li");

        item.textContent =
            `[${recommendation.priority}] ${recommendation.action}`;

        recommendationList.appendChild(item);
    });

    recommendationsSection.appendChild(
        recommendationList
    );

    // Narrative
    const narrativeSection =
        document.getElementById("narrative-section");

    clearSection(narrativeSection);
    addHeading(
        narrativeSection,
        "Analyst Narrative"
    );

    addParagraph(
        narrativeSection,
        data.report.narrative
    );
}

copyButton.addEventListener("click", async () => {
    if (!latestAnalysis) {
        return;
    }

    const report = latestAnalysis.report;

    const mitreText = report.mitre
        .map(
            (item) =>
                `${item.technique_id} - ${item.technique_name}`
        )
        .join("\n");

    const recommendationsText =
        report.recommendations
            .map(
                (item, index) =>
                    `${index + 1}. [${item.priority}] ${item.action}`
            )
            .join("\n");

    const text = `
Zyguor SOC Investigation Report

Alert Type:
${latestAnalysis.alert_type}

Severity:
${report.severity}

Confidence:
${report.confidence.level} (${report.confidence.score}%)

MITRE ATT&CK:
${mitreText}

Recommendations:
${recommendationsText}

Analyst Narrative:
${report.narrative}
`.trim();

    try {
        await navigator.clipboard.writeText(text);

        copyButton.textContent = "Copied";

        setTimeout(() => {
            copyButton.textContent = "Copy Report";
        }, 1500);
    } catch {
        copyButton.textContent = "Copy Failed";
    }
});

exportButton.addEventListener("click", () => {
    if (!latestAnalysis) {
        return;
    }

    const json = JSON.stringify(
        latestAnalysis,
        null,
        2
    );

    const blob = new Blob(
        [json],
        {
            type: "application/json",
        }
    );

    const url =
        URL.createObjectURL(blob);

    const link =
        document.createElement("a");

    link.href = url;
    link.download =
        "zyguor-soc-investigation.json";

    document.body.appendChild(link);
    link.click();
    link.remove();

    URL.revokeObjectURL(url);
});