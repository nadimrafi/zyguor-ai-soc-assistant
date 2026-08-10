const form = document.getElementById("alert-form");

const submitButton =
    form.querySelector('button[type="submit"]');

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

        await loadHistory();
    } catch (error) {
        showError(
            "Unable to Analyze Alert",
            error
        );
    } finally {
        submitButton.disabled = false;
        submitButton.textContent = "Analyze Alert";
    }
});

function clearSection(section) {
    if (section) {
        section.replaceChildren();
    }
}

function addHeading(section, text) {
    const heading =
        document.createElement("h3");

    heading.textContent = text;

    section.appendChild(heading);
}

function addParagraph(section, text) {
    const paragraph =
        document.createElement("p");

    paragraph.textContent = text;

    section.appendChild(paragraph);
}

function showError(titleText, error) {
    const result =
        document.getElementById("result");

    result.hidden = false;
    result.replaceChildren();

    const heading =
        document.createElement("h2");

    heading.textContent = titleText;

    const message =
        document.createElement("p");

    message.textContent =
        error instanceof Error
            ? error.message
            : "An unexpected error occurred.";

    result.appendChild(heading);
    result.appendChild(message);
}

function displayResult(data) {
    const result =
        document.getElementById("result");

    result.hidden = false;

    displayReportHeader(data);
    displaySummary(data);
    displaySeverity(data);
    displayConfidence(data);
    displayMitre(data);
    displayKnowledge(data);
    displayRecommendations(data);
    displayNarrative(data);
}

function displayReportHeader(data) {
    const reportHeader =
        document.getElementById("report-header");

    clearSection(reportHeader);

    const title =
        document.createElement("h2");

    title.textContent =
        "Security Investigation Report";

    reportHeader.appendChild(title);

    addParagraph(
        reportHeader,
        `Report ID: ${data.report.report_id}`
    );

    addParagraph(
        reportHeader,
        `Status: ${data.report.case_status}`
    );

    const generated =
        new Date(
            data.report.generated_at * 1000
        ).toLocaleString();

    addParagraph(
        reportHeader,
        `Generated: ${generated}`
    );
}

function displaySummary(data) {
    const section =
        document.getElementById("summary-section");

    clearSection(section);

    addHeading(section, "Summary");
    addParagraph(section, data.summary);
}

function displaySeverity(data) {
    const section =
        document.getElementById("severity-section");

    clearSection(section);

    addHeading(section, "Severity");

    const badge =
        document.createElement("span");

    badge.className =
        `severity-badge severity-${data.report.severity.toLowerCase()}`;

    badge.textContent =
        data.report.severity.toUpperCase();

    section.appendChild(badge);
}

function displayConfidence(data) {
    const section =
        document.getElementById("confidence-section");

    clearSection(section);

    addHeading(section, "Confidence");

    addParagraph(
        section,
        `${data.report.confidence.level} (${data.report.confidence.score}%)`
    );

    const track =
        document.createElement("div");

    track.className =
        "confidence-track";

    const bar =
        document.createElement("div");

    bar.className =
        "confidence-bar";

    bar.style.width =
        `${data.report.confidence.score}%`;

    track.appendChild(bar);
    section.appendChild(track);

    if (data.report.confidence.reasons.length > 0) {
        const list =
            document.createElement("ul");

        data.report.confidence.reasons.forEach(
            (reason) => {
                const item =
                    document.createElement("li");

                item.textContent = reason;

                list.appendChild(item);
            }
        );

        section.appendChild(list);
    }
}

function displayMitre(data) {
    const section =
        document.getElementById("mitre-section");

    clearSection(section);

    addHeading(section, "MITRE ATT&CK");

    if (data.report.mitre.length === 0) {
        addParagraph(
            section,
            "No MITRE ATT&CK technique mapped."
        );

        return;
    }

    const grid =
        document.createElement("div");

    grid.className =
        "mitre-grid";

    data.report.mitre.forEach(
        (technique) => {
            const card =
                document.createElement("div");

            card.className =
                "mitre-card";

            const id =
                document.createElement("strong");

            id.textContent =
                technique.technique_id;

            const name =
                document.createElement("p");

            name.textContent =
                technique.technique_name;

            card.appendChild(id);
            card.appendChild(name);

            grid.appendChild(card);
        }
    );

    section.appendChild(grid);
}

function displayKnowledge(data) {
    const section =
        document.getElementById("knowledge-section");

    clearSection(section);

    addHeading(
        section,
        "Security Findings"
    );

    data.report.knowledge.forEach(
        (fact) => {
            const block =
                document.createElement("div");

            block.className =
                "finding";

            const title =
                document.createElement("strong");

            title.textContent =
                fact.title;

            const description =
                document.createElement("p");

            description.textContent =
                fact.description;

            block.appendChild(title);
            block.appendChild(description);

            section.appendChild(block);
        }
    );
}

function displayRecommendations(data) {
    const section =
        document.getElementById(
            "recommendations-section"
        );

    clearSection(section);

    addHeading(
        section,
        "Recommended Analyst Actions"
    );

    const list =
        document.createElement("ol");

    data.report.recommendations.forEach(
        (recommendation) => {
            const item =
                document.createElement("li");

            item.textContent =
                `[${recommendation.priority}] ${recommendation.action}`;

            list.appendChild(item);
        }
    );

    section.appendChild(list);
}

function displayNarrative(data) {
    const section =
        document.getElementById("narrative-section");

    clearSection(section);

    addHeading(
        section,
        "Analyst Narrative"
    );

    addParagraph(
        section,
        data.report.narrative
    );
}

copyButton.addEventListener(
    "click",
    async () => {
        if (!latestAnalysis) {
            return;
        }

        const report =
            latestAnalysis.report;

        const mitreText =
            report.mitre
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

Report ID:
${report.report_id}

Status:
${report.case_status}

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
            await navigator.clipboard.writeText(
                text
            );

            copyButton.textContent =
                "Copied";

            setTimeout(() => {
                copyButton.textContent =
                    "Copy Report";
            }, 1500);
        } catch {
            copyButton.textContent =
                "Copy Failed";
        }
    }
);

exportButton.addEventListener(
    "click",
    () => {
        if (!latestAnalysis) {
            return;
        }

        const json =
            JSON.stringify(
                latestAnalysis,
                null,
                2
            );

        const blob =
            new Blob(
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
            `${latestAnalysis.report.report_id}.json`;

        document.body.appendChild(link);

        link.click();

        link.remove();

        URL.revokeObjectURL(url);
    }
);

async function loadHistory() {
    const historyList =
        document.getElementById(
            "history-list"
        );

    historyList.replaceChildren();

    try {
        const response =
            await fetch("/history");

        if (!response.ok) {
            throw new Error(
                "Unable to load investigation history."
            );
        }

        const reports =
            await response.json();

        if (reports.length === 0) {
            const message =
                document.createElement("p");

            message.textContent =
                "No saved investigations yet.";

            historyList.appendChild(
                message
            );

            return;
        }

        reports
            .slice()
            .reverse()
            .forEach(
                (filename) => {
                    const reportId =
                        filename.endsWith(".json")
                            ? filename.slice(0, -5)
                            : filename;

                    const button =
                        document.createElement(
                            "button"
                        );

                    button.type = "button";
                    button.className =
                        "history-item";

                    button.textContent =
                        reportId;

                    button.addEventListener(
                        "click",
                        () =>
                            loadSavedReport(
                                reportId
                            )
                    );

                    historyList.appendChild(
                        button
                    );
                }
            );
    } catch (error) {
        const message =
            document.createElement("p");

        message.textContent =
            error instanceof Error
                ? error.message
                : "Unable to load investigation history.";

        historyList.appendChild(
            message
        );
    }
}

async function loadSavedReport(reportId) {
    try {
        const response =
            await fetch(
                `/history/${encodeURIComponent(reportId)}`
            );

        if (!response.ok) {
            throw new Error(
                "Unable to load saved investigation."
            );
        }

        const report =
            await response.json();

        const data = {
            alert_type:
                "Saved Investigation",
            summary:
                "Saved investigation loaded successfully.",
            source_ip: null,
            username: null,
            hostname: null,
            timestamp: null,
            ipv4_addresses: [],
            report,
        };

        latestAnalysis = data;

        displayResult(data);
    } catch (error) {
        showError(
            "Unable to Load Investigation",
            error
        );
    }
}

loadHistory();