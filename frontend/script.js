// URL-Detector/frontend/script.js

async function checkURL() {
    const urlInput = document.getElementById('urlInput').value;
    const resultCard = document.getElementById('resultCard');
    const statusText = document.getElementById('statusText');
    const badge = document.getElementById('predictionBadge');
    const btn = document.getElementById('checkBtn');

    if (!urlInput) return alert("Please enter a URL");

    // UI Reset
    btn.disabled = true;
    resultCard.classList.remove('hidden');
    statusText.innerText = "Submitting to analysis queue...";
    badge.className = "badge processing";
    badge.innerText = "In Queue";

    try {
        // 1. Submit the job
        const response = await fetch('http://localhost:8000/analyze', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ url: urlInput })
        });
        const data = await response.json();
        const jobId = data.job_id;

        // 2. Poll for results every 1 second
        const pollInterval = setInterval(async () => {
            const res = await fetch(`http://localhost:8000/result/${jobId}`);
            const resultData = await res.json();

            if (resultData.status === 'completed') {
                clearInterval(pollInterval);
                displayResult(resultData.result);
                btn.disabled = false;
            }
        }, 1000);

    } catch (error) {
        statusText.innerText = "Error connecting to server.";
        btn.disabled = false;
    }
}

function displayResult(result) {
    const statusText = document.getElementById('statusText');
    const badge = document.getElementById('predictionBadge');

    statusText.innerText = `Finished analyzing: ${result.url}`;
    const prediction = result.prediction;
    badge.innerText = prediction;

    // Set color based on prediction
    badge.className = `badge ${prediction.toLowerCase()}`;
}