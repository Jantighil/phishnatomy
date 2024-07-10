async function checkEmail() {
    const emailContent = document.getElementById('email_content').value.trim();
    const fileInput = document.getElementById('file');

    if (emailContent === '' && fileInput.files.length === 0) {
        document.getElementById('result').innerHTML = `
            <p>Please enter email content or upload a document.</p>
        `;
        return;
    }

    if (emailContent !== '') {
        const response = await fetch('/check_email', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/x-www-form-urlencoded',
            },
            body: `email_content=${encodeURIComponent(emailContent)}`,
        });
        const result = await response.json();
        displayResult(result);
    } else if (fileInput.files.length > 0) {
        uploadFile();
    }
}

async function uploadFile() {
    const fileInput = document.getElementById('file');
    if (fileInput.files.length > 0) {
        const formData = new FormData();
        formData.append('file', fileInput.files[0]);

        const response = await fetch('/upload', {
            method: 'POST',
            body: formData,
        });
        const result = await response.json();
        displayResult(result);
    }
}

function displayResult(result) {
    let resultHTML = '';

    if (result.result === 'Phishing') {
        resultHTML += `<p>The email is classified as: <strong>${result.result}</strong></p>`;
    } else if (result.result === 'Sensitive') {
        resultHTML += `<p>The email contains the following sensitive phrase: <strong>${result.phrase}</strong></p>`;
    } else {
        resultHTML += `<p>The email is classified as: <strong>Safe</strong></p>`;
    }

    if (result.found_phrases.length > 0) {
        resultHTML += `<p>Found phrases:</p>`;
        resultHTML += `<ul>`;
        result.found_phrases.forEach(phrase => {
            resultHTML += `<li>${phrase} - Reason: ${result.reasons[phrase]}</li>`;
        });
        resultHTML += `</ul>`;
    } else {
        resultHTML += `<p>No suspicious phrases found.</p>`;
    }

    document.getElementById('result').innerHTML = resultHTML;
}

function triggerFileUpload() {
    document.getElementById('file').click();
}