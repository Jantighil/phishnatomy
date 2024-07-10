// function checkUrl() {
//     const url = document.getElementById('url').value;
//     const resultDiv = document.getElementById('result');
//     resultDiv.innerHTML = 'Checking...';

//     fetch('/check_url', {
//         method: 'POST',
//         headers: {
//             'Content-Type': 'application/json'
//         },
//         body: JSON.stringify({ url: url })
//     })
//     .then(response => response.json())
//     .then(data => {
//         if (data.status === 'legitimate') {
//             resultDiv.innerHTML = `<p class="legitimate">Legitimate URL</p>`;
//         } else {
//             resultDiv.innerHTML = `<p class="phishing">Phishing URL</p>`;
//         }
//         const explanations = data.explanation.map(exp => `<li>${exp}</li>`).join('');
//         resultDiv.innerHTML += `<ul>${explanations}</ul>`;
//     })
//     .catch(error => {
//         console.error('Error:', error);
//         resultDiv.innerHTML = '<p class="phishing">An error occurred. Please try again.</p>';
//     });
// }


async function checkEmail() {
    const emailContent = document.getElementById('email_content').value.trim();
    const fileInput = document.getElementById('file');
    const url = document.getElementById('url').value.trim();

    if (emailContent === '' && fileInput.files.length === 0 && url === '') {
        document.getElementById('result').innerHTML = `
            <p>Please enter email content, upload a document, or provide a URL.</p>
        `;
        return;
    }

    if (emailContent !== '' || url !== '') {
        const response = await fetch('/check_email_and_url', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
            },
            body: JSON.stringify({ email_content: emailContent, url: url }),
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
    } else if (result.result) {
        resultHTML += `<p>The email is classified as: <strong>${result.result}</strong></p>`;
    }

    if (result.found_phrases && result.found_phrases.length > 0) {
        resultHTML += `<p>Found phrases:</p>`;
        resultHTML += `<ul>`;
        result.found_phrases.forEach(phrase => {
            resultHTML += `<li>${phrase} - Reason: ${result.reasons[phrase]}</li>`;
        });
        resultHTML += `</ul>`;
    } else if (result.found_phrases) {
        resultHTML += `<p>No suspicious phrases found.</p>`;
    }

    if (result.url_status === 'phishing' || result.url_status === 'legitimate' || result.url_status === 'unknown') {
        resultHTML += `<p>The URL is classified as: <strong>${result.url_status}</strong></p>`;
        if (result.url_reasons && result.url_reasons.length > 0) {
            resultHTML += `<p>Reasons:</p>`;
            resultHTML += `<ul>`;
            result.url_reasons.forEach(reason => {
                resultHTML += `<li>${reason}</li>`;
            });
            resultHTML += `</ul>`;
        }
        if (result.url_explanation && result.url_explanation.length > 0) {
            resultHTML += `<p>Explanations:</p>`;
            resultHTML += `<ul>`;
            result.url_explanation.forEach(exp => {
                resultHTML += `<li>${exp}</li>`;
            });
            resultHTML += `</ul>`;
        }
    }

    document.getElementById('result').innerHTML = resultHTML;
}

function triggerFileUpload() {
    document.getElementById('file').click();
}
