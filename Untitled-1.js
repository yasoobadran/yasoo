// ...existing code...
async function startScan(url) {
    // ...existing code to start scan animation...

    let result = 'phish';
    try {
        const resp = await fetch('/api/scan', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ url })
        });
        if (resp.ok) {
            const data = await resp.json();
            if (data && (data.result === 'safe' || data.result === 'phish')) {
                result = data.result;
            }
        }
    } catch (e) {
        // keep default 'phish' on error
    }

    // Cleanup laser elements
    document.querySelectorAll('.laser-scan').forEach(el => {
        if (el && el.parentNode) el.parentNode.removeChild(el);
    });

    // wait animation end then send real result
    setTimeout(() => {
        if (window.lampOverlay && typeof window.lampOverlay.setScanResult === 'function') {
            window.lampOverlay.setScanResult(result);
        }
        // ...existing code to finish/cleanup UI...
    }, 900); // 900ms as requested
}
// ...existing code...