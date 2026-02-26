(function () {
    "use strict";

    function sleep(ms) {
        return new Promise((resolve) => setTimeout(resolve, ms));
    }

    async function uploadChunkWithRetry(url, formData, retries) {
        let attempt = 0;
        while (attempt <= retries) {
            try {
                const response = await fetch(url, {
                    method: "POST",
                    body: formData,
                    credentials: "same-origin",
                });
                if (response.ok) return response;
                throw new Error(`HTTP ${response.status}`);
            } catch (error) {
                attempt += 1;
                if (attempt > retries) throw error;
                await sleep(200 * attempt);
            }
        }
        throw new Error("upload failed");
    }

    window.WebShareUpload = {
        uploadChunkWithRetry,
    };
})();
