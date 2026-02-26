(function () {
    "use strict";

    if (typeof window.openModal !== "function") {
        window.openModal = function (id) {
            const modal = document.getElementById(id);
            if (modal) modal.style.display = "flex";
        };
    }

    if (typeof window.closeModal !== "function") {
        window.closeModal = function (id) {
            const modal = document.getElementById(id);
            if (modal) modal.style.display = "none";
        };
    }

    window.closeAllModals = function () {
        document.querySelectorAll(".overlay").forEach((modal) => {
            modal.style.display = "none";
        });
    };

    document.addEventListener("keydown", (event) => {
        if (event.key === "Escape") {
            window.closeAllModals();
        }
    });
})();
