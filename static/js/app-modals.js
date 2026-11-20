(function () {
    "use strict";

    window.openModal = function (id) {
        const modal = document.getElementById(id);
        if (!modal) return;
        if (typeof HTMLDialogElement !== "undefined" && modal instanceof HTMLDialogElement) {
            if (!modal.open) modal.showModal();
        } else {
            modal.style.display = "flex";
        }
    };

    window.closeModal = function (id) {
        const modal = document.getElementById(id);
        if (!modal) return;
        if (typeof HTMLDialogElement !== "undefined" && modal instanceof HTMLDialogElement) {
            if (modal.open) modal.close();
        } else {
            modal.style.display = "none";
        }
    };

    window.closeAllModals = function () {
        document.querySelectorAll("dialog.ws-dialog[open]").forEach((dialog) => {
            if (dialog.getAttribute("closedby") !== "none") {
                dialog.close();
            }
        });
        document.querySelectorAll(".overlay").forEach((modal) => {
            modal.style.display = "none";
        });
    };

    document.addEventListener("keydown", (event) => {
        if (event.key === "Escape") {
            document.querySelectorAll(".overlay").forEach((modal) => {
                if (modal.style.display && modal.style.display !== "none") {
                    modal.style.display = "none";
                }
            });
        }
    });

    if (typeof HTMLDialogElement !== "undefined" && !("closedBy" in HTMLDialogElement.prototype)) {
        const outside = (e, dialog) => {
            const r = dialog.getBoundingClientRect();
            return e.clientX < r.left || e.clientX > r.right || e.clientY < r.top || e.clientY > r.bottom;
        };
        document.addEventListener("DOMContentLoaded", () => {
            for (const dialog of document.querySelectorAll('dialog[closedby="any"]')) {
                let pressedOutside = false;
                dialog.addEventListener("pointerdown", (e) => {
                    pressedOutside = outside(e, dialog);
                });
                dialog.addEventListener("pointerup", (e) => {
                    if (pressedOutside && outside(e, dialog)) dialog.close();
                });
            }
        });
    }
})();
