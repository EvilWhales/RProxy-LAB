(function wrapWindowFunctions() {
    // Object to store call counts
    const callCounts = {};

    for (const prop in window) {
        // Ensure the property is actually on the window and not its prototype
        if (window.hasOwnProperty(prop)) {
            try {
                // Check if the property is a function and wrap it
                if (typeof window[prop] === 'function') {
                    const originalFunction = window[prop];
                    callCounts[prop] = 0;  // Initialize counter for this function

                    window[prop] = function(...args) {
                        callCounts[prop] += 1;
                        console.log(`Function ${prop} called ${callCounts[prop]} times with arguments:`, args);
                        console.log(callCounts);
                        return originalFunction.apply(this, args);
                    };
                }
            } catch (error) {
                console.error(`Error wrapping function ${prop}:`, error);
            }
        }
    }

    // Optionally expose the callCounts for external use or debugging
    window.functionCallCounts = callCounts;
})();

