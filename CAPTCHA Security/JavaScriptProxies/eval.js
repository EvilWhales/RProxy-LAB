(function wrapEvalFunction() {
    // Store the original eval function
    const originalEval = eval;

    // Initialize the call counter
    let evalCallCount = 0;

    // Replace the eval function with a wrapped version
    window.eval = function(code) {
        evalCallCount++;
        console.log(`eval called ${evalCallCount} times with arguments:`, code);

        // Call the original eval function with the provided code
        return originalEval(code);
    };
})();
