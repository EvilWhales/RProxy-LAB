const originalDocument = document;

// Object to keep track of function call counts
const functionCallCounts = {};

// Iterate over properties of the document object
for (const key of Object.getOwnPropertyNames(Document.prototype)) {
  if (typeof originalDocument[key] === 'function') {
    // Create a proxy function if the property is a function
    functionCallCounts[key] = 0;

    originalDocument[key] = new Proxy(originalDocument[key], {
      apply: function(target, thisArg, argumentsList) {
        // Increment the function call count
        functionCallCounts[key]++;

        // Log the function call
        console.log(`Function ${key} called ${functionCallCounts[key]} times with arguments:`, argumentsList);
        console.log(functionCallCounts);

        // Call the original function
        return Reflect.apply(target, thisArg, argumentsList);
      }
    });
  }
}
