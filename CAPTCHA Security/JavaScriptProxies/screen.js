const originalScreen = screen;

// Object to keep track of property access counts
const accessCounts = {};

const screenProxy = new Proxy(originalScreen, {
  get(target, prop, receiver) {
    // Convert property to a string to use as a key (for functions or symbols)
    const propName = String(prop);

    // Increment access count, initializing if first access
    accessCounts[propName] = (accessCounts[propName] || 0) + 1;

    // Output the current count for this property
    console.log(`Property ${propName} accessed ${accessCounts[propName]} times`);
    console.log(accessCounts);

    // Retrieve the property value
    const value = Reflect.get(target, prop, target);

    // If the property is a function, bind it to the original target
    if (typeof value === 'function') {
      return value.bind(target);
    }

    // Return the property value for non-functions
    return value;
  }
});

Object.defineProperty(window, 'screen', {
  value: screenProxy,
  writable: false,
  configurable: false
});
