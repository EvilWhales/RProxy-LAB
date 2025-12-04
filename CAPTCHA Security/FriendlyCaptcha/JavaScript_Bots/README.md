# JavaScript Bots

### Stages

Different bots stages from simple to advanced.

* `bot_v1.js` normal without any modifications.
* `bot_v2.js` same as 1 with webdriver modification.
* `bot_v3.js` same as 2 with infinite loop.
* `bot_v4.js` same as 3 with with threshold based switch. Change function `switchTorNode` in order to change proxy behavior or comment it out.
* `bot_v5.js` same as 4 with adjusted blob worker size to cores on the machine.
* `bot_v6.js` same as 4 with worker number set to 0 and offload workload to a local executable called `solver.exe` which must be in the same path.

#### Building and running

```bash
# Install dependencies
npm i puppeteer

# Run
node bot_vx.js
```

