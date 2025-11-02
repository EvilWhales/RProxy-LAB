async function setupChangeListeners(socket, page) {
    await page.exposeFunction('onElementChanged', (csspath, value, selectionStart, selectionEnd) => {
        socket.emit('inputchange', {
            csspath: csspath,
            value: value,
            selectionStart: selectionStart,
            selectionEnd: selectionEnd
        });
    });

    const attachChangeListeners = async () => {
        try {
            await page.evaluate(() => {
                if (!window.changeListenersAttached) {
                    function getCssPath(el) {
                        if (!(el instanceof Element)) return;
                        var path = [];
                        while (el.nodeType === Node.ELEMENT_NODE) {
                            var selector = el.nodeName.toLowerCase();
                            if (el.id) {
                                selector += '#' + el.id;
                                path.unshift(selector);
                                break;
                            } else {
                                var sib = el, nth = 1;
                                while (sib = sib.previousElementSibling) {
                                    if (sib.nodeName.toLowerCase() == selector) nth++;
                                }
                                if (nth != 1) selector += ":nth-of-type(" + nth + ")";
                            }
                            path.unshift(selector);
                            el = el.parentNode;
                        }
                        return path.join(" > ");
                    }

                    document.documentElement.addEventListener('input', (event) => {
                        const tag = event.target.tagName.toLowerCase();

                        if (tag === 'input' || tag === 'textarea') {
                            const inputType = event.target.type.toLowerCase();
                            let selectionStart = null;
                            let selectionEnd = null;

                            if (inputType === 'text' || inputType === 'textarea') {
                                selectionStart = event.target.selectionStart;
                                selectionEnd = event.target.selectionEnd;
                            }

                            window.onElementChanged(
                                getCssPath(event.target),
                                event.target.value,
                                selectionStart,
                                selectionEnd
                            );
                        }
                    });

                    window.changeListenersAttached = true;
                }
            });
        } catch (error) {
            console.error('Error in attachChangeListeners:', error);
        }
    };

    page.on('framenavigated', attachChangeListeners);
}

module.exports = {
    setupChangeListeners
};