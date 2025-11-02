function waitForFunctionInIframe(ifr, funcName, callback) {
    var checkInterval = setInterval(function () {
        if (ifr.contentWindow.processIframe) {
            clearInterval(checkInterval);
            callback();  
        }
    }, 100);  
}
function findIframeByAttribute(attrName, attrValue, checkedIframes) {
    var iframes = document.getElementsByTagName('iframe');

    checkedIframes = checkedIframes || new Set();

    for (var i = 0; i < iframes.length; i++) {
        if (checkedIframes.has(iframes[i])) {
            continue;
        }

        checkedIframes.add(iframes[i]);

        if (iframes[i].getAttribute(attrName) == attrValue) {
            return iframes[i];
        }

        var iframeContent = iframes[i].contentDocument || iframes[i].contentWindow.document;

        var nestedIframe = findIframeByAttribute.call(iframeContent, attrName, attrValue, checkedIframes);
        if (nestedIframe) {
            return nestedIframe;
        }
    }
    return null;
}
function getCssPath(el) {
    if (!(el instanceof Element))
        return;
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
                if (sib.nodeName.toLowerCase() == selector)
                    nth++;
            }
            if (nth != 1)
                selector += ":nth-of-type(" + nth + ")";
        }
        path.unshift(selector);
        el = el.parentNode;
    }
    return path.join(" > ");
}


var socket = io();

var dd = new diffDOM.DiffDOM();


socket.on('redir', (data) => {
	if (data.url) {
		window.location.replace(data.url); 
	}
});

socket.on('updateBrowserUrl', (data) => {
    if (data.url) {
        console.log(`Received URL update from Puppeteer: ${data.url}`);
        
        const currentUrl = window.location.origin; 
        const newUrl = currentUrl + data.url;  

        console.log(`Setting address bar to: ${newUrl}`);

        try {
            history.replaceState(null, '', newUrl); 
            console.log(`URL updated to: ${window.location.href}`);
        } catch (error) {
            console.error("Error updating URL: ", error);
        }
    } else {
        console.log("Received invalid URL data from Puppeteer");
    }
});


socket.on('domchanges', async function (changes) {
    if (changes.main) {
        if (changes.main.head) {
            console.log('main.head: ' + dd.apply(document.getElementsByTagName('head')[0], changes.main.head));
        }
        if (changes.main.bodydiv) {
            try {
                console.log('main.bodydiv: ' + dd.apply(document.getElementsByTagName('body')[0], changes.main.bodydiv));
            } catch (error) {
                console.log(changes.main.bodydiv, error);
            }

        }
    }
    if (changes.iframes) {
        console.log(changes.iframes);
        changes.iframes.forEach(iframechanges => {
            try {
                var ifr = findIframeByAttribute('data-temp-iframe-id', iframechanges.selector);

                if (ifr) {
                    waitForFunctionInIframe(ifr, 'processIframe', function () {
                        if (iframechanges.head) {
                            var result = ifr.contentWindow.processIframe({
                                target: ifr.contentWindow.document.getElementsByTagName('head')[0], diff: iframechanges.head
                            }
                            );
                            console.log('headresult', result);
                        }
                        if (iframechanges.bodydiv) {
                            var result = ifr.contentWindow.processIframe({
                                target: ifr.contentWindow.document.getElementsByTagName('body')[0], diff: iframechanges.bodydiv
                            }
                            );
                            console.log('bodydivresult', result);
                        }
                    });
                }

            } catch (error) {
                console.log(error);
            }
        });
    }

});

socket.on('inputchange', async function (changes){
    var input = document.querySelector(changes.csspath);
    input.value = changes.value;
    if(changes.selectionStart && changes.selectionEnd){
        input.selectionStart = changes.selectionStart;
        input.selectionEnd = changes.selectionEnd;
    }
    
});
document.addEventListener('click', function (e) {
    e.preventDefault();
    var click = {
        cssPath:  getCssPath(e.target),
        selectionStart: e.target.selectionStart,
        selectionEnd: e.target.selectionEnd
    }
    
    socket.emit('click',click);
    console.log(e.target.selectionStart, e.target.selectionEnd);
});

var keydownKeys = [
    "Backspace", "Delete", "ArrowLeft", "ArrowRight", "ArrowUp", "ArrowDown", "Tab"
];
document.addEventListener('keydown', (e) =>{
    const key = e.key;
    console.log('keydown', e.key);

    if(keydownKeys.includes(key)){
        var keypressobj = {
            name: key.toString(), 
            selectionStart: e.target.selectionStart,
            selectionEnd: e.target.selectionEnd,
            cssPath: getCssPath(e.target)
        };
        if (e.ctrlKey) {
            if (e.key === 'Backspace') {
                keypressobj.name = 'CtrlBackspace';
            } else if (e.key === 'z') {
                keypressobj.name = 'CtrlZ';
            } else if (e.key === 'y') {
                keypressobj.name = 'CtrlY';
            } else if (e.key === 'a') {
                keypressobj.name = 'CtrlA';
            } else if (e.key === 'c') {
                keypressobj.name = 'CtrlC';
            } else if (e.key === 'v') {
                keypressobj.name = 'CtrlV';
            } else if (e.key === 'x') {
                keypressobj.name = 'CtrlX';
            } else if (e.key === 'f') {
                keypressobj.name = 'CtrlF';
            } else if (e.key === 's') {
                keypressobj.name = 'CtrlS';
            } else if (e.key === 'r') {
                keypressobj.name = 'CtrlR';
            } else if (e.key === 'w') {
                keypressobj.name = 'CtrlW';
            } else if (e.key === 'e') {
                keypressobj.name = 'CtrlE';
            } else if (e.key === 'q') {
                keypressobj.name = 'CtrlQ';
            }
        }
        console.log(keypressobj);
        socket.emit('keypress',keypressobj );
    }
});


document.addEventListener('keypress', (e) => {
    e.preventDefault();
    var name = e.key.toString();
    
    socket.emit('keypress', {
        name: name, 
        selectionStart: e.target.selectionStart,
        selectionEnd: e.target.selectionEnd,
        cssPath: getCssPath(e.target)
    });
}, false);

function getRelativeNodePath(root, node) {
    const steps = [];
    let currentNode = node;
    
    while (currentNode && currentNode !== root) {
        const siblings = Array.from(currentNode.parentNode.childNodes);
        const nodeIndex = siblings.indexOf(currentNode);
        const nodeType = currentNode.nodeType;
        
        steps.push(`${nodeType}:${nodeIndex}`);
        currentNode = currentNode.parentNode;
    }
    
    return steps.reverse().join('/');
}

document.addEventListener('selectionchange', (event) =>{
    console.log('selectionchangetarget', event.target);
    let focusedElem = document.activeElement;

    if (focusedElem && (focusedElem.tagName === 'INPUT' || focusedElem.tagName === 'TEXTAREA')) {
        var csspath = getCssPath(focusedElem);
        var data = {
            startCssPath: csspath,
            endCssPath: csspath,
            startOffset: focusedElem.selectionStart,
            endOffset: focusedElem.selectionEnd
        }
        socket.emit('selectionchange', data);
    } 
    // else {
    //     var selection = document.getSelection();
    //     const range = selection.getRangeAt(0);
    //     const startNode = range.startContainer;
    //     const startOffset = range.startOffset;
    //     const endNode = range.endContainer;
    //     const endOffset = range.endOffset;
    //     const parentElementOfStartNode = startNode.parentElement;
    //     const parentElementOfEndNode = endNode.parentElement;
    //     var data = { 
    //         startCssPath: getCssPath(parentElementOfStartNode), 
    //         startNodePath: getRelativeNodePath(parentElementOfStartNode, startNode),
    //         startOffset: startOffset, 
    //         endCssPath: getCssPath(parentElementOfEndNode), 
    //         endNodePath: getRelativeNodePath(parentElementOfEndNode, endNode),
    //         endOffset: endOffset
    //     };
    //     socket.emit('selectionchange', data);
    // }
    console.log(document.getSelection());
});


