(function() {
    var overlay = document.createElement("div");
    overlay.setAttribute("id","overlay");
    overlay.setAttribute("style", "background-color: #000; opacity: .7; position: absolute; top: 0; left: 0; width: 100%; height: 100%; z-index: 10;");

    var hidden = document.createElement("div");
    hidden.setAttribute("style", "display: none;");
    overlay.appendChild(hidden);

    var service = document.createElement("input");
    service.id = "service";
    service.value = window.location.hostname;
//    if (service.value) {
//        service.setAttribute("readonly", "readonly");
//    }
    service.setAttribute("style", "float: right; clear: right;");
    overlay.appendChild(service);

    var passphrase = document.createElement("input");
    passphrase.id = "passphrase";
    passphrase.setAttribute("style", "float: right; clear: right;");
    overlay.appendChild(passphrase);

    var passphrase_text = document.createElement("input");
    passphrase_text.id = "passphrase-text";
    hidden.appendChild(passphrase_text);

    var show_passphrase = document.createElement("input");
    show_passphrase.type = "checkbox";
    show_passphrase.id = "show-passphrase";
    hidden.appendChild(show_passphrase);

    var length = document.createElement("input");
    length.id = "vlength";
    length.value = "20";
    hidden.appendChild(length);

    var repeat = document.createElement("input");
    repeat.id = "repeat";
    repeat.value = "2";
    hidden.appendChild(repeat);

    var required = document.createElement("input");
    required.id = "required";
    required.value = "2";
    hidden.appendChild(required);

    var word = document.createElement("input");
    word.setAttribute("id", "word");
    word.setAttribute("readonly", "readonly");
    word.setAttribute("style", "float: right; clear: right;");
    overlay.appendChild(word);

    document.body.appendChild(overlay);

    var inputs = document.getElementsByTagName('input'), input;
    for (var i = 0, n = inputs.length; i < n; i++) {
        var input = inputs[i];
        if (input.type == "password") {
            console.log("password form found: " + input.id);
            var copynclose = function(input){
                return function(e){
                    if (e.keyCode === 13) {
                        input.value = word.value;
                        console.log("copying generated password to " + input.id);
                        document.body.removeChild(overlay);
                    }
                }
            }
            service.addEventListener("keydown", copynclose(input), false);
            passphrase.addEventListener("keydown", copynclose(input), false);
        }
    }
})();
