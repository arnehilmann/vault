(function(){
    var $ = function(id) { return document.getElementById(id) };

    console.log(window.location.search);
    var args = window.location.search;
    console.log(args);
    args = args.slice(1);
    console.log(args);
    args = args.split("&");
    console.log(args);
    for (var i in args) {
        console.log(i);
        var arg = args[i];
        console.log(arg);
        var keyvalue = arg.split("=");
        console.log(keyvalue[0] + ": " + keyvalue[1]);
        $(keyvalue[0]).value = keyvalue[1];
    }
})();
