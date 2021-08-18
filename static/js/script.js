jQuery(function($) {
    var path = window.location.href;
    $('ul li a').each(function() {
        if (this.href === path && this.href != "login" && this.href != "signup") {
            $('ul li a').removeClass('active');
            $(this).addClass('active');
        }
    });
});
//
//$("input[type='file']").change(function(e) {
//
//    for (var i = 0; i < e.originalEvent.srcElement.files.length; i++) {
//
//        var file = e.originalEvent.srcElement.files[i];
//        var img = document.createElement("img");
//        var reader = new FileReader();
//        reader.onloadend = function() {
//             img.src = reader.result;
//        }
//        reader.readAsDataURL(file);
//        img.style.maxWidth = "100%";
//        $("input[type='file']").after(document.createElement("br"),img);
//    }
//});