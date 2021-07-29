jQuery(function($) {
    var path = window.location.href;
    $('ul li a').each(function() {
        if (this.href === path) {
            $('ul li a').removeClass('active');
            $(this).addClass('active');
        }
    });
});