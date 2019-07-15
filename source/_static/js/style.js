$(function(){

  var searchbar,
      mainmenu,
      form_control,
      querystr = '',
			loc = location.hash;
  var mainElement = $('.central-page-area'),
      tocWrapperElement = $('nav.full-toctree-nav'),
			gTocElement = $('nav.full-toctree-nav .globaltoc'),
      footerElement = $('#main-footer');
  var winScroll = 0,
      gTocScroll = 0,
      pageHeight = $('body').height(),
      windowHeight = $(window).height(),
      mainTop = mainElement.offset().top,
      mainBottom = footerElement.offset().top
			gTocSpaceBottom = 15,
      gTocSpaceTop = $('#search-lg').height();
  var breakpoint = 992,
			spaceBeforeAnchor = 60;
	var excludedSearchFolders = ['release-notes']; // List of folders that will be excluded from search

	// List of empty nodes, containing only a toctree
	var empty_toc_nodes = [
		'amazon/configuration/index',
		'compliance/index',
		'containers/index',
		'deployment/index',
		'development/index',
		'docker-monitor/index',
		'installation-guide/upgrading/legacy/index',
    'installation-guide/packages-list/linux/linux-index',
    'installation-guide/packages-list/solaris/solaris-index',
		'monitoring',
		'release-notes/index',
		'user-manual/index',
		'user-manual/agents/index',
		'user-manual/agents/remove-agents/index',
		'user-manual/agents/listing/index',
		'user-manual/kibana-app/reference/index',
		'user-manual/ruleset/ruleset-xml-syntax/index'
	];

  changeVerionPosition($(window).outerWidth());
  changeSearchPosition($(window).outerWidth());
	mark_toc_nodes_with_class(empty_toc_nodes, 'empty-toc-node');
	checkScroll();
  if (document.location.hash) {
		correctScrollTo(spaceBeforeAnchor);
  }

	// Finds current page section in globaltoc
	$('.globaltoc .toctree-l2.current a').each(function(e){
		if (!$(this).siblings('ul').length){
			$(this).addClass('leaf');
		}
	});

	// Finds all nodes that contains subtrees within the globaltoc and appends a toggle button to them
	$('.globaltoc .toctree-l1 a').each(function(e){
		if ($(this).siblings('ul').length){
			$(this).closest('li').addClass('toc-toggle');
			$(this).append($('<button class="toc-toggle-btn"><span class="toc-toggle-icon"></span></button>'));
		}
	});

	show_current_subtree();

	// Show the hidden menu
	setTimeout(function(){ $('#navbar-globaltoc').removeClass('hidden'); }, 500);

	$(window).on('hashchange', function(){
		updateFromHash();
		correctScrollTo(spaceBeforeAnchor);
	});

	function updateFromHash(){
		loc = location.hash;
		$('.globaltoc .leaf, .globaltoc a.current').removeClass('current');
		selectLeaf(loc);
	}

	function selectLeaf(hash){
		if (hash.length > 0) {
			$('.globaltoc [href="'+hash+'"]').addClass('current');
		} else {
			$('.globaltoc [href="#"]').addClass('current');
		}
	}

  /* Turn all tables in responsive table */
  reponsiveTables();

  function reponsiveTables(){
    $('#main-content table').each(function(){
      if ( $(this).width() > $('main').width()){
        $(this).addClass('table-responsive');
      }
    });
  }

  /* Page scroll event --------------------------------------------------------------------------------------------------*/
  $('#btn-scroll').on('click', function(){
    $("html, body").animate({ scrollTop: 0 }, "slow");
    return false;
  });

  $(window).on('scroll', function(e){
   var scrollYTopPosition = e.currentTarget.pageYOffset;

   // Back to top button
   if ( scrollYTopPosition >= $(window).height()*.50 ){
     $('#btn-scroll').fadeIn('slow');
   }
   else {
     $('#btn-scroll').fadeOut('slow');
   }

	 checkScroll();

 });

 function checkScroll(){
	 var scrollTop = $(document).scrollTop();
   var headerHeight = Math.round($('.header').height());
   if (scrollTop > headerHeight ) {
     $('body').addClass('scrolled');
		 /* Move searchbar to .menu-sub on scroll down if desktop size */
		 if ( $(window).outerWidth() >= breakpoint ) {
			 searcbarToHorizontal();
		 }
   } else {
     $('body').removeClass('scrolled');
		 /* Move searchbar to #search-lg on scroll up if desktop size */
		 if ( $(window).outerWidth() >= breakpoint ) {
			 searcbarToVertical();
		 }
   }
 }

 /* -- Same scroll in navbar ------------------------------------------------------------------------------- */

 $(window).on('scroll', function(e){

	// Get data of scroll and positions
	var document_height = $('.central-page-area').height();
	var footer_height = $('#main-footer').height();
	var document_scroll = $(window).scrollTop();
	var nav_height = $('#globaltoc').height() + $('#search-lg').height();
	var nav_scroll = $('.side-scroll').scrollTop();

	// Calculate navbar end scroll position
	//document_scroll -= 110;
	//document_height += footer_height;
	var proporcion = document_height/nav_height;
	var nav_scroll_end = (document_scroll/proporcion).toFixed();

	// Set navbar end scroll position
	$('.side-scroll').scrollTop(nav_scroll_end);

 });

	/* Global toc --------------------------------------------------------------------------------------------------*/
  function currentToc(){
    var href;
    // Gets the name of the first level folder
    category = document.location.pathname.split('/')[2]; // [2] The URL contains the version; [1]	for URLs without version
    category = (category && category.indexOf('.') < 0)?category:'';

    /* Highlight current category from #menu-submenu */
    $('#menu-submenu').find('li').each(function(){
      if ($(this).children('a').attr('href').indexOf(category) >= 0 && category.length > 0 ) {
        $(this).addClass('active');
      } else {
        $(this).removeClass('active');
      }
    });
  }

  currentToc();

  /* Toggle collapse */
  $('.globaltoc a .toc-toggle-btn').on('click', function(e){
		// Normal link: avoid toggle if current menu item doesn't have submenu
		li = $(e.target).closest('li');
		if (!li || li.children('ul').length == 0 ){
			return true;
		}

		e.stopPropagation();
		e.preventDefault();

		$('.globaltoc li.initial').removeClass('initial');
		if( li.hasClass('show')){
			li.removeClass('show');
		} else {
			li.addClass('show');
		}
		return false;
   });

	 function show_current_subtree(){
		 updateFromHash();
		 if ($('ul li.toctree-l1 a.current.reference.internal, ul li.toctree-l1 .current > .leaf').length == 0 && !$('#page').hasClass('index') ){
			 /* Shows the selected style for the parent document of pages that don't appear in the globaltoc */
				$('.globaltoc :contains("'+ $('#breadcrumbs li:nth-last-child(2) a').text() +'")').addClass('show').addClass('current');
			 return true;
		 }
		 var currentLeaf = $('.globaltoc a.current.leaf');
		 if (currentLeaf.length == 0){
			currentLeaf = $('.globaltoc [href="#"].current');
		 }
		 currentLeaf.parents('li').each(function(){
			$(this).addClass('initial').addClass('show');
		 });
		 $('#navbar-globaltoc').removeClass('hidden');
	 }

	 /* Note: this might be improved in the future using a new builder or extension */
	 function mark_toc_nodes_with_class(node_list, class_name){
		 var regex;
		 var cur_location = location.href.split('#')[0];
		 node_list.forEach(function(toc_node){
			 empty_node = '/' + toc_node + '.html';
			 regex = new RegExp( '[a-zA-Z09-_]+' + empty_node, 'g');
			 $('.globaltoc a').each(function(){
				 var href = $(this).prop('href').split('#')[0];
				 var is_current = (href === cur_location);
         /* The selected menu link in the globaltoc acts as the toggle button, showing on an off its subtree */
				 if ( regex.test(href) || is_current ) {
					 $(this).addClass(class_name);
				 }
				 if ( is_current ) {
					 $(this).addClass('current-toc-node');
				 }
			 });
		 });
	 }

	 $('.globaltoc .empty-toc-node').each(function(){
		 $(this).on('click', function(e){
			 e.preventDefault();
			 $(this).find('.toc-toggle-btn').click();
		 });
	 });

	 /* Scrolls up when clicking current toctree node */
	 $('.globaltoc .current-toc-node').each(function(){
		 $(this).on('click', function(e){
			 e.preventDefault();
			 $("html, body").animate({ scrollTop: 0 }, "500");
		 });
	 });

	/* Resize event --------------------------------------------------------------------------------------------------*/
	 $(window).on('resize', function(e){
		 var curWidth = $(this).outerWidth();
     $('table').removeClass('table-responsive');
     reponsiveTables();
     changeVerionPosition(curWidth);
     changeSearchPosition(curWidth);
		 currentToc();

		 checkScroll();
	 });

	function changeVerionPosition (currentWidth) {
		if (currentWidth >= breakpoint) {
			versionToDesktop();
		} else {
			versionToMobile();
		}
	}

  function versionToDesktop (){
    var vSelector = $('.release-selector-wrapper');
    if (vSelector.closest('#main-navbar').length > 0 ){
      // Selector in #main-navbar: change to .version-zone:
      vSelector.appendTo($('.version-zone'));
    }
  }

	function versionToMobile (){
		var vSelector = $('.release-selector-wrapper');
		if (vSelector.closest('.version-zone').length > 0 ){
			// Selector in .version-zone: change to #main-navbar
			vSelector.appendTo($('#main-navbar'));
		}
	}

  function changeSearchPosition (currentWidth){
    if (currentWidth >= breakpoint) {
			searcbarToDesktop();
		} else {
			searcbarToMobile();
		}
  }

  function searcbarToDesktop(){
    var searchbar = $('.search_main');
    if (searchbar.closest('.blue-bar').length > 0 ){
      // Search bar in .blue-bar .container: change to #search-lg
      searchbar.appendTo($('#search-lg'));
    }
  }

  function searcbarToMobile(){
    var searchbar = $('.search_main');
    if (searchbar.closest('#search-lg').length > 0 ){
      // Search bar in #search-lg: change to .blue-bar .container:
      searchbar.appendTo($('.blue-bar'));
    }
  }

	function searcbarToVertical(){
    var searchbar = $('.search_main');
    if (searchbar.closest('.blue-bar').length > 0 ){
      // Search bar in .blue-bar .container: change to #search-lg
      searchbar.prependTo($('#search-lg'));
    }
  }

  function searcbarToHorizontal(){
    var searchbar = $('.search_main');
    if (searchbar.closest('#search-lg').length > 0 ){
      // Search bar in #search-lg: change to .blue-bar .container:
      searchbar.prependTo($('.blue-bar'));
    }
  }

	// Corrects the scrolling movement so the element to which the page is being scrolled appears in the screen, having in mind the fixed top bar.
	function correctScrollTo(spaceBeforeAnchor){
    if( $('#page').hasClass('no-latest-docs') ) {
			spaceBeforeAnchor = spaceBeforeAnchor + 40;
		}
		setTimeout(function(){
			window.scrollTo(window.scrollX, window.scrollY - spaceBeforeAnchor);
    }, 10);
	}

	/* -- Add funcionability for cloud-info ---------------------------------------------------------------------------------- */

	if($(window).width() < 1200){
		$('#capabilities .left .topic.active p').not('.topic-title').slideDown(300);
	}

	$(window).resize(function(){
		if($(window).width() >= 1200){
			$('#capabilities .left .topic p').not('.topic-title').css({'display':'none'});
			if($('#capabilities .left .topic.active').length > 0){
				capabilitiesHome($('#capabilities .left .topic.active'));
			} else {
				capabilitiesHome($('#capabilities .left .topic').first());
			}
		} else {
			$('#capabilities .left .topic.active p').not('.topic-title').css({'display':'block'});
		}
	});

	$('#capabilities .left .topic').click(function(){
		capabilitiesHome(this);
	});

	function capabilitiesHome(ele){

		var ele_other = ele;
		var active = false;
		if($(ele).hasClass('active')){
			active = true;
		} else {
			ele_other = $('#capabilities .left .topic.active');
		}
		if($('#capabilities .left .topic.active').length <= 0){
			ele_other = false;
		}
		
		if($(window).width() >= 1200){

			var class_name = '';
			class_name = $(ele).attr('class');
			class_name = class_name.replace(' topic','');
			class_name = class_name.replace(' active','');
			var pos_box = $('#capabilities .left').offset();
			var pos_topic = $(ele).offset();
			$('#capabilities .topic').removeClass('active');
			$('#capabilities .right .topic.'+class_name).addClass('active');
			var pos = pos_topic.top - pos_box.top - 4;
			if(pos <= 0){ pos = 0; }
			$('#capabilities .line').css({'height':pos+'px'});
			$(ele).addClass('active');

		} else {

			if(ele_other != false){
			
			$(ele_other).find('p').not('.topic-title').slideUp(300, function(){
				setTimeout(function(){
					$(ele_other).removeClass('active');
				},100);
				setTimeout(function(){
					if(!active){
						$(ele).addClass('active');
						$(ele).find('p').not('.topic-title').slideDown(300);
					}
				},100);
			});
			
			} else {
			
				$(ele).addClass('active');
				$(ele).find('p').not('.topic-title').slideDown(300);

			}

		}

	}


  /* Search results --------------------------------------------------------------------------------------------------*/

  if ( $('#search-results').length > 0 ) {
    var ulSearch = $('ul.search');
    var lastResult = null;
    var splitURL;

    /* Detects every result that is added to the list */
    ulSearch.on('DOMSubtreeModified', function(){
      lastResult = $('ul.search li:last-child');
      splitURL = lastResult.children('a').prop('href').split('/');

      /* Checks the URL to mark the results found in excludedSearchFolders */
      $.each(excludedSearchFolders, function(index, value){
        if ( $.inArray(value, splitURL) !== -1 ) {
          lastResult.addClass('excluded-search-result'); /* Marks initially excluded result */
					lastResult.addClass('hidden-result'); /* Hides the excluded result */
          return false; // breaks the $.each loop
        }
      });
    });

    /* Replaces the result message */
    $('#search-results > p:first').one('DOMSubtreeModified', function(){
      var totalResults = $('ul.search li').length;
      var excludedResults = $('ul.search li.excluded-search-result').length;
      var resultText = '';
      if ( totalResults > 0 ){
        if ( excludedResults > 0 ) {
          resultText = 'Search finished. Found <span id="n-results">' + (totalResults-excludedResults) + '</span> page(s) matching the search query. <a id="toggle-results" class="include" href="#">Include Release Notes results</a>';
        } else {
          resultText = 'Search finished. Found <span id="n-results">' + totalResults + '</span> page(s) matching the search query.';
        }
        $(this).html(resultText);
      }
    });

    /* Click that allows showing excluded results */
    $(document).delegate('#search-results #toggle-results.include', 'click', function(){
			var toggleButton = $(this);
			var excludedResults = $('ul.search li.excluded-search-result');

      toggleButton.text(toggleButton.text().replace('Include', 'Exclude'));
      toggleButton.removeClass('include').addClass('exclude');
			$('#search-results #n-results').text($('ul.search li').length);

			excludedResults.each(function(e){
				currResult = $(this);
				currResult.hide(0, function(){
					$(this).removeClass('hidden-result');
				})
				currResult.show('fast');
			});
    });

    /* Click that allows hiding excluded results */
    $(document).delegate('#search-results #toggle-results.exclude', 'click', function(){
			var toggleButton = $(this);
			var excludedResults = $('ul.search li.excluded-search-result');

      toggleButton.text(toggleButton.text().replace('Exclude', 'Include'));
      toggleButton.removeClass('exclude').addClass('include');
			$('#search-results #n-results').text($('ul.search li').length - excludedResults.length);

			excludedResults.each(function(e){
				currResult = $(this);
				currResult.hide('fast', function(){
					$(this).addClass('hidden-result');
				});
			});
    });

  }
});
